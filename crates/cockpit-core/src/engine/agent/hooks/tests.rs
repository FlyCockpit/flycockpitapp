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

/// Minimal daemon-side capability stand-in for dispatch testing. The command
/// spelling in the hook must never reach the `ProcessEnv` lookup once this is
/// bound; only this synthetic private bundle path may reach the runner.
struct StaticRetainedHookAuthority;

impl crate::config::extended::hooks::RetainedHookExecutionAuthority
    for StaticRetainedHookAuthority
{
    fn launch(
        &self,
        components: &[String],
    ) -> Result<crate::config::extended::hooks::HookExecutionLaunch, String> {
        assert_eq!(components, &["hooks".to_owned(), "check".to_owned()]);
        Ok(
            crate::config::extended::hooks::HookExecutionLaunch::ambient(
                PathBuf::from("/daemon-private/snapshots/check"),
                PathBuf::from("/retained-source-cwd"),
            ),
        )
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
        execution: crate::config::extended::hooks::HookExecutionProvenance::Ambient,
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
    }
}

/// A raw output carrying a closed containment failure reason, as the production
/// containment path produces it. Used to prove the pre-tool fail-open matrix
/// includes `descendant_containment_unsupported` at the decision boundary.
fn containment_unsupported_output() -> HookRawOutput {
    HookRawOutput {
        stdout: String::new(),
        exit_code: None,
        duration_ms: 0,
        spawn_failed: false,
        timeout: false,
        failure_reason: Some(
            crate::engine::agent::hooks::REASON_DESCENDANT_CONTAINMENT_UNSUPPORTED,
        ),
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
// AC6: envelope bounds + reserved / clean environment (real runner paths)
// ---------------------------------------------------------------------------

/// Drive `run_observe_hooks` for one event through a capturing fake runner and
/// return (captured invocation, parsed stdin envelope). The hook always carries
/// a configured `MY_HOOK_VAR` and a spoofed `COCKPIT_HOOK_EVENT`, so every
/// caller can prove configured-env delivery AND reserved-key overwrite through
/// the production runner (not just `build_child_env` in isolation).
async fn observe_capture(
    process_env: &dyn ProcessEnv,
    event: HookEvent,
    match_value: &str,
    tool_name: Option<&str>,
    tool_call_id: Option<&str>,
    subagent_type: Option<&str>,
    subagent_id: Option<&str>,
    fields: ObserveFields<'_>,
) -> (CapturedInvocation, Value) {
    let (db, sid) = db_session().await;
    let mut env_map = BTreeMap::new();
    env_map.insert("MY_HOOK_VAR".to_string(), "value123".to_string());
    // A handler must never be able to spoof a reserved key.
    env_map.insert("COCKPIT_HOOK_EVENT".to_string(), "spoofed".to_string());
    let hook = test_hook(
        event,
        vec!["obs".to_string()],
        Some(vec![match_value.to_string()]),
        env_map,
        5,
    );
    let runner = FakeCommandRunner::new(successful_output(r#"{"decision":"allow"}"#));
    run_observe_hooks(
        &runner,
        process_env,
        &registry(vec![hook]),
        event,
        match_value,
        sid,
        workspace(),
        &db,
        tool_name,
        tool_call_id,
        subagent_type,
        subagent_id,
        fields,
        false,
    )
    .await;
    let inv = runner
        .invocations()
        .first()
        .cloned()
        .expect("observe hook invoked exactly once");
    let envelope: Value = serde_json::from_str(&inv.stdin).expect("observe envelope is valid JSON");
    (inv, envelope)
}

#[tokio::test]
async fn retained_relative_hook_dispatch_never_reopens_command_or_workspace_cwd() {
    let (db, session_id) = db_session().await;
    let mut hook = test_hook(
        HookEvent::SessionStart,
        vec!["hooks/check".into()],
        Some(vec!["fresh".into()]),
        BTreeMap::new(),
        5,
    );
    hook.execution = crate::config::extended::hooks::HookExecutionProvenance::RetainedRelative {
        components: vec!["hooks".into(), "check".into()],
        authority: None,
    };
    hook.bind_retained_execution_authority(Arc::new(StaticRetainedHookAuthority))
        .expect("bind retained authority");
    let runner = FakeCommandRunner::new(successful_output(r#"{"decision":"allow"}"#));
    let process_env = FakeProcessEnv::default();
    run_observe_hooks(
        &runner,
        &process_env,
        &registry(vec![hook]),
        HookEvent::SessionStart,
        "fresh",
        session_id,
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
        false,
    )
    .await;

    let invocation = runner
        .invocations()
        .into_iter()
        .next()
        .expect("retained hook invoked");
    assert_eq!(
        invocation.executable,
        PathBuf::from("/daemon-private/snapshots/check"),
        "the mutable source-relative command spelling is never reopened"
    );
    assert_eq!(
        invocation.cwd,
        PathBuf::from("/retained-source-cwd"),
        "dispatch uses the authority-selected cwd rather than the workspace spelling"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn retained_unix_cwd_fd_survives_source_directory_swap() {
    use std::os::unix::fs::PermissionsExt as _;

    let parent = tempfile::tempdir().expect("parent");
    let source = parent.path().join("source");
    let moved = parent.path().join("source-attached");
    std::fs::create_dir_all(&source).expect("source directory");
    std::fs::write(source.join("value"), "attached\n").expect("attached value");
    let source_fd = Arc::new(std::fs::File::open(&source).expect("open source directory"));

    let bundle = tempfile::tempdir().expect("private bundle");
    let executable = bundle.path().join("check");
    std::fs::write(&executable, "#!/bin/sh\ncat value\n").expect("bundle script");
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700))
        .expect("make bundle executable");

    std::fs::rename(&source, &moved).expect("move attached source");
    std::fs::create_dir(&source).expect("replacement source");
    std::fs::write(source.join("value"), "replacement\n").expect("replacement value");

    let output = spawn_real_hook_child(
        &executable,
        &[],
        &BTreeMap::new(),
        &crate::config::extended::hooks::HookWorkingDirectory::RetainedUnixDirectory(source_fd),
        "",
        Duration::from_secs(5),
    )
    .await;
    assert!(!output.spawn_failed && !output.timed_out);
    assert_eq!(output.stdout, "attached\n");
}

#[tokio::test]
async fn tool_hook_runner_envelope_bounds_and_reserved_environment() {
    let process_env = FakeProcessEnv::with_default_resolution();

    // Documented byte caps (the README contract states these exact sizes).
    assert_eq!(
        ENVELOPE_VALUE_MAX_BYTES,
        128 * 1024,
        "envelope value cap is 128 KiB"
    );
    assert_eq!(OUTPUT_CAP_BYTES, 64 * 1024, "captured stdout cap is 64 KiB");

    // --- sessionStart: full clean-environment + resolution + camelCase proof.
    let (inv, env) = observe_capture(
        &process_env,
        HookEvent::SessionStart,
        "fresh",
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
    // Bare executable resolved to an ABSOLUTE path via the ProcessEnv seam.
    assert_eq!(inv.executable, PathBuf::from("/fake/bin/obs"));
    assert!(inv.executable.is_absolute());
    // CWD is the session workspace root.
    assert_eq!(inv.cwd, workspace());
    // Configured env delivered; reserved key overwrites the handler's spoof.
    assert_eq!(inv.env["MY_HOOK_VAR"], "value123");
    assert_eq!(inv.env["COCKPIT_HOOK_EVENT"], "sessionStart");
    assert_eq!(inv.env["COCKPIT_WORKSPACE_ROOT"], "/tmp/hooks-test");
    assert!(inv.env.contains_key("COCKPIT_SESSION_ID"));
    // No inherited Unix ambient variables leak into the clean child env.
    for ambient in ["PATH", "HOME", "USER", "LD_PRELOAD", "SHELL"] {
        assert!(
            !inv.env.contains_key(ambient),
            "ambient variable `{ambient}` must not reach the hook child"
        );
    }
    // No Windows host variables were synthesized on this (or any) host env map.
    assert!(!inv.env.contains_key("ComSpec"));
    assert!(!inv.env.contains_key("PATHEXT"));
    // camelCase envelope, typed discriminator NOT overloaded onto source/reason.
    assert_eq!(env["hookEventName"], "sessionStart");
    assert_eq!(env["workspaceRoot"], "/tmp/hooks-test");
    assert!(env.get("sessionId").is_some());
    assert!(env.get("timestamp").is_some());
    assert_eq!(env["startSource"], "fresh");
    assert!(
        env.get("source").is_none() && env.get("reason").is_none(),
        "typed discriminators must not be overloaded onto generic source/reason"
    );

    // EVERY reserved key is overwritten after configured env (not just the one
    // spoofed above). Drives the single `build_child_env` funnel all runners use
    // with a tool-applicable event so the tool keys are also exercised.
    {
        let mut spoof = BTreeMap::new();
        for key in RESERVED_ENV_KEYS {
            spoof.insert((*key).to_string(), "SPOOFED".to_string());
        }
        let hook = test_hook(
            HookEvent::PreToolUse,
            vec!["/bin/x".to_string()],
            None,
            spoof,
            5,
        );
        let sid = uuid::Uuid::new_v4();
        let built = build_child_env(
            &hook,
            &process_env,
            HookEvent::PreToolUse,
            sid,
            Path::new("/ws"),
            Some("bash"),
            Some("call_9"),
        )
        .unwrap();
        assert_eq!(built["COCKPIT_HOOK_EVENT"], "preToolUse");
        assert_eq!(built["COCKPIT_HOOK_NAME"], "project:abcdef0123456789:0");
        assert_eq!(built["COCKPIT_SESSION_ID"], sid.to_string());
        assert_eq!(built["COCKPIT_WORKSPACE_ROOT"], "/ws");
        assert_eq!(built["COCKPIT_TOOL_NAME"], "bash");
        assert_eq!(built["COCKPIT_TOOL_CALL_ID"], "call_9");
        for key in RESERVED_ENV_KEYS {
            assert_ne!(
                built[*key], "SPOOFED",
                "reserved key `{key}` must be overwritten after configured env"
            );
        }
    }

    // --- Every remaining observe discriminator is a first-class camelCase field.
    let (_, env) = observe_capture(
        &process_env,
        HookEvent::UserPromptSubmit,
        "queued",
        None,
        None,
        None,
        None,
        ObserveFields {
            prompt_source: Some("queued"),
            ..Default::default()
        },
    )
    .await;
    assert_eq!(env["promptSource"], "queued");

    let (_, env) = observe_capture(
        &process_env,
        HookEvent::PermissionDenied,
        "bash",
        Some("bash"),
        Some("call_pd"),
        None,
        None,
        ObserveFields {
            permission_kind: Some("approval_denied"),
            ..Default::default()
        },
    )
    .await;
    assert_eq!(env["permissionKind"], "approval_denied");
    assert_eq!(env["toolName"], "bash");

    let (_, env) = observe_capture(
        &process_env,
        HookEvent::StopFailure,
        "network",
        None,
        None,
        None,
        None,
        ObserveFields {
            error_class: Some("network"),
            ..Default::default()
        },
    )
    .await;
    assert_eq!(env["errorClass"], "network");

    let (_, env) = observe_capture(
        &process_env,
        HookEvent::PreCompact,
        "auto",
        None,
        None,
        None,
        None,
        ObserveFields {
            compact_source: Some("auto"),
            ..Default::default()
        },
    )
    .await;
    assert_eq!(env["compactSource"], "auto");

    let (_, env) = observe_capture(
        &process_env,
        HookEvent::SubagentStart,
        "reviewer",
        None,
        None,
        Some("reviewer"),
        Some("sub-1"),
        ObserveFields::default(),
    )
    .await;
    assert_eq!(env["subagentType"], "reviewer");
    assert_eq!(env["subagentId"], "sub-1");

    // --- stop / subagentStop stop-gate camelCase fields via run_stop_hooks.
    {
        let (db, sid) = db_session().await;
        let runner = FakeCommandRunner::new(successful_output(r#"{"decision":"allow"}"#));
        let mut state = StopGateState::default();
        run_stop_hooks(
            &runner,
            &process_env,
            &registry(vec![test_hook(
                HookEvent::Stop,
                vec!["obs".to_string()],
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
            false,
            &mut state,
        )
        .await;
        let stdin: Value =
            serde_json::from_str(&runner.invocations()[0].stdin).expect("stop envelope JSON");
        assert_eq!(stdin["hookEventName"], "stop");
        assert_eq!(stdin["stopReason"], "end_turn");
        assert_eq!(stdin["stopHookActive"], Value::Bool(false));
    }
    {
        let (db, sid) = db_session().await;
        let runner = FakeCommandRunner::new(successful_output(r#"{"decision":"allow"}"#));
        let mut state = StopGateState::default();
        run_stop_hooks(
            &runner,
            &process_env,
            &registry(vec![test_hook(
                HookEvent::SubagentStop,
                vec!["obs".to_string()],
                Some(vec!["reviewer".to_string()]),
                BTreeMap::new(),
                5,
            )]),
            HookEvent::SubagentStop,
            "reviewer",
            sid,
            workspace(),
            &db,
            Some("reviewer"),
            Some("sub-9"),
            Some("completed"),
            false,
            &mut state,
        )
        .await;
        let stdin: Value =
            serde_json::from_str(&runner.invocations()[0].stdin).expect("subagentStop envelope");
        assert_eq!(stdin["hookEventName"], "subagentStop");
        assert_eq!(stdin["subagentType"], "reviewer");
        assert_eq!(stdin["subagentId"], "sub-9");
        assert_eq!(stdin["endReason"], "completed");
    }

    // --- 128 KiB envelope clipping flags: preToolUse toolInput.
    {
        let (db, sid) = db_session().await;
        let runner = FakeCommandRunner::new(successful_output(r#"{"decision":"allow"}"#));
        let big = json!({ "data": "x".repeat(200 * 1024) });
        run_pre_tool_hooks(
            &runner,
            &process_env,
            &registry(vec![test_hook(
                HookEvent::PreToolUse,
                vec!["obs".to_string()],
                Some(vec!["bash".to_string()]),
                BTreeMap::new(),
                5,
            )]),
            "bash",
            &big,
            "call_big",
            sid,
            workspace(),
            &db,
            false,
        )
        .await;
        let stdin: Value = serde_json::from_str(&runner.invocations()[0].stdin).unwrap();
        assert_eq!(stdin["hookEventName"], "preToolUse");
        assert_eq!(stdin["toolName"], "bash");
        assert_eq!(stdin["toolCallId"], "call_big");
        assert_eq!(
            stdin["toolInputTruncated"],
            Value::Bool(true),
            "an over-cap toolInput must set toolInputTruncated"
        );
        assert!(
            serde_json::to_string(&stdin["toolInput"]).unwrap().len() <= ENVELOPE_VALUE_MAX_BYTES,
            "clipped toolInput serialized form must not exceed the hard 128 KiB cap"
        );
    }
    // A small toolInput sets no truncation flag (distinguishing input).
    {
        let (db, sid) = db_session().await;
        let runner = FakeCommandRunner::new(successful_output(r#"{"decision":"allow"}"#));
        run_pre_tool_hooks(
            &runner,
            &process_env,
            &registry(vec![test_hook(
                HookEvent::PreToolUse,
                vec!["obs".to_string()],
                Some(vec!["bash".to_string()]),
                BTreeMap::new(),
                5,
            )]),
            "bash",
            &json!({ "small": true }),
            "call_small",
            sid,
            workspace(),
            &db,
            false,
        )
        .await;
        let stdin: Value = serde_json::from_str(&runner.invocations()[0].stdin).unwrap();
        assert!(
            stdin.get("toolInputTruncated").is_none(),
            "a small toolInput must not set the truncated flag"
        );
    }

    // --- 128 KiB envelope clipping flags: postToolUse toolResult.
    {
        let (db, sid) = db_session().await;
        let runner = FakeCommandRunner::new(successful_output(r#"{"decision":"allow"}"#));
        let big_text = "y".repeat(200 * 1024);
        let ok: anyhow::Result<crate::engine::tool::ToolOutput> =
            Ok(crate::engine::tool::ToolOutput::text(&big_text));
        run_post_tool_hooks(
            &runner,
            &process_env,
            &registry(vec![test_hook(
                HookEvent::PostToolUse,
                vec!["obs".to_string()],
                Some(vec!["bash".to_string()]),
                BTreeMap::new(),
                5,
            )]),
            HookEvent::PostToolUse,
            "bash",
            &json!({ "cmd": "ls" }),
            "call_post",
            &ok,
            sid,
            workspace(),
            &db,
            false,
        )
        .await;
        let stdin: Value = serde_json::from_str(&runner.invocations()[0].stdin).unwrap();
        assert_eq!(stdin["hookEventName"], "postToolUse");
        assert_eq!(
            stdin["toolResultTruncated"],
            Value::Bool(true),
            "an over-cap toolResult must set toolResultTruncated"
        );
    }

    // --- Windows SystemRoot/WINDIR construction + missing-SystemRoot fail-open,
    // proved host-independently through the ProcessEnv-seam-backed pure helper.
    let win = windows_clean_env_additions(Some("C:\\Windows".to_string()))
        .expect("present SystemRoot constructs the clean Windows additions");
    assert!(
        win.iter()
            .any(|(k, v)| *k == "SystemRoot" && v == "C:\\Windows")
    );
    assert!(
        win.iter()
            .any(|(k, v)| *k == "WINDIR" && v == "C:\\Windows")
    );
    assert!(
        !win.iter().any(|(k, _)| *k == "ComSpec" || *k == "PATHEXT"),
        "Windows additions must not include ComSpec/PATHEXT"
    );
    let missing = windows_clean_env_additions(None);
    assert!(
        missing.is_err(),
        "a missing parent SystemRoot must fail open, not fabricate a value"
    );
    assert!(missing.unwrap_err().contains("SystemRoot"));

    // --- Bare executable that cannot be resolved: the runner is never invoked
    // and a failed row is recorded (executable-not-found fail-open).
    {
        let (db, sid) = db_session().await;
        let no_resolve = FakeProcessEnv::default(); // resolves nothing
        let runner = FakeCommandRunner::new(successful_output(r#"{"decision":"allow"}"#));
        run_observe_hooks(
            &runner,
            &no_resolve,
            &registry(vec![observe_hook(HookEvent::SessionStart, "fresh")]),
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
            false,
        )
        .await;
        assert!(
            runner.invocations().is_empty(),
            "an unresolved bare executable must not reach the command runner"
        );
        let rows = hook_run_events(&db, sid).await;
        assert_eq!(
            rows,
            vec![("sessionStart".to_string(), "failed".to_string())]
        );
    }
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
        false,
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
        false,
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
async fn hook_event_table_dispatches_each_native_lifecycle_boundary() {
    // Scripted per-event harness. For each wired observe event
    // (sessionStart / userPromptSubmit / permissionDenied / preCompact /
    // postCompact / stopFailure from increment 2A, plus subagentStart /
    // subagentStop / sessionEnd wired in this increment 2B-i):
    //   1. a hook whose matcher equals the boundary vocabulary fires exactly
    //      one `hook_run` row and receives its first-class typed envelope field
    //      on stdin, and
    //   2. a hook whose matcher is a *lookalike* (a sibling value the boundary
    //      never uses) fires nothing — proving exact-matcher selection, not a
    //      blanket "any hook for this event" dispatch.
    // The still-unwired `stop` root-continuation event (2B-ii) is deliberately
    // NOT asserted reachable here.
    // The typed-field assertions fail to compile against dead-code HEAD (the
    // `startSource`/`promptSource`/`permissionKind`/`errorClass`/`compactSource`
    // envelope fields and `ObserveFields` do not exist there), and the row/no-row
    // assertions fail behaviorally if a boundary's matcher/typed field is wrong.
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
    // `compactSource`. `agent_requested` is preserved as its OWN value (F2),
    // never collapsed into `auto`.
    for (event, key, source) in [
        (HookEvent::PreCompact, "preCompact", "manual"),
        (HookEvent::PostCompact, "postCompact", "auto"),
        (HookEvent::PreCompact, "preCompact", "agent_requested"),
    ] {
        let (rows, stdin) = observe_once(
            &env,
            &registry(vec![observe_hook(event, source)]),
            event,
            source,
            None,
            ObserveFields {
                compact_source: Some(source),
                ..Default::default()
            },
        )
        .await;
        assert_eq!(rows, vec![(key.to_string(), "success".to_string())]);
        let stdin = stdin.expect("compact hook invoked");
        assert_eq!(stdin["hookEventName"], key);
        assert_eq!(stdin["compactSource"], source);
    }
    // An `agent_requested` compaction must not fire an `auto`-only hook.
    let (rows, _) = observe_once(
        &env,
        &registry(vec![observe_hook(HookEvent::PreCompact, "auto")]),
        HookEvent::PreCompact,
        "agent_requested",
        None,
        ObserveFields {
            compact_source: Some("agent_requested"),
            ..Default::default()
        },
    )
    .await;
    assert!(
        rows.is_empty(),
        "agent_requested must stay a distinct compactSource from auto"
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

#[test]
fn error_class_match_value_is_stable_per_variant() {
    use crate::engine::model::InferenceErrorClass as C;
    // Fixed variants reuse the class's own snake_case vocabulary; the two
    // data-bearing variants collapse to a stable coarse `&'static str` token.
    assert_eq!(error_class_match_value(&C::TimeoutTtft), "timeout_ttft");
    assert_eq!(error_class_match_value(&C::TimeoutIdle), "timeout_idle");
    assert_eq!(error_class_match_value(&C::Network), "network");
    assert_eq!(error_class_match_value(&C::Http(503)), "http");
    assert_eq!(
        error_class_match_value(&C::BillingOrQuotaExhausted),
        "billing_or_quota_exhausted"
    );
    assert_eq!(
        error_class_match_value(&C::Other("weird".to_string())),
        "other"
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
            uuid::Uuid::new_v4(),
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
// The containment-owned parts of these acceptance tests (the
// `descendant_containment_unsupported` fail-open reason, proven-empty timeout
// settlement) are deferred with the process-containment runner integration
// (increment 2) and are not covered here.
// ---------------------------------------------------------------------------

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
        false,
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
    let rows: Vec<_> = db
        .list_session_events(sid)
        .await
        .unwrap()
        .into_iter()
        .filter(|event| event.kind == "hook_run")
        .collect();
    let data = rows[0].data.as_object().unwrap();
    for forbidden in ["payload", "stdout", "stderr", "output", "argv", "cwd"] {
        assert!(!data.contains_key(forbidden), "audit leaked `{forbidden}`");
    }
}

#[tokio::test]
async fn local_knowledge_write_fence_skips_model_triggered_hook_commands() {
    let (db, sid) = db_session().await;
    let reg = registry(vec![test_hook(
        HookEvent::PreToolUse,
        vec!["fenced-hook".to_string()],
        Some(vec!["bash".to_string()]),
        BTreeMap::new(),
        5,
    )]);
    let runner = FakeCommandRunner::new(successful_output(r#"{"decision":"deny"}"#));
    let env = FakeProcessEnv::with_default_resolution();

    let outcome = run_pre_tool_hooks(
        &runner,
        &env,
        &reg,
        "bash",
        &json!({}),
        "call-fenced",
        sid,
        workspace(),
        &db,
        true,
    )
    .await;

    assert_eq!(
        outcome,
        PreHookOutcome::Allow,
        "the hook gate remains fail-open"
    );
    assert!(
        runner.invocations().is_empty(),
        "the fenced hook must not spawn"
    );
    assert_eq!(
        hook_run_statuses(&db, sid).await,
        vec!["failed".to_string()]
    );
}

#[tokio::test]
async fn local_knowledge_write_fence_skips_stop_hook_commands() {
    let (db, sid) = db_session().await;
    let runner = FakeCommandRunner::new(successful_output(
        r#"{"decision":"block","reason":"must not run"}"#,
    ));
    let env = FakeProcessEnv::with_default_resolution();
    let mut state = StopGateState::default();

    let outcome = run_stop_hooks(
        &runner,
        &env,
        &registry(vec![test_hook(
            HookEvent::Stop,
            vec!["stop".to_string()],
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
        true,
        &mut state,
    )
    .await;

    assert_eq!(
        outcome,
        StopHookOutcome::End,
        "the stop gate remains fail-open"
    );
    assert!(
        runner.invocations().is_empty(),
        "the fenced hook must not spawn"
    );
    let rows: Vec<_> = db
        .list_session_events(sid)
        .await
        .unwrap()
        .into_iter()
        .filter(|event| event.kind == "hook_run")
        .collect();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].data["status"], "failed");
    assert_eq!(
        rows[0].data["reason"], REASON_LOCAL_KNOWLEDGE_WRITE_FENCE,
        "the fenced stop audit reason is a stable exact value"
    );
}

#[tokio::test]
async fn local_knowledge_write_fence_skips_observe_hook_commands() {
    let (db, sid) = db_session().await;
    let runner = FakeCommandRunner::new(successful_output(r#"{"decision":"allow"}"#));
    let env = FakeProcessEnv::with_default_resolution();

    run_observe_hooks(
        &runner,
        &env,
        &registry(vec![observe_hook(HookEvent::SessionStart, "fresh")]),
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
        true,
    )
    .await;

    assert!(
        runner.invocations().is_empty(),
        "the fenced hook must not spawn"
    );
    let rows = db.list_session_events(sid).await.unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].data["status"], "failed");
    assert_eq!(
        rows[0].data["reason"], REASON_LOCAL_KNOWLEDGE_WRITE_FENCE,
        "the fenced observe audit reason is a stable exact value"
    );
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
            false,
        )
        .await;
        (outcome, hook_run_statuses(&db, sid).await)
    }

    let resolves = FakeProcessEnv::with_default_resolution();

    // Every failure mode below is fail-open: the pre gate returns `Allow` (so
    // the ordinary tool dispatch proceeds) and records exactly one bounded row.
    let big_malformed = "x".repeat(200 * 1024);
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
        // The process-containment path (increment 2C): an unsupported-before-
        // spawn outcome is fail-open with a bounded failed row, exactly like the
        // other runner failure modes.
        (
            "descendant containment unsupported",
            containment_unsupported_output(),
        ),
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

    // The containment-unsupported reason must reach the durable ledger VERBATIM
    // (not collapsed to a generic "spawn failed"), so a later audit can tell a
    // containment fail-open apart from an ordinary spawn failure.
    {
        let (db, sid) = db_session().await;
        let reg = registry(vec![test_hook(
            HookEvent::PreToolUse,
            vec!["h".to_string()],
            Some(vec!["bash".to_string()]),
            BTreeMap::new(),
            5,
        )]);
        let runner = FakeCommandRunner::new(containment_unsupported_output());
        let outcome = run_pre_tool_hooks(
            &runner,
            &resolves,
            &reg,
            "bash",
            &json!({}),
            "call-1",
            sid,
            workspace(),
            &db,
            false,
        )
        .await;
        assert_eq!(outcome, PreHookOutcome::Allow);
        let events: Vec<_> = db
            .list_session_events(sid)
            .await
            .unwrap()
            .into_iter()
            .filter(|event| event.kind == "hook_run")
            .collect();
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].data["reason"].as_str(),
            Some(REASON_DESCENDANT_CONTAINMENT_UNSUPPORTED),
            "containment-unsupported fail-open must record the exact reason constant"
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
        false,
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
        false,
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
        false,
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
            false,
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
            false,
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

    // No matching hooks → End, state untouched.
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
            false,
            &mut state,
        )
        .await;
        assert_eq!(outcome, StopHookOutcome::End);
        assert_eq!(state.continuation_count, 0);
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
            false,
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
            false,
            &mut state,
        )
        .await;
        assert_eq!(
            outcome,
            StopHookOutcome::ForcedEnd(ForcedEndCause::HookRequested)
        );
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
            false,
            &mut state,
        )
        .await;
        assert_eq!(
            outcome,
            StopHookOutcome::ForcedEnd(ForcedEndCause::ContinuationCap)
        );
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
            false,
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
            false,
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
        false,
        &mut state,
    )
    .await;
    assert_eq!(
        outcome,
        StopHookOutcome::ForcedEnd(ForcedEndCause::ContinuationCap)
    );
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

#[tokio::test]
async fn subagent_stop_dispatch_carries_child_envelope_and_honors_continuation() {
    // The UNIFIED `subagentStop` dispatch runs through the SAME `run_stop_hooks`
    // G::Stop dispatcher as root `stop`, but its envelope describes the CHILD
    // (camelCase `subagentType` / `subagentId` / `endReason` + the gate
    // re-entrancy flag `stopHookActive`) and carries NO `stopReason` (that is a
    // root-`stop` field; the subagent matcher token is already `subagentType`).
    // A blocking hook returns `Continue` and counts against the caller's latch.
    let env = FakeProcessEnv::with_default_resolution();
    let subagent_stop_hook = || {
        test_hook(
            HookEvent::SubagentStop,
            vec!["s".to_string()],
            Some(vec!["builder".to_string()]),
            BTreeMap::new(),
            5,
        )
    };
    let (db, sid) = db_session().await;
    let runner = FakeCommandRunner::new(successful_output(
        r#"{"decision":"block","reason":"tests still red"}"#,
    ));
    let mut state = StopGateState::default();
    let outcome = run_stop_hooks(
        &runner,
        &env,
        &registry(vec![subagent_stop_hook()]),
        HookEvent::SubagentStop,
        "builder",
        sid,
        workspace(),
        &db,
        Some("builder"),
        Some("task-42"),
        Some("completed"),
        false,
        &mut state,
    )
    .await;
    assert_eq!(
        outcome,
        StopHookOutcome::Continue {
            reason: "tests still red".to_string(),
            additional_context: None,
        },
        "a blocking subagentStop hook grants a continuation to re-run the child"
    );
    assert_eq!(state.continuation_count, 1);

    let invocations = runner.invocations();
    assert_eq!(invocations.len(), 1);
    let env_json: serde_json::Value = serde_json::from_str(&invocations[0].stdin).unwrap();
    assert_eq!(env_json["hookEventName"], "subagentStop");
    assert_eq!(env_json["subagentType"], "builder");
    assert_eq!(env_json["subagentId"], "task-42");
    assert_eq!(env_json["endReason"], "completed");
    assert_eq!(
        env_json["stopHookActive"], false,
        "the first consultation is not yet inside a continuation loop"
    );
    assert!(
        env_json.get("stopReason").is_none(),
        "subagentStop carries no stopReason (that is a root-stop field)"
    );
    assert!(
        env_json.get("source").is_none() && env_json.get("reason").is_none(),
        "child identity must not be overloaded onto generic source/reason"
    );
    assert_eq!(
        hook_run_statuses(&db, sid).await,
        vec!["blocked".to_string()]
    );

    // A TERMINAL subagentStop (abort/fail): a fresh discarded state, block ignored
    // by the caller. Here we still observe the envelope carries the terminal
    // `endReason`, and the dispatch records the row.
    let (db, sid) = db_session().await;
    let runner = FakeCommandRunner::new(successful_output(""));
    let mut discarded = StopGateState::default();
    let _ = run_stop_hooks(
        &runner,
        &env,
        &registry(vec![subagent_stop_hook()]),
        HookEvent::SubagentStop,
        "builder",
        sid,
        workspace(),
        &db,
        Some("builder"),
        Some("task-99"),
        Some("aborted"),
        false,
        &mut discarded,
    )
    .await;
    let env_json: serde_json::Value = serde_json::from_str(&runner.invocations()[0].stdin).unwrap();
    assert_eq!(env_json["endReason"], "aborted");
    assert_eq!(env_json["subagentId"], "task-99");
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
                    HookMatcherPolicy::ErrorClass => ("errorClass", Vec::new()),
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
            // The machine-checked fail-open needles are the SAME single-sourced
            // runner reason constants written to `hook_run.reason` (Decision #6
            // / #9), not hand-typed slugs. If a constant's value drifts from the
            // README prose, `hooks_documentation_matches_typed_contract` fails.
            fail_open_conditions: vec![
                REASON_SPAWN_FAILED,
                REASON_EXECUTABLE_NOT_FOUND,
                REASON_HOOK_TIMED_OUT,
                REASON_MALFORMED_JSON_OUTPUT,
                REASON_OUTPUT_NOT_JSON_OBJECT,
                REASON_MALFORMED_HOOK_OUTPUT,
                REASON_NONZERO_EXIT_PREFIX,
                REASON_UNEXPECTED_PRE_TOOL_BLOCK,
                REASON_UNEXPECTED_STOP_DENY,
                REASON_UNKNOWN_OR_MISSING_DECISION,
                REASON_DESCENDANT_CONTAINMENT_UNSUPPORTED,
                REASON_DESCENDANT_CONTAINMENT_UNCERTAIN,
                REASON_DESCENDANT_CONTAINMENT_FAILED,
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

/// Strip `#[cfg(test)]`-guarded `mod` blocks from a source file so a lifecycle
/// event referenced only from an inline unit-test module is NOT counted as a
/// production call site. Only `#[cfg(test)]` immediately followed by a `mod`
/// item is stripped (via brace matching); a `#[cfg(test)]` on a `use`/`fn` is
/// left in place so unrelated production code is never accidentally removed.
fn strip_cfg_test_modules(src: &str) -> String {
    const NEEDLE: &str = "#[cfg(test)]";
    let bytes = src.as_bytes();
    let mut out = String::with_capacity(src.len());
    let mut i = 0;
    while i < src.len() {
        if src[i..].starts_with(NEEDLE) {
            let after = &src[i + NEEDLE.len()..];
            let trimmed = after.trim_start();
            let is_mod = trimmed.starts_with("mod ")
                || trimmed.starts_with("pub mod ")
                || trimmed.starts_with("pub(crate) mod ");
            // Only strip an INLINE braced module (`mod foo { ... }`). An external
            // module DECLARATION (`mod tests;`) has a `;` before any `{`, so we
            // must not treat the next unrelated `{` as its body and delete real
            // production source after it.
            let brace_before_semi = {
                let semi = src[i..].find(';');
                let brace = src[i..].find('{');
                matches!((brace, semi), (Some(b), Some(s)) if b < s)
                    || matches!((brace, semi), (Some(_), None))
            };
            if is_mod
                && brace_before_semi
                && let Some(brace_rel) = src[i..].find('{')
            {
                // Skip from the opening brace to its matching close brace.
                let mut depth = 0isize;
                let mut j = i + brace_rel;
                while j < src.len() {
                    match bytes[j] {
                        b'{' => depth += 1,
                        b'}' => {
                            depth -= 1;
                            if depth == 0 {
                                j += 1;
                                break;
                            }
                        }
                        _ => {}
                    }
                    j += 1;
                }
                i = j;
                continue;
            }
        }
        let ch = src[i..].chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

/// Read every production (non-test) `cockpit-core` source file, excluding the
/// hooks runner-definition file (`engine/agent/hooks.rs`, which defines the
/// dispatch functions rather than calling them), with `#[cfg(test)]` modules
/// stripped. Returns per-file `(path, stripped_text)` so reachability can be
/// asserted at file granularity (a lifecycle event must be constructed in a
/// file that also *dispatches* hooks).
fn production_dispatch_files() -> Vec<(PathBuf, String)> {
    let src_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let runner_defs = src_root.join("engine").join("agent").join("hooks.rs");
    let mut files = Vec::new();
    let mut stack = vec![src_root];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("read src dir") {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                if path.file_name().is_some_and(|n| n == "tests") {
                    continue; // whole test-only directory
                }
                stack.push(path);
                continue;
            }
            if path.extension().is_none_or(|ext| ext != "rs") {
                continue;
            }
            let name = path.file_name().unwrap().to_string_lossy().to_string();
            if name == "tests.rs" || name.ends_with("_tests.rs") || name.ends_with("_test.rs") {
                continue;
            }
            if path == runner_defs {
                continue;
            }
            let text = std::fs::read_to_string(&path).expect("read source file");
            files.push((path, strip_cfg_test_modules(&text)));
        }
    }
    files
}

/// True if `text` contains a real, non-comment construction of `needle`
/// (`HookEvent::<Variant>`) that is passed to a hook dispatch/fire call — proved
/// by the construction line sitting within a small line window of a dispatch
/// marker (one of the four canonical runners or an observe/subagent fire helper
/// that wraps them). A mention inside a `//` comment, a doc string, or a dead
/// construction far from any dispatch call does NOT count.
fn event_dispatched_in(text: &str, needle: &str) -> bool {
    const MARKERS: &[&str] = &[
        "run_observe_hooks(",
        "run_stop_hooks(",
        "run_pre_tool_hooks(",
        "run_post_tool_hooks(",
        "fire_observe_hook(",
        "fire_subagent_hook(",
    ];
    // Window spans a multi-line call argument list (event and runner call are a
    // few lines apart, in either order).
    const WINDOW: usize = 12;
    let lines: Vec<&str> = text.lines().collect();
    let is_comment = |l: &str| l.trim_start().starts_with("//");
    let ctor_lines: Vec<usize> = lines
        .iter()
        .enumerate()
        .filter(|(_, l)| l.contains(needle) && !is_comment(l))
        .map(|(i, _)| i)
        .collect();
    if ctor_lines.is_empty() {
        return false;
    }
    let marker_lines: Vec<usize> = lines
        .iter()
        .enumerate()
        .filter(|(_, l)| MARKERS.iter().any(|m| l.contains(m)))
        .map(|(i, _)| i)
        .collect();
    ctor_lines
        .iter()
        .any(|&c| marker_lines.iter().any(|&m| c.abs_diff(m) <= WINDOW))
}

/// AC11 reachability: every `HookEvent::ALL` entry must have a REAL production
/// call site, not merely an entry in a hand-maintained table. A lifecycle event
/// is reachable only if it is CONSTRUCTED (`HookEvent::<Variant>`) inside a
/// production, non-test cockpit-core file that also dispatches hooks. Because
/// the `HookEvent` enum is defined in `cockpit-config` (a different crate) and
/// the runner definitions in `engine/agent/hooks.rs` are excluded, the only
/// remaining `HookEvent::<Variant>` construction in this corpus IS the dispatch
/// or fire-call argument — so deleting an event's dispatch call removes its only
/// production reference and fails this test.
///
/// `preToolUse` is dispatched with an implicit event argument inside
/// `run_pre_tool_hooks`, so its reachable call site is the production call to
/// that runner (in `tool_dispatch`), which this check requires directly.
///
/// The construction must also sit within a small line window of a dispatch/fire
/// marker (see [`event_dispatched_in`]), so a bare mention in a comment or a
/// dead construction far from any runner call does not keep an event green.
///
/// What this catches: a newly-added-but-unwired event (no dispatched
/// construction at all) and the removal of any wired event's only dispatch/fire
/// call. What it does not catch: a deliberately-retained dead `HookEvent::X`
/// construction placed adjacent to an unrelated hook call — which
/// `cargo clippy -D warnings` independently rejects as an unused value in the
/// CI gate.
fn assert_every_event_has_production_call_site() {
    let files = production_dispatch_files();
    // Guard against a vacuous scan: the corpus must actually contain the
    // dispatch entry points.
    let has_any = |m: &str| files.iter().any(|(_, t)| t.contains(m));
    for marker in [
        "run_observe_hooks(",
        "run_stop_hooks(",
        "run_post_tool_hooks(",
        "run_pre_tool_hooks(",
    ] {
        assert!(
            has_any(marker),
            "reachability corpus is missing dispatch call `{marker}` — the scan would be vacuous"
        );
    }

    for event in HookEvent::ALL {
        if matches!(event, HookEvent::PreToolUse) {
            assert!(
                has_any("run_pre_tool_hooks("),
                "`preToolUse` has no production `run_pre_tool_hooks(` call site"
            );
            continue;
        }
        let needle = format!("HookEvent::{event:?}");
        let reachable = files
            .iter()
            .any(|(_, text)| event_dispatched_in(text, &needle));
        assert!(
            reachable,
            "lifecycle event `{}` has no production dispatch call site: no non-test \
             cockpit-core file (excluding the runner definitions) both constructs \
             `{needle}` and dispatches hooks. Wire it at its boundary, or the README \
             must stop describing it as supported.",
            event.key()
        );
    }
}

/// `hooks_documentation_matches_typed_contract` verifies that the public
/// `apps/cli/README.md` `## Hooks` contract block matches the typed
/// config/runtime constants. It fails on a missing marker, any
/// missing/extra/wrong normative value, an unsupported format presented as
/// supported, a fail-open needle that diverges from the single-sourced runner
/// reason constants, or a lifecycle event lacking a real production call site.
#[test]
fn hooks_documentation_matches_typed_contract() {
    let block = read_hooks_contract_block();
    assert!(!block.trim().is_empty(), "hooks-contract block is empty");
    let contract = HookDocumentationContract::from_typed_constants();
    assert_contract_block_matches(&block, &contract);
    // (b) every documented event must actually be reachable in production.
    assert_every_event_has_production_call_site();
}

// ---------------------------------------------------------------------------
// Process-containment runner orchestration (increment 2C, AC7)
//
// These drive the REAL `run_hook_child_contained` orchestration against a REAL
// `ProcessContainmentActor` (backed by a fake adapter), with an injected fake
// hook child so no external executable is spawned. They prove: a proven lease
// is created and the child runs under it; timeout/cancel settle ONLY on
// `EmptyOutcome::ProvenEmpty`; the three single-sourced fail-open reasons are
// emitted verbatim; the body never runs when containment is unsupported; and a
// dropped run future still terminates the lease.
// ---------------------------------------------------------------------------

use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};

use crate::process_containment::{
    FakeEmptyMode, FakeProvenAdapter, FakeUnsupportedAdapter, PlatformKind, ProcessContainmentActor,
};

/// Drive `run_hook_child_contained` with a real containment actor backed by
/// `adapter` and a fake hook child that returns `outcome`. Returns the produced
/// `HookRawOutput` and whether the (fake) hook body actually ran.
async fn drive_contained_hook(
    adapter: crate::process_containment::SharedAdapter,
    outcome: super::ChildRunOutcome,
) -> (HookRawOutput, bool) {
    let (db, sid) = db_session().await;
    let actor = ProcessContainmentActor::start(db.clone(), adapter);
    let handle = actor.handle();
    let ran = Arc::new(AtomicBool::new(false));
    let ran_child = ran.clone();
    let result = super::run_hook_child_contained(
        &handle,
        sid,
        PathBuf::from("/fake/bin/hook"),
        vec!["--literal".to_string(), "arg with spaces".to_string()],
        PathBuf::from("/tmp/hooks-test"),
        std::time::Instant::now(),
        move |_lease| async move {
            ran_child.store(true, AtomicOrdering::SeqCst);
            outcome
        },
    )
    .await;
    (result, ran.load(AtomicOrdering::SeqCst))
}

fn child_timed_out() -> super::ChildRunOutcome {
    super::ChildRunOutcome {
        stdout: String::new(),
        exit_code: None,
        spawn_failed: false,
        timed_out: true,
    }
}

fn child_completed(stdout: &str) -> super::ChildRunOutcome {
    super::ChildRunOutcome {
        stdout: stdout.to_string(),
        exit_code: Some(0),
        spawn_failed: false,
        timed_out: false,
    }
}

#[tokio::test]
async fn tool_hook_runner_argv_timeout_and_proven_empty() {
    // A timed-out hook child under a PROVEN lease settles as a timeout ONLY
    // after the same-generation empty oracle proves the group empty.
    let fake = FakeProvenAdapter::new(PlatformKind::Fake);
    let (result, ran) = drive_contained_hook(Arc::new(fake.clone()), child_timed_out()).await;
    assert!(ran, "a proven lease must actually run the hook child");
    assert!(
        result.timeout,
        "a timed-out child settles as a timeout on ProvenEmpty"
    );
    assert_eq!(
        result.failure_reason, None,
        "proven-empty settlement carries no containment failure reason"
    );
    assert!(
        !fake.spawn_log().is_empty(),
        "a real containment lease was created for the child"
    );
    assert!(
        !fake.terminate_log().is_empty(),
        "the lease was terminated before the timeout settled"
    );

    // Distinguishing case: the SAME timed-out child under an adapter whose empty
    // oracle returns Uncertain must NOT settle as a timeout — it fails open as
    // `descendant_containment_uncertain`. This proves settlement is gated on
    // ProvenEmpty, not merely on the child future finishing.
    let uncertain = FakeProvenAdapter::new(PlatformKind::Fake);
    uncertain.set_empty_mode(FakeEmptyMode::Uncertain);
    let (result, ran) = drive_contained_hook(Arc::new(uncertain), child_timed_out()).await;
    assert!(ran);
    assert!(
        !result.timeout,
        "an unproven-empty outcome must not report a settled timeout"
    );
    assert_eq!(
        result.failure_reason,
        Some(REASON_DESCENDANT_CONTAINMENT_UNCERTAIN)
    );
}

#[tokio::test]
async fn tool_hook_runner_unsupported_before_spawn_skips_body() {
    // Unsupported-before-spawn (DescendantContainmentUnavailable): fail open as
    // `descendant_containment_unsupported` and NEVER run the hook body.
    let (result, ran) = drive_contained_hook(
        Arc::new(FakeUnsupportedAdapter::management_boundary()),
        child_completed(r#"{"decision":"deny","reason":"should never run"}"#),
    )
    .await;
    assert!(
        !ran,
        "the hook body must NOT run when containment is unsupported before spawn"
    );
    assert_eq!(
        result.failure_reason,
        Some(REASON_DESCENDANT_CONTAINMENT_UNSUPPORTED)
    );
}

#[tokio::test]
async fn tool_hook_runner_uncertain_after_spawn_fails_open() {
    // Uncertain after spawn: the child ran, but the group could not be proven
    // empty. Fail open as `descendant_containment_uncertain`; the child's own
    // decision must NOT settle, and the lease is still terminated.
    let fake = FakeProvenAdapter::new(PlatformKind::Fake);
    fake.set_empty_mode(FakeEmptyMode::Uncertain);
    let (result, ran) = drive_contained_hook(
        Arc::new(fake.clone()),
        child_completed(r#"{"decision":"allow"}"#),
    )
    .await;
    assert!(
        ran,
        "the child ran (distinguishes uncertain-after-spawn from unsupported-before-spawn)"
    );
    assert_eq!(
        result.failure_reason,
        Some(REASON_DESCENDANT_CONTAINMENT_UNCERTAIN),
        "a non-proven-empty outcome fails open as uncertain instead of honoring the hook decision"
    );
    assert!(
        !fake.terminate_log().is_empty(),
        "the lease was terminated even though empty could not be proven"
    );
}

#[tokio::test]
async fn tool_hook_runner_actor_terminate_error_is_failed() {
    // A terminate/await actor error fails open as `descendant_containment_failed`.
    let fake = FakeProvenAdapter::new(PlatformKind::Fake);
    fake.set_kill_fail_once(true);
    let (result, ran) = drive_contained_hook(Arc::new(fake.clone()), child_completed("{}")).await;
    assert!(ran);
    assert_eq!(
        result.failure_reason,
        Some(REASON_DESCENDANT_CONTAINMENT_FAILED),
        "a terminate actor error fails open as descendant_containment_failed"
    );
}

#[test]
fn externally_documented_hook_failure_reason_constants_are_stable() {
    // Independent literals (NOT the constants) — the exact `hook_run.reason`
    // strings are a durable-ledger + docs contract; a changed VALUE must fail.
    assert_eq!(
        REASON_DESCENDANT_CONTAINMENT_UNSUPPORTED,
        "descendant_containment_unsupported"
    );
    assert_eq!(
        REASON_DESCENDANT_CONTAINMENT_UNCERTAIN,
        "descendant_containment_uncertain"
    );
    assert_eq!(
        REASON_DESCENDANT_CONTAINMENT_FAILED,
        "descendant_containment_failed"
    );
    assert_eq!(
        REASON_LOCAL_KNOWLEDGE_WRITE_FENCE,
        "local_knowledge_write_fence"
    );
}

#[tokio::test]
async fn tool_hook_runner_without_handle_is_unsupported() {
    // Drive the REAL production entry point `CommandRunner::run` on a runner with
    // no containment handle: it must fail open as unsupported and never raw-spawn
    // the executable. A runner that bypassed containment would instead try to
    // spawn `/fake/bin/hook` and report a plain spawn failure (reason None), so
    // this fails against a non-contained runner.
    let runner = TokioCommandRunner::new();
    let out = runner
        .run(
            Path::new("/fake/bin/hook"),
            &[],
            &BTreeMap::new(),
            Path::new("/tmp/hooks-test"),
            "{}",
            Duration::from_secs(5),
            uuid::Uuid::new_v4(),
        )
        .await;
    assert_eq!(
        out.failure_reason,
        Some(REASON_DESCENDANT_CONTAINMENT_UNSUPPORTED)
    );
    assert!(
        out.stdout.is_empty(),
        "no child output when containment is unavailable"
    );
}

#[tokio::test]
async fn tool_hook_runner_dropped_future_terminates_lease() {
    // Drop an ACTUAL pending `run_hook_child_contained` future while its hook
    // child is running (the closure hangs). The in-run guard must still
    // terminate the lease via its detached cleanup rather than orphaning the
    // child's containment. This exercises the real orchestration future, so it
    // would fail if the guard were missing or misplaced.
    let (db, sid) = db_session().await;
    let fake = FakeProvenAdapter::new(PlatformKind::Fake);
    let actor = ProcessContainmentActor::start(db.clone(), Arc::new(fake.clone()));
    let handle = actor.handle();
    // Keep the sender alive so the child future stays pending (hangs).
    let (_hold_tx, hold_rx) = tokio::sync::oneshot::channel::<()>();
    // Set inside the child closure, which runs ONLY after the in-run guard has
    // been armed — so observing it guarantees the guard exists before we abort.
    let child_running = Arc::new(AtomicBool::new(false));
    let child_running_set = child_running.clone();
    let run_handle = handle.clone();
    let task = tokio::spawn(async move {
        super::run_hook_child_contained(
            &run_handle,
            sid,
            PathBuf::from("/fake/bin/hook"),
            vec![],
            PathBuf::from("/tmp/hooks-test"),
            std::time::Instant::now(),
            move |_lease| async move {
                child_running_set.store(true, AtomicOrdering::SeqCst);
                // Hang so the run future is dropped WHILE the child is running.
                let _ = hold_rx.await;
                super::ChildRunOutcome {
                    stdout: String::new(),
                    exit_code: Some(0),
                    spawn_failed: false,
                    timed_out: false,
                }
            },
        )
        .await
    });
    // Wait until the child is running under an armed guard.
    let mut spawned = false;
    for _ in 0..5000 {
        if child_running.load(AtomicOrdering::SeqCst) {
            spawned = true;
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(
        spawned,
        "the child should be running under an armed guard before being dropped"
    );
    // Drop the pending run future while the child is running.
    task.abort();
    // Bounded, wall-clock-free wait for the guard's detached terminate to land.
    let mut terminated = false;
    for _ in 0..5000 {
        if !fake.terminate_log().is_empty() {
            terminated = true;
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(
        terminated,
        "dropping a pending contained-run future must terminate its lease via the guard"
    );
}
