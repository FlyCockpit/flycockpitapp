use super::{
    App, GIT_AGENT_TOKEN_CAP, McpAction, PaneSide, SandboxCommand, SandboxEscalationCommand,
    cache_config_caches, cap_tokens, editor_argv_for_cwd, new_external_editor_tempfile,
    parse_llm_mode_arg, parse_mcp_action, parse_pane_side, parse_sandbox_arg,
    parse_sandbox_escalation_arg, sanitize_for_raw_stdout, slash_args, strip_ansi, tool_invocation,
    xml_escape,
};
use crate::tui::history::HistoryEntry;
use serde_json::json;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

#[test]
fn strip_ansi_removes_csi_and_cr() {
    assert_eq!(strip_ansi("\x1b[31mred\x1b[0m\r\nplain"), "red\nplain");
}

#[test]
fn strip_ansi_removes_osc() {
    assert_eq!(strip_ansi("\x1b]0;window title\x07body"), "body");
}

#[test]
fn raw_stdout_sanitizer_removes_csi_sequences() {
    assert_eq!(
        sanitize_for_raw_stdout("plain \x1b[31mred\x1b[0m text"),
        "plain red text"
    );
}

#[test]
fn raw_stdout_sanitizer_removes_osc_title_sequences() {
    assert_eq!(
        sanitize_for_raw_stdout("before \x1b]0;window title\x07after"),
        "before after"
    );
}

#[test]
fn raw_stdout_sanitizer_removes_osc52_clipboard_sequences() {
    assert_eq!(
        sanitize_for_raw_stdout("copy \x1b]52;c;SGVsbG8=\x07done"),
        "copy done"
    );
}

#[test]
fn raw_stdout_sanitizer_removes_bare_carriage_returns() {
    assert_eq!(sanitize_for_raw_stdout("one\rtwo\r\nthree"), "onetwothree");
}

#[test]
fn raw_stdout_sanitizer_removes_misc_controls_and_del() {
    assert_eq!(
        sanitize_for_raw_stdout("a\x07b\x08c\x0bd\x0ce\x7ff\tg"),
        "abcdef\tg"
    );
}

#[test]
fn raw_stdout_sanitizer_keeps_ordinary_unicode() {
    assert_eq!(
        sanitize_for_raw_stdout("naïve café こんにちは Привет"),
        "naïve café こんにちは Привет"
    );
}

#[test]
fn build_exit_tail_lines_returns_sanitized_lines() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    app.exit_tail_lines = -1;
    app.history.push(HistoryEntry::Plain {
        line: "safe\x1b]52;c;SGVsbG8=\x07 text\x07 with\nbreak".to_string(),
    });

    assert_eq!(
        app.build_exit_tail_lines(),
        vec!["safe text withbreak".to_string()]
    );
}

#[test]
fn slash_args_splits_off_command_token() {
    assert_eq!(slash_args("/git status -s"), "status -s");
    assert_eq!(slash_args("/git"), "");
    assert_eq!(slash_args("/editor right"), "right");
    // A bare prefix (popup-accepted before any space) has no args.
    assert_eq!(slash_args("/g"), "");
}

#[test]
fn parse_mcp_action_covers_every_subcommand() {
    use McpAction::*;
    assert_eq!(parse_mcp_action(""), List);
    assert_eq!(parse_mcp_action("list"), List);
    assert_eq!(parse_mcp_action("settings"), Settings);
    assert_eq!(
        parse_mcp_action("on"),
        SetEnabled {
            id: None,
            enable: Some(true)
        }
    );
    assert_eq!(
        parse_mcp_action("off gh"),
        SetEnabled {
            id: Some("gh".into()),
            enable: Some(false)
        }
    );
    assert_eq!(
        parse_mcp_action("toggle"),
        SetEnabled {
            id: None,
            enable: None
        }
    );
    assert_eq!(
        parse_mcp_action("toggle gh"),
        SetEnabled {
            id: Some("gh".into()),
            enable: None
        }
    );
    // Unknown sub → usage.
    assert_eq!(parse_mcp_action("monty bogus"), Usage);
    assert_eq!(parse_mcp_action("monty"), Usage);
    assert_eq!(parse_mcp_action("frobnicate"), Usage);
}

#[test]
fn parse_pane_side_aliases() {
    assert_eq!(parse_pane_side("up"), PaneSide::Top);
    assert_eq!(parse_pane_side("down"), PaneSide::Bottom);
    assert_eq!(parse_pane_side("LEFT"), PaneSide::Left);
    assert_eq!(parse_pane_side(""), PaneSide::Full);
    assert_eq!(parse_pane_side("garbage"), PaneSide::Full);
}

#[test]
fn editor_argv_appends_cwd_after_parsed_editor_args() {
    let cwd = std::path::Path::new("/tmp/project dir");

    assert_eq!(
        editor_argv_for_cwd(std::ffi::OsStr::new("nvim"), cwd),
        vec!["nvim".to_string(), "/tmp/project dir".to_string()]
    );
    assert_eq!(
        editor_argv_for_cwd(std::ffi::OsStr::new("code --reuse-window"), cwd),
        vec![
            "code".to_string(),
            "--reuse-window".to_string(),
            "/tmp/project dir".to_string()
        ]
    );
    assert_eq!(
        editor_argv_for_cwd(
            std::ffi::OsStr::new("\"/Applications/My Editor\" --wait"),
            cwd
        ),
        vec![
            "/Applications/My Editor".to_string(),
            "--wait".to_string(),
            "/tmp/project dir".to_string()
        ]
    );
}

#[test]
fn external_editor_tempfile_name_is_not_pid_predictable() {
    let temp = new_external_editor_tempfile().unwrap();
    let name = temp.path().file_name().unwrap().to_string_lossy();
    assert!(name.starts_with("cockpit-prompt-"), "{name}");
    assert!(name.ends_with(".md"), "{name}");
    assert_ne!(
        name.as_ref(),
        format!("cockpit-prompt-{}.md", std::process::id())
    );
}

#[cfg(unix)]
#[test]
fn external_editor_tempfile_is_owner_only() {
    use std::os::unix::fs::PermissionsExt;

    let temp = new_external_editor_tempfile().unwrap();
    let mode = temp.path().metadata().unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
}

#[test]
fn parse_sandbox_arg_maps_to_modes_and_network() {
    use cockpit_core::tools::sandbox_mode::SandboxMode;

    assert_eq!(parse_sandbox_arg(""), Ok(SandboxCommand::Cycle));
    assert_eq!(parse_sandbox_arg("  "), Ok(SandboxCommand::Cycle));
    assert_eq!(
        parse_sandbox_arg("on"),
        Ok(SandboxCommand::Set(SandboxMode::Sandbox))
    );
    assert_eq!(
        parse_sandbox_arg("off"),
        Ok(SandboxCommand::Set(SandboxMode::Off))
    );
    assert_eq!(
        parse_sandbox_arg("container"),
        Ok(SandboxCommand::Set(SandboxMode::Container))
    );
    assert_eq!(
        parse_sandbox_arg("container-ro"),
        Ok(SandboxCommand::Set(SandboxMode::ContainerReadonly))
    );
    assert_eq!(
        parse_sandbox_arg("readonly"),
        Ok(SandboxCommand::Set(SandboxMode::ContainerReadonly))
    );
    assert_eq!(
        parse_sandbox_arg("network   ON"),
        Ok(SandboxCommand::Network(true))
    );
    assert_eq!(
        parse_sandbox_arg("network off"),
        Ok(SandboxCommand::Network(false))
    );
    assert_eq!(parse_sandbox_arg("maybe"), Err("maybe".to_string()));
}

#[test]
fn parse_sandbox_escalation_arg_maps_to_actions() {
    assert_eq!(
        parse_sandbox_escalation_arg(""),
        Ok(SandboxEscalationCommand::Status)
    );
    assert_eq!(
        parse_sandbox_escalation_arg(" allow "),
        Ok(SandboxEscalationCommand::Set(true))
    );
    assert_eq!(
        parse_sandbox_escalation_arg("DISALLOW"),
        Ok(SandboxEscalationCommand::Set(false))
    );
    assert_eq!(
        parse_sandbox_escalation_arg("maybe"),
        Err("maybe".to_string())
    );
}

#[test]
fn next_sandbox_mode_skips_unavailable_container_modes() {
    use super::next_sandbox_mode;
    use cockpit_core::container::{ContainerAvailability, ContainerUnavailableReason};
    use cockpit_core::tools::sandbox_mode::SandboxMode;

    let unavailable = ContainerAvailability {
        runtime: None,
        harness_in_container: false,
        available: false,
        reason: Some(ContainerUnavailableReason::NoRuntime),
    };
    assert_eq!(
        next_sandbox_mode(SandboxMode::Off, &unavailable),
        SandboxMode::Sandbox
    );
    assert_eq!(
        next_sandbox_mode(SandboxMode::Sandbox, &unavailable),
        SandboxMode::Off
    );

    let available = ContainerAvailability {
        runtime: Some(cockpit_core::container::ContainerRuntimeKind::Docker),
        harness_in_container: false,
        available: true,
        reason: None,
    };
    assert_eq!(
        next_sandbox_mode(SandboxMode::Sandbox, &available),
        SandboxMode::Container
    );
    assert_eq!(
        next_sandbox_mode(SandboxMode::Container, &available),
        SandboxMode::ContainerReadonly
    );
}

#[test]
fn parse_llm_mode_arg_toggle_default_and_aliases() {
    use cockpit_config::extended::LlmMode;
    // No arg or `toggle` → toggle (None).
    assert_eq!(parse_llm_mode_arg(""), Ok(None));
    assert_eq!(parse_llm_mode_arg("  "), Ok(None));
    assert_eq!(parse_llm_mode_arg("toggle"), Ok(None));
    assert_eq!(parse_llm_mode_arg("TOGGLE"), Ok(None));
    // `defend` is the advertised form; `defensive` is a silent alias.
    assert_eq!(parse_llm_mode_arg("defend"), Ok(Some(LlmMode::Defensive)));
    assert_eq!(
        parse_llm_mode_arg("defensive"),
        Ok(Some(LlmMode::Defensive))
    );
    assert_eq!(parse_llm_mode_arg(" Defend "), Ok(Some(LlmMode::Defensive)));
    // `normal` selects normal.
    assert_eq!(parse_llm_mode_arg("normal"), Ok(Some(LlmMode::Normal)));
    // `frontier` selects frontier; no short alias is accepted.
    assert_eq!(parse_llm_mode_arg("frontier"), Ok(Some(LlmMode::Frontier)));
    assert!(parse_llm_mode_arg("front").is_err());
    // Anything else is a usage error.
    assert!(parse_llm_mode_arg("yolo").is_err());
}

#[test]
fn cache_break_warning_suppressed_on_no_cache_provider() {
    use cockpit_config::providers::{CacheConfig, CacheMode};
    // No-cache provider → the predicate says it doesn't cache, so the
    // warning is suppressed.
    let none = CacheConfig {
        mode: CacheMode::None,
        ttl_secs: 300,
    };
    assert!(
        !cache_config_caches(&none),
        "a no-cache provider must report no caching (warning suppressed)"
    );
    // Caching provider → the warning fires.
    let ephemeral = CacheConfig {
        mode: CacheMode::Ephemeral,
        ttl_secs: 300,
    };
    assert!(
        cache_config_caches(&ephemeral),
        "a caching provider must report caching (warning fires)"
    );
}

#[test]
fn xml_escape_attr() {
    assert_eq!(xml_escape("a\"b<c>&d"), "a&quot;b&lt;c&gt;&amp;d");
}

#[test]
fn cap_tokens_keeps_small_input() {
    let small = "short git output";
    assert_eq!(cap_tokens(small, GIT_AGENT_TOKEN_CAP), small);
}

#[test]
fn cap_tokens_truncates_large_input() {
    let big = "word ".repeat(5000);
    let capped = cap_tokens(&big, 100);
    assert!(capped.contains("truncated"));
    assert!(cockpit_core::tokens::count(&capped) <= 200);
}

#[test]
fn tool_invocation_websearch_shows_query_text() {
    let (summary, full) = tool_invocation(
        "websearch",
        &json!({ "query": "OpenAI model release news" }),
    );
    assert_eq!(summary, "OpenAI model release news");
    assert_eq!(full, "OpenAI model release news");
    assert!(!summary.contains("<25c>"));
}

#[test]
fn tool_invocation_unknown_tool_shows_string_args() {
    let prompt = "Describe the deployment risk for the west region".repeat(2);
    let (summary, full) = tool_invocation(
        "custom_audit",
        &json!({ "prompt": prompt, "dry_run": true }),
    );
    assert!(summary.contains("prompt=\"Describe the deployment risk"));
    assert!(summary.contains("dry_run=true"));
    assert!(full.contains("Describe the deployment risk for the west region"));
    assert!(!summary.contains("<"));
    assert!(!full.contains("<"));
}

#[cfg(unix)]
fn sh_command(script: &str) -> std::process::Command {
    let mut command = std::process::Command::new("/bin/sh");
    command.arg("-c").arg(script);
    command
}

#[cfg(unix)]
#[test]
fn exec_capture_shell_captures_stdout_and_status() {
    use super::exec_capture_shell;
    let (out, failed) = exec_capture_shell("printf hello", std::path::Path::new("."));
    assert!(!failed);
    assert!(out.contains("hello"));
    let (_o, failed) = exec_capture_shell("exit 3", std::path::Path::new("."));
    assert!(failed);
}

#[cfg(unix)]
#[test]
fn run_capture_kills_on_output_overflow_and_keeps_tail() {
    let options = super::RunCaptureOptions {
        max_bytes: 128,
        timeout: Duration::from_secs(5),
        cancel: None,
    };
    let (out, failed) = super::run_capture_with_options(
        sh_command(r#"i=0; while :; do printf 'prefix-%04d-suffix\n' "$i"; i=$((i+1)); done"#),
        options,
    );

    assert!(failed);
    assert!(out.contains("command output exceeded 128 bytes"), "{out}");
    assert!(!out.contains("prefix-0000-suffix"), "{out}");
    assert!(
        out.len() < 512,
        "overflow output was not capped: {}",
        out.len()
    );
}

#[cfg(unix)]
#[test]
fn run_capture_timeout_kills_child() {
    let options = super::RunCaptureOptions {
        max_bytes: 1024,
        timeout: Duration::from_millis(50),
        cancel: None,
    };
    let started = Instant::now();
    let (out, failed) = super::run_capture_with_options(sh_command("sleep 5"), options);

    assert!(failed);
    assert!(started.elapsed() < Duration::from_secs(2));
    assert!(out.contains("command timed out"), "{out}");
}

#[cfg(unix)]
#[test]
fn run_capture_keeps_stdout_and_stderr_tails() {
    let options = super::RunCaptureOptions {
        max_bytes: 24,
        timeout: Duration::from_secs(5),
        cancel: None,
    };
    let (out, failed) = super::run_capture_with_options(
        sh_command(
            "printf 'stdout-old-aaaaaaaaaaaaaaaa'; printf 'stdout-tail\n'; printf 'stderr-old-bbbbbbbbbbbbbbbb' >&2; printf 'stderr-tail\n' >&2",
        ),
        options,
    );

    assert!(failed, "tail truncation is reported as failed overflow");
    assert!(out.contains("stdout-tail"), "{out}");
    assert!(out.contains("stderr-tail"), "{out}");
    assert!(!out.contains("stdout-old"), "{out}");
    assert!(!out.contains("stderr-old"), "{out}");
    assert!(out.contains("command output exceeded 24 bytes"), "{out}");
}

#[cfg(unix)]
#[test]
fn run_capture_cancellation_kills_child() {
    let cancel = Arc::new(AtomicBool::new(false));
    let cancel_for_thread = Arc::clone(&cancel);
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(50));
        cancel_for_thread.store(true, Ordering::Relaxed);
    });
    let options = super::RunCaptureOptions {
        max_bytes: 1024,
        timeout: Duration::from_secs(5),
        cancel: Some(cancel),
    };
    let started = Instant::now();
    let (out, failed) = super::run_capture_with_options(sh_command("sleep 5"), options);

    assert!(failed);
    assert!(started.elapsed() < Duration::from_secs(2));
    assert!(out.contains("command cancelled"), "{out}");
}
