//! `cockpit run` — one-shot non-interactive prompt through the daemon.
//!
//! Lifecycle (GOALS §8b + the user's refinement on the `--ephemeral`
//! flag):
//!
//! - **Default:** attach to a long-running daemon if one is up;
//!   otherwise spawn an ephemeral daemon that exits when the run
//!   completes.
//! - **`--ephemeral`:** always spawn a fresh daemon for this run. The
//!   daemon ends when the run does.
//!
//! Behavior:
//!
//! 1. Resolve project root (cwd or `--project`).
//! 2. Build the prompt (argv + stdin).
//! 3. probe_or_spawn the daemon, attach a new session.
//! 4. Send the prompt and pump events until `TurnComplete`.
//! 5. In `default` format we stream assistant text to stdout; in
//!    `json` format we emit one envelope per line.
//! 6. If we own the daemon (ephemeral path), shut it down. An
//!    [`EphemeralDaemonGuard`] (Layer A) guarantees this fires on every
//!    exit — happy path, early `?` error, panic/unwind, or
//!    SIGINT/SIGTERM — never on a run that attached to a pre-existing
//!    persistent daemon.

use std::io::{IsTerminal, Read, Write};

use anyhow::{Context, Result};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::cli::{OutputFormat, RunArgs};
use crate::daemon::client::{LifecycleMode, probe_or_spawn};
use crate::daemon::ephemeral_guard::{EphemeralDaemonGuard, spawn_signal_shutdown};
use crate::daemon::proto::{self, Request, Response};

#[derive(Debug, Clone, Default)]
pub(crate) struct RunPumpOptions<'a> {
    pub(crate) verbose_json: bool,
    pub(crate) follow: bool,
    pub(crate) session: Option<&'a str>,
    pub(crate) agent_override: Option<&'a str>,
    pub(crate) model_override: Option<&'a str>,
}

pub async fn run(args: RunArgs, no_sandbox: bool) -> Result<()> {
    let cwd = std::env::current_dir().context("resolving cwd")?;
    let db = crate::db::Db::open_default().context("opening cockpit DB")?;
    crate::config::trust::enforce_noninteractive_workspace_trust(&db, &cwd)?;

    let format = args.output_format();
    let json_mode = matches!(format, OutputFormat::Json);
    let prompt = match build_prompt(&args) {
        Ok(prompt) => prompt,
        Err(e) if json_mode => {
            emit_json(&json!({
                "event": "error",
                "code": "invalid_arguments",
                "message": e.to_string()
            }))?;
            std::process::exit(2);
        }
        Err(e) => return Err(e),
    };
    if args.ephemeral && args.session.is_some() {
        if json_mode {
            emit_json(&json!({
                "event": "error",
                "code": "invalid_arguments",
                "message": "--ephemeral cannot be combined with --session"
            }))?;
            std::process::exit(2);
        }
        anyhow::bail!("--ephemeral cannot be combined with --session");
    }
    if prompt.trim().is_empty() && !(args.follow && args.session.is_some()) {
        if json_mode {
            emit_json(&json!({
                "event": "error",
                "code": "empty_prompt",
                "message": "no prompt supplied (pass a message, --prompt-file, or pipe one on stdin)"
            }))?;
            std::process::exit(2);
        }
        anyhow::bail!("no prompt supplied (pass a message or pipe one on stdin)");
    }

    let mode = if args.ephemeral {
        LifecycleMode::AlwaysEphemeral
    } else {
        LifecycleMode::AttachOrEphemeral
    };

    let daemon = probe_or_spawn(mode).await?;
    let client = daemon.client.clone();

    // Layer A: arm the shutdown backstop *only* when we own the daemon.
    // Held across every `?` below so an error return still reaps it.
    let guard = daemon
        .owns_daemon
        .then(|| EphemeralDaemonGuard::new(daemon.socket.clone()));

    // A signal handler so Ctrl-C / SIGTERM during the run reaps the
    // daemon instead of orphaning it. Shares the guard's armed flag and
    // socket so it drives the identical synchronous shutdown.
    let signal_task = spawn_signal_shutdown(guard.as_ref(), true);

    let result = run_turn(&client, &args, prompt, no_sandbox).await;

    // Stop the signal watcher and run the (now happy-path) shutdown
    // before deciding the exit code, so the daemon is gone whether the
    // turn succeeded or errored.
    if let Some(task) = signal_task {
        task.abort();
    }
    if let Some(guard) = &guard {
        guard.shutdown();
    }
    // Drop the guard explicitly here so its (now-disarmed) drop is a
    // no-op and we don't carry it past `process::exit`.
    drop(guard);

    let exit_code = match result {
        Ok(code) => code,
        Err(e) if json_mode => {
            emit_json(&json!({
                "event": "error",
                "code": "command_failed",
                "message": e.to_string()
            }))?;
            1
        }
        Err(e) => return Err(e),
    };
    if exit_code != 0 {
        std::process::exit(exit_code);
    }
    Ok(())
}

/// Attach, send the prompt, pump events. Split out so the `?` operators
/// unwind through [`run`]'s guard rather than skipping it.
async fn run_turn(
    client: &crate::daemon::client::DaemonClient,
    args: &RunArgs,
    prompt: String,
    no_sandbox: bool,
) -> Result<i32> {
    attach_send_pump(
        client,
        prompt,
        no_sandbox,
        args.output_format(),
        RunPumpOptions {
            verbose_json: args.verbose,
            follow: args.follow,
            session: args.session.as_deref(),
            agent_override: args.agent.as_deref(),
            model_override: args.model.as_deref(),
        },
    )
    .await
}

/// Attach a fresh headless session, send `prompt`, and pump events to
/// completion, returning the run exit code. Shared by `cockpit run` and
/// `cockpit init` so both drive the identical non-interactive turn over
/// the daemon. The caller owns the daemon lifecycle (probe/spawn +
/// ephemeral guard).
pub(crate) async fn attach_send_pump(
    client: &crate::daemon::client::DaemonClient,
    prompt: String,
    no_sandbox: bool,
    format: OutputFormat,
    options: RunPumpOptions<'_>,
) -> Result<i32> {
    let cwd = std::env::current_dir().context("resolving cwd")?;
    let project_root = cwd.to_string_lossy().into_owned();
    let requested_session = options
        .session
        .map(Uuid::parse_str)
        .transpose()
        .context("parsing --session")?;
    let env_snapshot = crate::env_snapshot::EnvSnapshot::from_process(
        crate::env_snapshot::EnvSnapshotSource::ExplicitCli,
    );

    // Attach a fresh session. `no_sandbox` (sandboxing part 2) makes this
    // noninteractive session start unsandboxed unless the daemon was
    // launched `--no-sandbox` (which wins). `model_override` (`--model`, the
    // plan executor passes the plan's pinned model) overrides every spawned
    // agent's frontmatter model for this session's run.
    let attached = client
        .request_ok(Request::Attach {
            session_id: requested_session,
            project_root: Some(project_root),
            no_sandbox,
            // A streamed run has no UI to answer an interrupt — a
            // non-interactive attach. The loop guard treats the session as
            // headless and auto-rejects a back-to-back repeat (with the
            // guidance error) rather than blocking.
            interactive: false,
            model_override: options.model_override.map(str::to_string),
            client_protocol_version: crate::daemon::proto::PROTOCOL_VERSION,
            env_snapshot: Some(env_snapshot.to_wire()),
            env_policy: crate::env_snapshot::EnvDriftPolicy::Daemon,
        })
        .await?;
    let (session_id, repair_required) = match attached {
        Response::Attached {
            session_id,
            repair_required,
            ..
        } => (session_id, repair_required.map(|repair| *repair)),
        other => anyhow::bail!("unexpected attach response: {other:?}"),
    };
    if requested_session.is_some()
        && let Some(repair) = repair_required
    {
        let label = if repair.short_id.is_empty() {
            repair.session_id.to_string()
        } else {
            repair.short_id.clone()
        };
        let ids = if repair.failing_tool_call_ids.is_empty() {
            "unknown".to_string()
        } else {
            repair.failing_tool_call_ids.join(", ")
        };
        anyhow::bail!(
            "session {label} requires Responses transcript repair before model dispatch\n\
             provider/model: {}/{} ({})\n\
             failure: {} ({ids})\n\
             detail: {}\n\
             actions: open in the TUI for read-only browsing, use `/fork` from the last valid turn, explicitly repair synthetic tool results, or run `cockpit export {label}` for a debug bundle",
            repair.provider,
            repair.model,
            repair.wire_api,
            repair.failure_kind,
            repair.detail
        );
    }
    if matches!(format, OutputFormat::Json) {
        emit_json(&json!({
            "event": "session_attached",
            "session_id": session_id,
            "resumed": requested_session.is_some()
        }))?;
    }
    if let Some(agent) = options.agent_override {
        client
            .request_ok(Request::SetAgent {
                name: agent.to_string(),
            })
            .await
            .with_context(|| format!("switching run session to agent `{agent}`"))?;
    }

    let was_processing = is_processing(client, session_id).await?;
    if !prompt.trim().is_empty() {
        // Send the user message.
        client
            .request_ok(Request::SendUserMessage {
                text: prompt,
                image_refs: Vec::new(),
                forced_skill: None,
            })
            .await
            .context("sending user message")?;
        if matches!(format, OutputFormat::Json) {
            emit_json(&json!({
                "event": "message_sent",
                "session_id": session_id
            }))?;
        }
    }

    if requested_session.is_some() && was_processing && !options.follow {
        if matches!(format, OutputFormat::Json) {
            emit_json(&json!({
                "event": "message_queued",
                "session_id": session_id
            }))?;
        }
        return Ok(0);
    }

    // Pump events until the turn completes (or the session ends).
    pump_events(client, session_id, format, options.verbose_json).await
}

fn build_prompt(args: &RunArgs) -> Result<String> {
    let has_message = !args.message.is_empty();
    if has_message && args.prompt_file.is_some() {
        anyhow::bail!("ambiguous prompt sources: pass either message args or --prompt-file");
    }

    if let Some(path) = &args.prompt_file {
        if !std::io::stdin().is_terminal() {
            anyhow::bail!("ambiguous prompt sources: stdin cannot be combined with --prompt-file");
        }
        return std::fs::read_to_string(path)
            .with_context(|| format!("reading prompt file {}", path.display()));
    }

    if !std::io::stdin().is_terminal() {
        if has_message {
            anyhow::bail!("ambiguous prompt sources: stdin cannot be combined with message args");
        }
        let mut stdin_buf = String::new();
        std::io::stdin()
            .read_to_string(&mut stdin_buf)
            .context("reading stdin")?;
        return Ok(stdin_buf.trim_end().to_string());
    }

    Ok(args.message.join(" "))
}

pub(crate) async fn pump_events(
    client: &crate::daemon::client::DaemonClient,
    session_id: Uuid,
    format: OutputFormat,
    verbose_json: bool,
) -> Result<i32> {
    let mut stdout = std::io::stdout().lock();
    let mut error_seen = false;

    while let Some(event) = client.next_event().await {
        // Filter to this session's events.
        if event_session(&event) != Some(session_id) {
            continue;
        }

        match handle_run_event(
            session_id,
            &event,
            format,
            verbose_json,
            stdout.is_terminal(),
            &mut stdout,
            &mut error_seen,
        ) {
            RunEventAction::Continue => {}
            RunEventAction::Break => break,
            RunEventAction::Return(code) => return Ok(code),
        }
    }

    let _ = stdout.write_all(b"\n");
    let _ = stdout.flush();

    Ok(if error_seen { 3 } else { 0 })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RunEventAction {
    Continue,
    Break,
    Return(i32),
}

fn handle_run_event(
    session_id: Uuid,
    event: &proto::Event,
    format: OutputFormat,
    verbose_json: bool,
    sanitize_tty: bool,
    stdout: &mut impl Write,
    error_seen: &mut bool,
) -> RunEventAction {
    match format {
        OutputFormat::Default => match event {
            proto::Event::AssistantTextDelta { delta, .. } => {
                if sanitize_tty {
                    let _ = stdout.write_all(sanitize_terminal_text(delta).as_bytes());
                } else {
                    let _ = stdout.write_all(delta.as_bytes());
                }
                let _ = stdout.flush();
            }
            proto::Event::ToolError { tool, error, .. } => {
                *error_seen = true;
                let _ = writeln!(stdout, "\n[error: {tool}: {error}]");
            }
            proto::Event::InferenceFailed {
                provider,
                model,
                error_class,
                detail,
                ..
            } => {
                *error_seen = true;
                let _ = writeln!(
                    stdout,
                    "\n[inference failed: {provider}/{model} {error_class}: {detail}]"
                );
            }
            proto::Event::SessionPersistFailed { error, .. } => {
                eprintln!("[session persist failed: {error}]");
                return RunEventAction::Return(3);
            }
            proto::Event::Reconnecting {
                attempt,
                provider,
                model,
                url,
                ..
            } => {
                // Non-interactive parity: surface the indefinite network retry
                // on stderr (recurring, attempt-numbered, naming
                // provider/model/url) so a headless `run` against a downed
                // server is never silently hung. Stderr keeps stdout the clean
                // assistant transcript.
                eprintln!(
                    "[reconnecting: {provider}/{model} unreachable at {url} (attempt {attempt})]"
                );
            }
            proto::Event::SessionEnded { reason, .. } => {
                let _ = writeln!(stdout, "\n[session ended: {reason}]");
                return RunEventAction::Break;
            }
            _ => {}
        },
        OutputFormat::Json => {
            if let Some(value) = normalized_event(session_id, event, verbose_json)
                && let Ok(line) = serde_json::to_string(&value)
            {
                let _ = writeln!(stdout, "{line}");
            }
        }
    }

    if matches!(event, proto::Event::SessionEnded { .. }) {
        return RunEventAction::Break;
    }
    if matches!(event, proto::Event::InferenceFailed { .. }) {
        *error_seen = true;
    }
    if let proto::Event::SessionPersistFailed { error, .. } = event {
        if matches!(format, OutputFormat::Json) {
            eprintln!("[session persist failed: {error}]");
        }
        return RunEventAction::Return(3);
    }
    if matches!(event, proto::Event::AgentIdle { .. }) {
        return RunEventAction::Break;
    }
    RunEventAction::Continue
}

fn sanitize_terminal_text(input: &str) -> String {
    enum Escape {
        None,
        Esc,
        Csi,
        Osc,
        OscEsc,
    }

    let mut out = String::with_capacity(input.len());
    let mut escape = Escape::None;
    for ch in input.chars() {
        match escape {
            Escape::None => match ch {
                '\u{1b}' => escape = Escape::Esc,
                '\n' | '\t' => out.push(ch),
                c if c.is_control() => {}
                c => out.push(c),
            },
            Escape::Esc => match ch {
                '[' => escape = Escape::Csi,
                ']' => escape = Escape::Osc,
                '\u{1b}' => escape = Escape::Esc,
                c if ('@'..='~').contains(&c) => escape = Escape::None,
                _ => {}
            },
            Escape::Csi => {
                if ('@'..='~').contains(&ch) {
                    escape = Escape::None;
                }
            }
            Escape::Osc => match ch {
                '\u{7}' => escape = Escape::None,
                '\u{1b}' => escape = Escape::OscEsc,
                _ => {}
            },
            Escape::OscEsc => {
                escape = if ch == '\\' {
                    Escape::None
                } else {
                    Escape::Osc
                };
            }
        }
    }
    out
}

async fn is_processing(
    client: &crate::daemon::client::DaemonClient,
    session_id: Uuid,
) -> Result<bool> {
    match client
        .request_ok(Request::SessionLiveStatus {
            session_ids: vec![session_id],
        })
        .await?
    {
        Response::SessionLiveStatus { statuses } => Ok(statuses
            .into_iter()
            .any(|s| s.session_id == session_id && s.processing)),
        other => anyhow::bail!("unexpected live-status response: {other:?}"),
    }
}

fn emit_json(value: &Value) -> Result<()> {
    println!("{}", serde_json::to_string(value)?);
    Ok(())
}

fn normalized_event(session_id: Uuid, event: &proto::Event, verbose: bool) -> Option<Value> {
    let mut value = match event {
        proto::Event::ThinkingStarted { agent, .. } => {
            json!({ "event": "thinking_started", "session_id": session_id, "agent": agent })
        }
        proto::Event::AssistantTextDelta { agent, delta, .. } => {
            json!({ "event": "assistant_delta", "session_id": session_id, "agent": agent, "delta": delta })
        }
        proto::Event::ReasoningDelta { agent, delta, .. } => {
            json!({ "event": "reasoning_delta", "session_id": session_id, "agent": agent, "delta": delta })
        }
        proto::Event::AssistantText {
            agent,
            text,
            reasoning,
            seq,
            ..
        } => json!({
            "event": "assistant_message",
            "session_id": session_id,
            "agent": agent,
            "text": text,
            "reasoning": reasoning,
            "seq": seq
        }),
        proto::Event::UserMessageRecorded { seq, .. } => {
            json!({ "event": "user_message_recorded", "session_id": session_id, "seq": seq })
        }
        proto::Event::ToolStart {
            agent,
            call_id,
            tool,
            args,
            ..
        } => json!({
            "event": "tool_start",
            "session_id": session_id,
            "agent": agent,
            "call_id": call_id,
            "tool": tool,
            "args": args
        }),
        proto::Event::ToolEnd {
            agent,
            call_id,
            tool,
            output,
            truncated,
            ..
        } => json!({
            "event": "tool_end",
            "session_id": session_id,
            "agent": agent,
            "call_id": call_id,
            "tool": tool,
            "output": output,
            "truncated": truncated
        }),
        proto::Event::ResourceWait {
            agent,
            request_id,
            display_id,
            resources,
            queue_position,
            ..
        } => json!({
            "event": "resource_wait",
            "session_id": session_id,
            "agent": agent,
            "request_id": request_id,
            "display_id": display_id,
            "resources": resources,
            "queue_position": queue_position
        }),
        proto::Event::ResourceStart {
            agent,
            request_id,
            display_id,
            resources,
            wait_ms,
            ..
        } => json!({
            "event": "resource_start",
            "session_id": session_id,
            "agent": agent,
            "request_id": request_id,
            "display_id": display_id,
            "resources": resources,
            "wait_ms": wait_ms
        }),
        proto::Event::ResourceClear {
            agent,
            request_id,
            display_id,
            resources,
            ..
        } => json!({
            "event": "resource_clear",
            "session_id": session_id,
            "agent": agent,
            "request_id": request_id,
            "display_id": display_id,
            "resources": resources
        }),
        proto::Event::ToolError {
            agent,
            call_id,
            tool,
            error,
            ..
        } => json!({
            "event": "tool_error",
            "session_id": session_id,
            "agent": agent,
            "call_id": call_id,
            "tool": tool,
            "error": error
        }),
        proto::Event::InferenceFailed {
            agent,
            provider,
            model,
            error_class,
            detail,
            ..
        } => json!({
            "event": "inference_failed",
            "session_id": session_id,
            "agent": agent,
            "provider": provider,
            "model": model,
            "error_class": error_class,
            "detail": detail
        }),
        proto::Event::Usage {
            agent,
            input_tokens,
            output_tokens,
            cached_input_tokens,
            cache_creation_input_tokens,
            ..
        } => json!({
            "event": "usage",
            "session_id": session_id,
            "agent": agent,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "cached_input_tokens": cached_input_tokens,
            "cache_creation_input_tokens": cache_creation_input_tokens
        }),
        proto::Event::AgentIdle { .. } => {
            json!({ "event": "turn_complete", "session_id": session_id })
        }
        proto::Event::SessionEnded { reason, .. } => {
            json!({ "event": "session_ended", "session_id": session_id, "reason": reason })
        }
        proto::Event::SessionPersistFailed { error, .. } => {
            json!({ "event": "error", "session_id": session_id, "code": "session_persist_failed", "message": error })
        }
        other if verbose => {
            json!({ "event": "raw_event", "session_id": session_id, "raw": proto::Envelope::event(other.clone()) })
        }
        _ => return None,
    };
    if verbose
        && let Some(obj) = value.as_object_mut()
        && !obj.contains_key("raw")
    {
        obj.insert(
            "raw".to_string(),
            json!(proto::Envelope::event(event.clone())),
        );
    }
    Some(value)
}

fn event_session(event: &proto::Event) -> Option<uuid::Uuid> {
    use proto::Event::*;
    Some(match event {
        ThinkingStarted { session_id, .. }
        | QueueUpdated { session_id, .. }
        | ForegroundInputTarget { session_id, .. }
        | Reconnecting { session_id, .. }
        | AssistantTextDelta { session_id, .. }
        | ReasoningDelta { session_id, .. }
        | AssistantText { session_id, .. }
        | UserMessageRecorded { session_id, .. }
        | QueuedUserMessagesFolded { session_id, .. }
        | SessionPersistFailed { session_id, .. }
        | SessionDriverFailed { session_id, .. }
        | PreflightStarted { session_id, .. }
        | UserMessageRetracted { session_id, .. }
        | Notice { session_id, .. }
        | SkillAutoInjected { session_id, .. }
        | ToolStart { session_id, .. }
        | ToolEnd { session_id, .. }
        | ResourceWait { session_id, .. }
        | ResourceStart { session_id, .. }
        | ResourceClear { session_id, .. }
        | ToolError { session_id, .. }
        | InferenceFailed { session_id, .. }
        | InferenceWarning { session_id, .. }
        | BackupUsed { session_id, .. }
        | SubagentSpawned { session_id, .. }
        | SubagentReport { session_id, .. }
        | NestedTurn { session_id, .. }
        | Usage { session_id, .. }
        | InterruptRaised { session_id, .. }
        | InterruptResolved { session_id, .. }
        | AgentIdle { session_id, .. }
        | PrimarySwapped { session_id, .. }
        | LlmModeChanged { session_id, .. }
        | SessionEnded { session_id, .. }
        | ScheduleStarted { session_id, .. }
        | ScheduleProgress { session_id, .. }
        | ScheduleNote { session_id, .. }
        | ScheduleCompleted { session_id, .. }
        | ContextProjection { session_id, .. }
        | Pruned { session_id, .. }
        | CompactReady { session_id, .. }
        | SandboxState { session_id, .. }
        | SandboxUnavailable { session_id, .. }
        | RedactionState { session_id, .. }
        | PreflightState { session_id, .. }
        | TrustedOnlyState { session_id, .. }
        | ApprovalModeState { session_id, .. }
        | DelegationRecursionState { session_id, .. }
        | TandemState { session_id, .. }
        | GitignoreAllow { session_id, .. }
        | PausedWorkAvailable { session_id, .. }
        | WaitingForLock { session_id, .. } => *session_id,
        // Daemon-global events (no session_id) — irrelevant to a headless
        // one-shot run, so they're filtered out by the session check.
        CaffeinateState { .. }
        | ConnectorStatus { .. }
        | DaemonDraining { .. }
        | TerminalOutput { .. }
        | TerminalClipboard { .. }
        | TerminalViewers { .. }
        | TerminalClosed { .. }
        | LspNotice { .. }
        | EnvDriftWarning { .. } => {
            return None;
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_agent_idle_becomes_turn_complete_with_session_id() {
        let session_id = Uuid::new_v4();
        let value = normalized_event(
            session_id,
            &proto::Event::AgentIdle {
                session_id,
                turn_id: None,
            },
            false,
        )
        .expect("normalized event");

        assert_eq!(value["event"], "turn_complete");
        assert_eq!(value["session_id"], session_id.to_string());
        assert!(value.get("raw").is_none());
    }

    #[test]
    fn json_default_stream_is_normalized_not_raw_envelope() {
        let session_id = Uuid::new_v4();
        let value = normalized_event(
            session_id,
            &proto::Event::AssistantTextDelta {
                session_id,
                agent: "Build".into(),
                delta: "hi".into(),
            },
            false,
        )
        .expect("normalized event");

        assert_eq!(value["event"], "assistant_delta");
        assert_eq!(value["session_id"], session_id.to_string());
        assert_eq!(value["agent"], "Build");
        assert_eq!(value["delta"], "hi");
        assert!(value.get("kind").is_none());
        assert!(value.get("raw").is_none());
    }

    #[test]
    fn verbose_json_preserves_normalized_event_and_raw_envelope() {
        let session_id = Uuid::new_v4();
        let value = normalized_event(
            session_id,
            &proto::Event::UserMessageRecorded {
                session_id,
                seq: 42,
                preflight_cleaned: None,
            },
            true,
        )
        .expect("normalized event");

        assert_eq!(value["event"], "user_message_recorded");
        assert_eq!(value["session_id"], session_id.to_string());
        assert_eq!(value["seq"], 42);
        assert_eq!(value["raw"]["kind"], "evt");
        assert_eq!(value["raw"]["event"], "user_message_recorded");
    }

    #[test]
    fn verbose_json_wraps_unknown_session_event() {
        let session_id = Uuid::new_v4();
        let value = normalized_event(
            session_id,
            &proto::Event::Notice {
                session_id,
                text: "heads up".into(),
            },
            true,
        )
        .expect("raw wrapper");

        assert_eq!(value["event"], "raw_event");
        assert_eq!(value["session_id"], session_id.to_string());
        assert_eq!(value["raw"]["kind"], "evt");
        assert_eq!(value["raw"]["event"], "notice");
    }

    #[test]
    fn default_handler_surfaces_drained_tool_error() {
        let session_id = Uuid::new_v4();
        let mut out = Vec::new();
        let mut error_seen = false;
        let action = handle_run_event(
            session_id,
            &proto::Event::ToolError {
                session_id,
                agent: "Build".into(),
                call_id: "call-1".into(),
                tool: "bash".into(),
                error: "boom".into(),
                kind: crate::engine::tool::ToolFailKind::Execution,
            },
            OutputFormat::Default,
            false,
            false,
            &mut out,
            &mut error_seen,
        );

        assert_eq!(action, RunEventAction::Continue);
        assert!(error_seen);
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("[error: bash: boom]"));
    }

    #[test]
    fn default_handler_surfaces_inference_failed_and_sets_error() {
        let session_id = Uuid::new_v4();
        let mut out = Vec::new();
        let mut error_seen = false;
        let action = handle_run_event(
            session_id,
            &proto::Event::InferenceFailed {
                session_id,
                agent: "Build".into(),
                provider: "openai".into(),
                model: "gpt-5".into(),
                error_class: "auth".into(),
                detail: "credentials rejected".into(),
            },
            OutputFormat::Default,
            false,
            false,
            &mut out,
            &mut error_seen,
        );

        assert_eq!(action, RunEventAction::Continue);
        assert!(error_seen);
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("[inference failed: openai/gpt-5 auth: credentials rejected]"));
    }

    #[test]
    fn json_handler_emits_inference_failed_and_sets_error() {
        let session_id = Uuid::new_v4();
        let mut out = Vec::new();
        let mut error_seen = false;
        let action = handle_run_event(
            session_id,
            &proto::Event::InferenceFailed {
                session_id,
                agent: "Build".into(),
                provider: "openai".into(),
                model: "gpt-5".into(),
                error_class: "auth".into(),
                detail: "credentials rejected".into(),
            },
            OutputFormat::Json,
            false,
            false,
            &mut out,
            &mut error_seen,
        );

        assert_eq!(action, RunEventAction::Continue);
        assert!(error_seen);
        let line: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(line["event"], "inference_failed");
        assert_eq!(line["provider"], "openai");
        assert_eq!(line["model"], "gpt-5");
        assert_eq!(line["error_class"], "auth");
        assert_eq!(line["detail"], "credentials rejected");
    }

    #[test]
    fn default_handler_surfaces_drained_session_ended_and_breaks() {
        let session_id = Uuid::new_v4();
        let mut out = Vec::new();
        let mut error_seen = false;
        let action = handle_run_event(
            session_id,
            &proto::Event::SessionEnded {
                session_id,
                reason: "done".into(),
            },
            OutputFormat::Default,
            false,
            false,
            &mut out,
            &mut error_seen,
        );

        assert_eq!(action, RunEventAction::Break);
        assert!(!error_seen);
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("[session ended: done]"));
    }

    #[test]
    fn default_handler_streams_drained_assistant_deltas_once() {
        let session_id = Uuid::new_v4();
        let mut out = Vec::new();
        let mut error_seen = false;
        for delta in ["hello", " world"] {
            let action = handle_run_event(
                session_id,
                &proto::Event::AssistantTextDelta {
                    session_id,
                    agent: "Build".into(),
                    delta: delta.into(),
                },
                OutputFormat::Default,
                false,
                false,
                &mut out,
                &mut error_seen,
            );
            assert_eq!(action, RunEventAction::Continue);
        }

        assert!(!error_seen);
        assert_eq!(String::from_utf8(out).unwrap(), "hello world");
    }

    #[test]
    fn default_handler_strips_terminal_control_sequences_for_tty() {
        let session_id = Uuid::new_v4();
        let mut out = Vec::new();
        let mut error_seen = false;
        let action = handle_run_event(
            session_id,
            &proto::Event::AssistantTextDelta {
                session_id,
                agent: "Build".into(),
                delta: "\u{1b}[31mred\u{1b}[0m\tok\n\u{7}x".into(),
            },
            OutputFormat::Default,
            false,
            true,
            &mut out,
            &mut error_seen,
        );

        assert_eq!(action, RunEventAction::Continue);
        assert_eq!(String::from_utf8(out).unwrap(), "red\tok\nx");
    }

    #[test]
    fn json_handler_preserves_raw_control_sequences() {
        let session_id = Uuid::new_v4();
        let mut out = Vec::new();
        let mut error_seen = false;
        let action = handle_run_event(
            session_id,
            &proto::Event::AssistantTextDelta {
                session_id,
                agent: "Build".into(),
                delta: "\u{1b}[31mred\u{1b}[0m".into(),
            },
            OutputFormat::Json,
            false,
            true,
            &mut out,
            &mut error_seen,
        );

        assert_eq!(action, RunEventAction::Continue);
        let line: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(line["delta"], "\u{1b}[31mred\u{1b}[0m");
    }
}
