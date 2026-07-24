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
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::approval::store::GrantKind;
use crate::cli::{OutputFormat, RunArgs};
use crate::daemon::client::{LifecycleMode, probe_or_spawn};
use crate::daemon::ephemeral_guard::{EphemeralDaemonGuard, spawn_signal_shutdown};
use crate::daemon::proto::{self, Request, Response};

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
struct RunWorkspaceTrustError(String);

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
struct RunUsageError(String);

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
struct RunTurnFailure(String);

#[derive(Debug, Clone, Default)]
pub(crate) struct RunPumpOptions<'a> {
    pub(crate) verbose_json: bool,
    pub(crate) follow: bool,
    pub(crate) session: Option<Uuid>,
    pub(crate) agent_override: Option<&'a str>,
    pub(crate) model_override: Option<&'a str>,
    pub(crate) project_root: Option<&'a Path>,
    pub(crate) approve: &'a [GrantKind],
    pub(crate) image_data: &'a [Vec<u8>],
}

pub async fn run(args: RunArgs, no_sandbox: bool, project_alias: Option<&Path>) -> Result<()> {
    let format = args.output_format();
    let json_mode = matches!(format, OutputFormat::Json);
    if let Err(error) = validate_ephemeral_continuation(&args) {
        exit_run_error(format, 2, "invalid_arguments", &error.to_string());
    }
    let cwd = match resolve_run_cwd(args.cwd.as_deref(), project_alias) {
        Ok(cwd) => cwd,
        Err(error) => exit_run_error(format, 2, "invalid_arguments", &error.to_string()),
    };
    let prompt = match build_prompt(&args, &cwd) {
        Ok(prompt) => prompt,
        Err(error) => exit_run_error(format, 2, "invalid_arguments", &error.to_string()),
    };
    if let Err(error) = validate_prompt(&prompt) {
        exit_run_error(format, 2, "empty_prompt", &error.to_string());
    }
    let db = match crate::db::Db::open_default().context("opening cockpit DB") {
        Ok(db) => db,
        Err(error) => exit_run_error(format, 2, "configuration", &format!("{error:#}")),
    };
    if let Err(error) =
        crate::config::trust::enforce_noninteractive_workspace_trust(&db, &cwd).await
    {
        exit_run_error(format, 3, "workspace_trust", &error.to_string());
    }

    let requested_session = match resolve_requested_session(&args, &db, &cwd).await {
        Ok(session) => session,
        Err(error) => exit_run_error(format, 2, "invalid_arguments", &error.to_string()),
    };
    let image_files = match resolve_attachment_paths(&cwd, &args.file) {
        Ok(paths) => paths,
        Err(error) => exit_run_error(format, 2, "invalid_arguments", &error.to_string()),
    };
    let image_data = match load_and_validate_images(&image_files) {
        Ok(images) => images,
        Err(error) => exit_run_error(format, 2, "invalid_attachment", &format!("{error:#}")),
    };

    let mode = if args.ephemeral {
        LifecycleMode::AlwaysEphemeral
    } else {
        LifecycleMode::AttachOrEphemeral
    };

    let daemon = match probe_or_spawn(mode).await {
        Ok(daemon) => daemon,
        Err(error) => exit_run_error(format, 4, "daemon_connection", &format!("{error:#}")),
    };
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

    let result = run_turn(
        &client,
        &args,
        prompt,
        no_sandbox,
        &cwd,
        requested_session,
        &image_data,
    )
    .await;

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
        Err(error) if error.downcast_ref::<RunWorkspaceTrustError>().is_some() => {
            let message = error.to_string();
            if json_mode {
                emit_json(&json!({
                    "event": "error",
                    "code": "workspace_trust",
                    "message": message
                }))?;
                emit_run_complete(false, 3)?;
            } else {
                eprintln!("{message}");
            }
            3
        }
        Err(error) if error.downcast_ref::<RunUsageError>().is_some() => {
            let message = error.to_string();
            if json_mode {
                emit_json(&json!({
                    "event": "error",
                    "code": "invalid_arguments",
                    "message": message
                }))?;
                emit_run_complete(false, 2)?;
            } else {
                eprintln!("{message}");
            }
            2
        }
        Err(error) if error.downcast_ref::<RunTurnFailure>().is_some() => {
            let message = error.to_string();
            if json_mode {
                emit_json(&json!({
                    "event": "error",
                    "code": "turn_failed",
                    "message": message
                }))?;
                emit_run_complete(false, 1)?;
            } else {
                eprintln!("{message}");
            }
            1
        }
        Err(error) if json_mode => {
            emit_json(&json!({
                "event": "error",
                "code": "command_failed",
                "message": error.to_string()
            }))?;
            emit_run_complete(false, 4)?;
            4
        }
        Err(error) => {
            eprintln!("run failed: {error:#}");
            4
        }
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
    project_root: &Path,
    requested_session: Option<Uuid>,
    image_data: &[Vec<u8>],
) -> Result<i32> {
    attach_send_pump(
        client,
        prompt,
        no_sandbox,
        args.output_format(),
        RunPumpOptions {
            verbose_json: args.verbose,
            follow: args.follow,
            session: requested_session,
            agent_override: args.agent.as_deref(),
            model_override: args.model.as_deref(),
            project_root: Some(project_root),
            approve: &args.approve,
            image_data,
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
    let cwd = match options.project_root {
        Some(root) => root.to_path_buf(),
        None => std::env::current_dir().context("resolving cwd")?,
    };
    let project_root = cwd.to_string_lossy().into_owned();
    let requested_session = options.session;
    let env_snapshot = crate::env_snapshot::EnvSnapshot::from_process(
        crate::env_snapshot::EnvSnapshotSource::ExplicitCli,
    );

    // Attach a fresh session. `no_sandbox` (sandboxing part 2) makes this
    // noninteractive session start unsandboxed unless the daemon was
    // launched `--no-sandbox` (which wins). `model_override` (`--model`, the
    // plan executor passes the plan's pinned model) overrides every spawned
    // agent's frontmatter model for this session's run.
    let attached = match client
        .request(Request::Attach {
            session_id: requested_session,
            since_seq: None,
            project_root: Some(project_root),
            no_sandbox,
            // A streamed run has no UI to answer an interrupt — a
            // non-interactive attach. The loop guard treats the session as
            // headless and auto-rejects a back-to-back repeat (with the
            // guidance error) rather than blocking.
            interactive: false,
            model_override: options.model_override.map(str::to_string),
            client_protocol_version: client.negotiated().version,
            env_snapshot: Some(env_snapshot.to_wire()),
            env_policy: crate::env_snapshot::EnvDriftPolicy::Daemon,
        })
        .await?
    {
        Ok(response) => response,
        Err(error) if error.code == proto::ErrorCode::WorkspaceTrust => {
            return Err(RunWorkspaceTrustError(error.message).into());
        }
        Err(error)
            if matches!(
                error.code,
                proto::ErrorCode::BadRequest
                    | proto::ErrorCode::ProtocolVersion
                    | proto::ErrorCode::RootMissing
                    | proto::ErrorCode::PathOutsideRoot
            ) =>
        {
            return Err(RunUsageError(error.message).into());
        }
        Err(error)
            if matches!(
                error.code,
                proto::ErrorCode::UnknownSession
                    | proto::ErrorCode::Authorization
                    | proto::ErrorCode::ReadOnly
            ) =>
        {
            return Err(RunTurnFailure(error.message).into());
        }
        Err(error) => anyhow::bail!("daemon error: {error}"),
    };
    let (session_id, repair_required) = match attached {
        Response::Attached {
            session_id,
            repair_required,
            ..
        } => (session_id, repair_required.map(|repair| *repair)),
        other => anyhow::bail!("unexpected attach response: {other:?}"),
    };
    let mut stdout = std::io::stdout().lock();
    let mut stderr = std::io::stderr().lock();
    write_session_attached(
        format,
        session_id,
        requested_session.is_some(),
        &mut stdout,
        &mut stderr,
    )?;
    drop(stdout);
    drop(stderr);
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
        return Err(RunTurnFailure(format!(
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
        ))
        .into());
    }
    if let Some(agent) = options.agent_override {
        match client
            .request(Request::SetAgent {
                name: agent.to_string(),
            })
            .await
            .with_context(|| format!("switching run session to agent `{agent}`"))?
        {
            Ok(_) => {}
            Err(error) if error.code == proto::ErrorCode::BadRequest => {
                return Err(RunUsageError(error.message).into());
            }
            Err(error) => anyhow::bail!("daemon error: {error}"),
        }
    }

    let was_processing = is_processing(client, session_id).await?;
    let submitted_message = !prompt.trim().is_empty();
    if submitted_message {
        let image_refs = load_and_upload_images(client, options.image_data).await?;
        // Send the user message.
        client
            .request_ok(Request::SendUserMessage {
                text: prompt,
                display_text: None,
                tag_expansions: Vec::new(),
                image_refs,
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
            emit_run_complete(true, 0)?;
        }
        return Ok(0);
    }

    // Pump events until the turn completes (or the session ends).
    pump_events(
        client,
        session_id,
        format,
        options.verbose_json,
        options.approve,
        submitted_message,
    )
    .await
}

fn resolve_run_cwd(cwd: Option<&Path>, project_alias: Option<&Path>) -> Result<PathBuf> {
    if cwd.is_some() && project_alias.is_some() {
        anyhow::bail!("--cwd and --project are aliases; pass only one");
    }
    let selected = match cwd.or(project_alias) {
        Some(path) => path.to_path_buf(),
        None => std::env::current_dir().context("resolving cwd")?,
    };
    if !selected.exists() {
        anyhow::bail!("run cwd does not exist: {}", selected.display());
    }
    if !selected.is_dir() {
        anyhow::bail!("run cwd is not a directory: {}", selected.display());
    }
    selected
        .canonicalize()
        .with_context(|| format!("canonicalizing run cwd {}", selected.display()))
}

async fn resolve_requested_session(
    args: &RunArgs,
    db: &crate::db::Db,
    root: &Path,
) -> Result<Option<Uuid>> {
    if let Some(session) = &args.session {
        let session_id = Uuid::parse_str(session).context("parsing --session")?;
        let stored = db
            .get_session(session_id)
            .await
            .context("looking up --session")?
            .ok_or_else(|| anyhow::anyhow!("unknown session {session_id}"))?;
        let stored_root = Path::new(&stored.project_root)
            .canonicalize()
            .with_context(|| format!("canonicalizing session root {}", stored.project_root))?;
        if stored_root != root {
            anyhow::bail!(
                "session {session_id} belongs to {}; --cwd/--project selected {}",
                stored_root.display(),
                root.display()
            );
        }
        return Ok(Some(session_id));
    }
    if !args.continue_session {
        return Ok(None);
    }

    db.most_recent_session_for_root_by_message(&root.to_string_lossy())
        .await
        .context("selecting latest session for --continue")?
        .map(|session| Some(session.session_id))
        .ok_or_else(|| anyhow::anyhow!("no previous session for workspace {}", root.display()))
}

fn resolve_attachment_paths(root: &Path, files: &[PathBuf]) -> Result<Vec<PathBuf>> {
    files
        .iter()
        .map(|path| {
            let resolved = if path.is_absolute() {
                path.clone()
            } else {
                root.join(path)
            };
            if !resolved.is_file() {
                anyhow::bail!("attachment is not a file: {}", resolved.display());
            }
            resolved
                .canonicalize()
                .with_context(|| format!("canonicalizing attachment {}", resolved.display()))
        })
        .collect()
}

fn load_and_validate_images(paths: &[PathBuf]) -> Result<Vec<Vec<u8>>> {
    if paths.len() > proto::MAX_IMAGES_PER_USER_MESSAGE {
        return Err(RunUsageError(format!(
            "too many images: {} exceeds {} image limit",
            paths.len(),
            proto::MAX_IMAGES_PER_USER_MESSAGE
        ))
        .into());
    }
    let images: Vec<Vec<u8>> = paths
        .iter()
        .map(|path| {
            let bytes = std::fs::read(path)
                .with_context(|| format!("reading attachment {}", path.display()))?;
            crate::daemon::server::validate_png_attachment_blocking(bytes)
                .map_err(|error| anyhow::anyhow!(error.message))
        })
        .collect::<Result<_>>()?;
    if let Some(image) = images
        .iter()
        .find(|image| image.len() > proto::MAX_SINGLE_IMAGE_BYTES)
    {
        return Err(RunUsageError(format!(
            "image is too large: {} bytes exceeds {} byte limit",
            image.len(),
            proto::MAX_SINGLE_IMAGE_BYTES
        ))
        .into());
    }
    let total: usize = images.iter().map(Vec::len).sum();
    if total > proto::MAX_TOTAL_IMAGE_BYTES {
        return Err(RunUsageError(format!(
            "total image data is too large: {total} bytes exceeds {} byte limit",
            proto::MAX_TOTAL_IMAGE_BYTES
        ))
        .into());
    }
    Ok(images)
}

async fn load_and_upload_images(
    client: &crate::daemon::client::DaemonClient,
    images: &[Vec<u8>],
) -> Result<Vec<proto::ImageAttachmentRef>> {
    match crate::daemon::image_upload::upload_submission_images(client, images).await {
        Ok(refs) => Ok(refs),
        Err(error) => Err(map_image_upload_error(error)),
    }
}

fn map_image_upload_error(error: crate::daemon::image_upload::ImageUploadError) -> anyhow::Error {
    match error {
        crate::daemon::image_upload::ImageUploadError::Usage(message) => {
            RunUsageError(message).into()
        }
        error => error.into(),
    }
}

fn exit_run_error(format: OutputFormat, exit_code: i32, code: &str, message: &str) -> ! {
    if matches!(format, OutputFormat::Json) {
        let mut stdout = std::io::stdout().lock();
        let _ = writeln!(
            stdout,
            "{}",
            json!({ "event": "error", "code": code, "message": message })
        );
        let _ = writeln!(
            stdout,
            "{}",
            json!({ "event": "run_complete", "ok": false, "exit_code": exit_code })
        );
        let _ = stdout.flush();
    } else {
        eprintln!("{message}");
    }
    std::process::exit(exit_code)
}

fn emit_run_complete(ok: bool, exit_code: i32) -> Result<()> {
    emit_json(&json!({
        "event": "run_complete",
        "ok": ok,
        "exit_code": exit_code
    }))
}

fn write_session_attached(
    format: OutputFormat,
    session_id: Uuid,
    resumed: bool,
    stdout: &mut impl Write,
    stderr: &mut impl Write,
) -> Result<()> {
    if matches!(format, OutputFormat::Json) {
        writeln!(
            stdout,
            "{}",
            json!({
                "event": "session_attached",
                "session_id": session_id,
                "resumed": resumed
            })
        )?;
    } else {
        writeln!(stderr, "session: {session_id}")?;
    }
    Ok(())
}

fn build_prompt(args: &RunArgs, root: &Path) -> Result<String> {
    build_prompt_from_reader(args, root, &mut std::io::stdin().lock())
}

fn build_prompt_from_reader(args: &RunArgs, root: &Path, stdin: &mut impl Read) -> Result<String> {
    let has_message = !args.message.is_empty();
    if has_message && args.prompt_file.is_some() {
        anyhow::bail!("ambiguous prompt sources: pass either message args or --prompt-file");
    }

    if let Some(path) = &args.prompt_file {
        let path = if path.is_absolute() {
            path.clone()
        } else {
            root.join(path)
        };
        return std::fs::read_to_string(&path)
            .with_context(|| format!("reading prompt file {}", path.display()));
    }

    if has_message {
        return Ok(args.message.join(" "));
    }

    let mut stdin_buf = String::new();
    stdin
        .read_to_string(&mut stdin_buf)
        .context("reading stdin")?;
    Ok(stdin_buf.trim_end().to_string())
}

fn validate_prompt(prompt: &str) -> Result<()> {
    if prompt.trim().is_empty() {
        anyhow::bail!("no prompt: pass a message, --prompt-file, or pipe stdin");
    }
    Ok(())
}

fn validate_ephemeral_continuation(args: &RunArgs) -> Result<()> {
    if args.ephemeral && (args.continue_session || args.session.is_some()) {
        anyhow::bail!(
            "--ephemeral sessions cannot be continued; drop --ephemeral or start a new session"
        );
    }
    Ok(())
}

pub(crate) async fn pump_events(
    client: &crate::daemon::client::DaemonClient,
    session_id: Uuid,
    format: OutputFormat,
    verbose_json: bool,
    approve: &[GrantKind],
    expect_submitted_message: bool,
) -> Result<i32> {
    let mut stdout = std::io::stdout().lock();
    let mut stderr = std::io::stderr().lock();
    let mut outcome = RunOutcome::new(expect_submitted_message);

    while let Some(event) = client.next_event().await {
        // Filter to this session's events.
        if event_session(&event) != Some(session_id) {
            continue;
        }

        let action = handle_run_event(
            session_id,
            &event,
            format,
            verbose_json,
            stdout.is_terminal(),
            &mut stdout,
            &mut stderr,
            &mut outcome,
        );

        if let proto::Event::InterruptRaised {
            interrupt_id,
            question,
            questions,
            ..
        } = &event
        {
            let resolution = resolve_run_interrupt(question.as_ref(), questions.as_ref(), approve);
            client
                .request_ok(Request::ResolveInterrupt {
                    interrupt_id: *interrupt_id,
                    response: resolution.response,
                })
                .await
                .context("auto-resolving noninteractive run approval")?;
            if matches!(format, OutputFormat::Json) {
                writeln!(
                    stdout,
                    "{}",
                    json!({
                        "event": "approval_resolved",
                        "session_id": session_id,
                        "interrupt_id": interrupt_id,
                        "outcome": if resolution.approved { "approved_once" } else { "auto_denied" },
                        "class": resolution.class.map(GrantKind::as_str),
                    })
                )?;
            } else if resolution.approved {
                writeln!(
                    stderr,
                    "[noninteractive run: approved {} for this run only]",
                    resolution
                        .class
                        .map(GrantKind::as_str)
                        .unwrap_or("decision")
                )?;
            } else {
                writeln!(
                    stderr,
                    "[noninteractive run: approval auto-denied; re-run with --approve <class> or use the TUI]"
                )?;
            }
        }

        match action {
            RunEventAction::Continue => {}
            RunEventAction::Break => {
                if outcome.ready_to_finish() {
                    break;
                }
            }
            RunEventAction::Return(code) => {
                if matches!(format, OutputFormat::Json) {
                    writeln!(
                        stdout,
                        "{}",
                        json!({ "event": "run_complete", "ok": false, "exit_code": code })
                    )?;
                }
                return Ok(code);
            }
        }
    }

    if matches!(format, OutputFormat::Default) && outcome.streamed_text {
        let _ = stdout.write_all(b"\n");
    }
    let _ = stdout.flush();
    let disconnected = !outcome.ready_to_finish();
    let code = terminal_exit_code(&outcome);
    if disconnected {
        if matches!(format, OutputFormat::Json) {
            writeln!(
                stdout,
                "{}",
                json!({
                    "event": "error",
                    "code": "daemon_connection",
                    "message": "daemon connection closed before run completed"
                })
            )?;
        } else {
            writeln!(stderr, "[daemon connection closed before run completed]")?;
        }
    }
    if matches!(format, OutputFormat::Default) && code == 1 && outcome.is_empty_turn() {
        writeln!(
            stderr,
            "[run failed: turn completed without inference, assistant output, or tool progress]"
        )?;
    }
    if matches!(format, OutputFormat::Json) {
        writeln!(
            stdout,
            "{}",
            json!({ "event": "run_complete", "ok": code == 0, "exit_code": code })
        )?;
        stdout.flush()?;
    }
    Ok(code)
}

#[derive(Debug, Default)]
struct RunOutcome {
    expect_submitted_message: bool,
    message_recorded: bool,
    inference_dispatched: bool,
    progress: bool,
    streamed_text: bool,
    terminal_failure: bool,
    terminal_seen: bool,
}

impl RunOutcome {
    fn new(expect_submitted_message: bool) -> Self {
        Self {
            expect_submitted_message,
            ..Self::default()
        }
    }

    fn observe(&mut self, event: &proto::Event) {
        match event {
            proto::Event::UserMessageRecorded { .. } => {
                self.message_recorded = true;
                // Discard an idle snapshot observed during attach. Only a
                // terminal event after this submitted message can finish it.
                self.terminal_seen = false;
            }
            proto::Event::ThinkingStarted { .. } => {
                self.inference_dispatched = true;
                self.terminal_failure = false;
            }
            proto::Event::AssistantTextDelta { .. }
            | proto::Event::AssistantText { .. }
            | proto::Event::ReasoningDelta { .. }
            | proto::Event::ToolStart { .. }
            | proto::Event::ToolEnd { .. } => self.progress = true,
            proto::Event::InferenceFailed { .. } | proto::Event::ToolError { .. } => {
                self.terminal_failure = true;
            }
            proto::Event::AgentIdle { .. } => {
                self.terminal_seen = true;
            }
            proto::Event::SessionEnded { .. } => {
                self.terminal_seen = true;
                self.terminal_failure = true;
            }
            _ => {}
        }
    }

    fn ready_to_finish(&self) -> bool {
        self.terminal_seen && (!self.expect_submitted_message || self.message_recorded)
    }

    fn is_empty_turn(&self) -> bool {
        self.ready_to_finish() && !self.inference_dispatched && !self.progress
    }

    fn exit_code(&self) -> i32 {
        if !self.ready_to_finish() || self.terminal_failure || self.is_empty_turn() {
            1
        } else {
            0
        }
    }
}

fn terminal_exit_code(outcome: &RunOutcome) -> i32 {
    if outcome.ready_to_finish() {
        outcome.exit_code()
    } else {
        4
    }
}

struct InterruptResolution {
    response: proto::ResolveResponse,
    approved: bool,
    class: Option<GrantKind>,
}

fn resolve_run_interrupt(
    legacy: Option<&proto::InterruptQuestion>,
    set: Option<&proto::InterruptQuestionSet>,
    approved_classes: &[GrantKind],
) -> InterruptResolution {
    let questions = set
        .map(|set| set.questions.as_slice())
        .or_else(|| legacy.map(std::slice::from_ref))
        .unwrap_or_default();
    let mut approved = !questions.is_empty();
    let mut class = None;
    let responses = questions
        .iter()
        .map(|question| {
            let question_class = interrupt_approval_class(question);
            class = class.or(question_class);
            let selected = question_class
                .filter(|class| approved_classes.contains(class))
                .and_then(|_| safe_once_option(question));
            if let Some(selected_id) = selected {
                proto::ResolveResponse::Single { selected_id }
            } else {
                approved = false;
                noninteractive_denial_response()
            }
        })
        .collect::<Vec<_>>();
    let response = match responses.as_slice() {
        [] => noninteractive_denial_response(),
        [one] => one.clone(),
        _ => proto::ResolveResponse::Batch { responses },
    };
    InterruptResolution {
        response,
        approved,
        class,
    }
}

fn noninteractive_denial_response() -> proto::ResolveResponse {
    proto::ResolveResponse::Freetext {
        text: crate::approval::NONINTERACTIVE_RUN_DENIAL.to_string(),
    }
}

fn interrupt_approval_class(question: &proto::InterruptQuestion) -> Option<GrantKind> {
    match question {
        proto::InterruptQuestion::Single {
            permission: true,
            approval_class,
            ..
        } => *approval_class,
        _ => None,
    }
}

fn safe_once_option(question: &proto::InterruptQuestion) -> Option<String> {
    let proto::InterruptQuestion::Single { options, .. } = question else {
        return None;
    };
    [
        crate::approval::ID_APPROVE_ONCE,
        crate::approval::ID_APPROVE,
        crate::approval::ID_ESCALATE_RUN_UNCONFINED_ONCE,
        crate::approval::ID_GITIGNORE_FILE,
    ]
    .into_iter()
    .find(|id| options.iter().any(|option| option.id == *id))
    .map(str::to_string)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RunEventAction {
    Continue,
    Break,
    Return(i32),
}

#[allow(clippy::too_many_arguments)] // Keeps renderer sinks injectable in focused tests.
fn handle_run_event(
    session_id: Uuid,
    event: &proto::Event,
    format: OutputFormat,
    verbose_json: bool,
    sanitize_tty: bool,
    stdout: &mut impl Write,
    stderr: &mut impl Write,
    outcome: &mut RunOutcome,
) -> RunEventAction {
    outcome.observe(event);
    match format {
        OutputFormat::Default => match event {
            proto::Event::AssistantTextDelta { delta, .. } => {
                if !delta.is_empty() {
                    outcome.streamed_text = true;
                }
                if sanitize_tty {
                    let _ = stdout.write_all(sanitize_terminal_text(delta).as_bytes());
                } else {
                    let _ = stdout.write_all(delta.as_bytes());
                }
                let _ = stdout.flush();
            }
            proto::Event::ToolError { tool, error, .. } => {
                let _ = writeln!(stderr, "[error: {tool}: {error}]");
            }
            proto::Event::InferenceFailed {
                provider,
                model,
                error_class,
                detail,
                ..
            } => {
                let _ = writeln!(
                    stderr,
                    "[inference failed: {provider}/{model} {error_class}: {detail}]"
                );
            }
            proto::Event::SessionPersistFailed { error, .. } => {
                let _ = writeln!(stderr, "[session persist failed: {error}]");
                return RunEventAction::Return(1);
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
                let _ = writeln!(
                    stderr,
                    "[reconnecting: {provider}/{model} unreachable at {url} (attempt {attempt})]"
                );
            }
            proto::Event::CommandCapabilityUnavailable { text, .. } => {
                let _ = writeln!(stderr, "[notice: {text}]");
            }
            proto::Event::SessionEnded { reason, .. } => {
                let _ = writeln!(stderr, "[session ended: {reason}]");
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
    if let proto::Event::SessionPersistFailed { .. } = event {
        return RunEventAction::Return(1);
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
        proto::Event::InterruptRaised {
            interrupt_id,
            agent,
            description,
            question,
            questions,
            pending_count,
            reason,
            ..
        } => json!({
            "event": "approval_request",
            "session_id": session_id,
            "interrupt_id": interrupt_id,
            "agent": agent,
            "description": description,
            "question": question,
            "questions": questions,
            "pending_count": pending_count,
            "reason": reason,
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
        proto::Event::CommandCapabilityUnavailable {
            text, fix_command, ..
        } => json!({
            "event": "command_capability_unavailable",
            "session_id": session_id,
            "text": text,
            "fix_command": fix_command,
        }),
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
        ConfigSnapshot { snapshot } => snapshot.session_id,
        ThinkingStarted { session_id, .. }
        | QueueUpdated { session_id, .. }
        | ForegroundInputTarget { session_id, .. }
        | ActiveModelState { session_id, .. }
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
        | InferenceSucceeded { session_id, .. }
        | InferenceWarning { session_id, .. }
        | BackupUsed { session_id, .. }
        | SubagentSpawned { session_id, .. }
        | SubagentRouting { session_id, .. }
        | SubagentReport { session_id, .. }
        | NestedTurn { session_id, .. }
        | Usage { session_id, .. }
        | InterruptRaised { session_id, .. }
        | InterruptResolved { session_id, .. }
        | HistoryReplay { session_id, .. }
        | InterruptQueueChanged { session_id, .. }
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
        | SandboxEscalationState { session_id, .. }
        | SandboxUnavailable { session_id, .. }
        | CommandCapabilityUnavailable { session_id, .. }
        | RedactionState { session_id, .. }
        | PreflightState { session_id, .. }
        | TrustedOnlyState { session_id, .. }
        | ApprovalModeState { session_id, .. }
        | DelegationRecursionState { session_id, .. }
        | TandemState { session_id, .. }
        | GitignoreAllow { session_id, .. }
        | PausedWorkAvailable { session_id, .. }
        | WaitingForLock { session_id, .. } => *session_id,
        EventStreamLagged {
            session_id: Some(session_id),
            ..
        } => *session_id,
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
        | EventStreamLagged {
            session_id: None, ..
        }
        | EnvDriftWarning { .. }
        | Unknown => {
            return None;
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run_args() -> RunArgs {
        RunArgs {
            message: Vec::new(),
            prompt_file: None,
            agent: None,
            agent_file: None,
            model: None,
            continue_session: false,
            session: None,
            cwd: None,
            approve: Vec::new(),
            fork: false,
            format: OutputFormat::Default,
            json: false,
            verbose: false,
            follow: false,
            file: Vec::new(),
            thinking: false,
            ephemeral: false,
        }
    }

    fn approval_question(class: GrantKind) -> proto::InterruptQuestion {
        proto::InterruptQuestion::Single {
            prompt: "Allow this operation?".into(),
            options: vec![proto::InterruptOption {
                id: crate::approval::ID_APPROVE_ONCE.into(),
                label: "Allow once".into(),
                description: None,
                secondary: false,
            }],
            allow_freetext: false,
            command_detail: None,
            permission: true,
            approval_class: Some(class),
            sandbox_escalation: None,
        }
    }

    #[test]
    fn args_win_over_nontty_stdin() {
        let mut args = run_args();
        args.message = vec!["say".into(), "hi".into()];

        let mut empty = std::io::Cursor::new(Vec::<u8>::new());
        assert_eq!(
            build_prompt_from_reader(&args, Path::new("."), &mut empty).unwrap(),
            "say hi"
        );

        let mut nonempty = std::io::Cursor::new(b"ignored stdin".to_vec());
        assert_eq!(
            build_prompt_from_reader(&args, Path::new("."), &mut nonempty).unwrap(),
            "say hi"
        );
        assert_eq!(
            nonempty.position(),
            0,
            "argument prompts leave stdin unread"
        );
    }

    #[test]
    fn no_prompt_sources_errors() {
        let args = run_args();
        let mut stdin = std::io::Cursor::new(Vec::<u8>::new());
        let prompt = build_prompt_from_reader(&args, Path::new("."), &mut stdin).unwrap();
        let error = validate_prompt(&prompt).unwrap_err();
        assert_eq!(
            error.to_string(),
            "no prompt: pass a message, --prompt-file, or pipe stdin"
        );

        assert!(validate_prompt("").is_err());
    }

    #[test]
    fn ephemeral_rejects_continuation() {
        let mut args = run_args();
        args.ephemeral = true;
        args.continue_session = true;
        assert_eq!(
            validate_ephemeral_continuation(&args)
                .unwrap_err()
                .to_string(),
            "--ephemeral sessions cannot be continued; drop --ephemeral or start a new session"
        );

        args.continue_session = false;
        args.session = Some(Uuid::new_v4().to_string());
        assert!(validate_ephemeral_continuation(&args).is_err());
    }

    #[test]
    fn attachment_limits_and_daemon_bad_requests_are_usage_errors() {
        let paths = (0..=proto::MAX_IMAGES_PER_USER_MESSAGE)
            .map(|index| PathBuf::from(format!("unread-image-{index}.png")))
            .collect::<Vec<_>>();
        let error = load_and_validate_images(&paths).unwrap_err();
        assert!(error.downcast_ref::<RunUsageError>().is_some());
        assert!(error.to_string().contains("too many images"));

        let error = map_image_upload_error(crate::daemon::image_upload::ImageUploadError::Usage(
            "configured upload limit rejected the image".into(),
        ));
        assert!(error.downcast_ref::<RunUsageError>().is_some());

        let error = map_image_upload_error(
            crate::daemon::image_upload::ImageUploadError::Transport("socket closed".into()),
        );
        assert!(error.downcast_ref::<RunUsageError>().is_none());
    }

    #[test]
    fn empty_turn_is_failure() {
        let session_id = Uuid::new_v4();
        let mut outcome = RunOutcome::new(true);
        outcome.observe(&proto::Event::UserMessageRecorded {
            session_id,
            seq: 1,
            preflight_cleaned: None,
        });
        outcome.observe(&proto::Event::AgentIdle {
            session_id,
            turn_id: None,
            reason: crate::engine::IdleReason::Completed,
        });
        assert!(outcome.is_empty_turn());
        assert_eq!(outcome.exit_code(), 1);
    }

    #[test]
    fn daemon_disconnect_is_exit_four() {
        let session_id = Uuid::new_v4();
        let mut outcome = RunOutcome::new(true);
        outcome.observe(&proto::Event::UserMessageRecorded {
            session_id,
            seq: 1,
            preflight_cleaned: None,
        });
        outcome.observe(&proto::Event::ThinkingStarted {
            session_id,
            agent: "Build".into(),
            turn_id: None,
        });
        assert_eq!(terminal_exit_code(&outcome), 4);
    }

    #[test]
    fn ephemeral_flag_combinations_dispatch() {
        let session_id = Uuid::new_v4();
        let mut outcome = RunOutcome::new(true);
        // An attach snapshot may contain the daemon's pre-submission idle
        // state. It must not finish the run before the queued message lands.
        outcome.observe(&proto::Event::AgentIdle {
            session_id,
            turn_id: None,
            reason: crate::engine::IdleReason::Completed,
        });
        assert!(!outcome.ready_to_finish());
        outcome.observe(&proto::Event::UserMessageRecorded {
            session_id,
            seq: 1,
            preflight_cleaned: None,
        });
        outcome.observe(&proto::Event::ThinkingStarted {
            session_id,
            agent: "Build".into(),
            turn_id: None,
        });
        assert!(outcome.message_recorded);
        assert!(outcome.inference_dispatched);
        assert!(!outcome.ready_to_finish());
        outcome.observe(&proto::Event::AgentIdle {
            session_id,
            turn_id: None,
            reason: crate::engine::IdleReason::Completed,
        });
        assert_eq!(outcome.exit_code(), 0);
    }

    #[test]
    fn run_approval_auto_denied() {
        let question = approval_question(GrantKind::Command);
        let resolution = resolve_run_interrupt(Some(&question), None, &[]);
        assert!(!resolution.approved);
        assert_eq!(resolution.class, Some(GrantKind::Command));
        assert!(matches!(
            resolution.response,
            proto::ResolveResponse::Freetext { ref text }
                if text == crate::approval::NONINTERACTIVE_RUN_DENIAL
        ));
    }

    #[test]
    fn run_approve_class_grants() {
        let question = approval_question(GrantKind::Command);
        let resolution = resolve_run_interrupt(Some(&question), None, &[GrantKind::Command]);
        assert!(resolution.approved);
        assert_eq!(resolution.class, Some(GrantKind::Command));
        assert!(matches!(
            resolution.response,
            proto::ResolveResponse::Single { ref selected_id }
                if selected_id == crate::approval::ID_APPROVE_ONCE
        ));

        let mismatch = resolve_run_interrupt(Some(&question), None, &[GrantKind::Path]);
        assert!(!mismatch.approved);
    }

    #[test]
    fn run_approve_class_grants_harness() {
        let question = approval_question(GrantKind::Harness);
        let resolution = resolve_run_interrupt(Some(&question), None, &[GrantKind::Harness]);
        assert!(resolution.approved);
        assert_eq!(resolution.class, Some(GrantKind::Harness));
        assert!(matches!(
            resolution.response,
            proto::ResolveResponse::Single { ref selected_id }
                if selected_id == crate::approval::ID_APPROVE_ONCE
        ));
    }

    #[test]
    fn run_prints_session_id() {
        let session_id = Uuid::new_v4();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        write_session_attached(
            OutputFormat::Default,
            session_id,
            false,
            &mut stdout,
            &mut stderr,
        )
        .unwrap();
        assert!(stdout.is_empty());
        assert_eq!(
            String::from_utf8(stderr).unwrap(),
            format!("session: {session_id}\n")
        );

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        write_session_attached(
            OutputFormat::Json,
            session_id,
            true,
            &mut stdout,
            &mut stderr,
        )
        .unwrap();
        assert!(stderr.is_empty());
        let value: Value = serde_json::from_slice(&stdout).unwrap();
        assert_eq!(value["event"], "session_attached");
        assert_eq!(value["session_id"], session_id.to_string());
        assert_eq!(value["resumed"], true);
    }

    #[test]
    fn cwd_flag_sets_workspace_root() {
        let root = tempfile::tempdir().unwrap();
        let nested = root.path().join("nested");
        std::fs::create_dir(&nested).unwrap();
        std::fs::write(nested.join("image.png"), b"png").unwrap();
        std::fs::write(nested.join("prompt.txt"), "from target cwd").unwrap();

        let canonical = resolve_run_cwd(Some(&nested), None).unwrap();
        assert_eq!(canonical, nested.canonicalize().unwrap());
        assert_eq!(
            resolve_attachment_paths(&canonical, &[PathBuf::from("image.png")]).unwrap(),
            vec![nested.join("image.png").canonicalize().unwrap()]
        );
        let mut args = run_args();
        args.prompt_file = Some(PathBuf::from("prompt.txt"));
        let mut stdin = std::io::Cursor::new(b"ignored".to_vec());
        assert_eq!(
            build_prompt_from_reader(&args, &canonical, &mut stdin).unwrap(),
            "from target cwd"
        );
        assert!(resolve_run_cwd(Some(root.path()), Some(root.path())).is_err());
    }

    #[test]
    fn json_agent_idle_becomes_turn_complete_with_session_id() {
        let session_id = Uuid::new_v4();
        let value = normalized_event(
            session_id,
            &proto::Event::AgentIdle {
                session_id,
                turn_id: None,
                reason: crate::engine::IdleReason::Completed,
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
        let mut stderr = Vec::new();
        let mut outcome = RunOutcome::new(false);
        let action = handle_run_event(
            session_id,
            &proto::Event::ToolError {
                session_id,
                agent: "Build".into(),
                call_id: "call-1".into(),
                tool: "bash".into(),
                error: "boom".into(),
                kind: crate::engine::tool::ToolFailKind::Execution,
                seq: None,
            },
            OutputFormat::Default,
            false,
            false,
            &mut out,
            &mut stderr,
            &mut outcome,
        );

        assert_eq!(action, RunEventAction::Continue);
        assert!(outcome.terminal_failure);
        let text = String::from_utf8(stderr).unwrap();
        assert!(text.contains("[error: bash: boom]"));
    }

    #[test]
    fn inference_failure_is_loud() {
        let session_id = Uuid::new_v4();
        let mut out = Vec::new();
        let mut stderr = Vec::new();
        let mut outcome = RunOutcome::new(false);
        let action = handle_run_event(
            session_id,
            &proto::Event::InferenceFailed {
                session_id,
                agent: "Build".into(),
                provider: "openai".into(),
                model: "gpt-5".into(),
                error_class: proto::InferenceErrorClass::Other("auth".into()),
                detail: "credentials rejected".into(),
                auth_failure: None,
            },
            OutputFormat::Default,
            false,
            false,
            &mut out,
            &mut stderr,
            &mut outcome,
        );

        assert_eq!(action, RunEventAction::Continue);
        assert!(outcome.terminal_failure);
        let text = String::from_utf8(stderr).unwrap();
        assert!(text.contains("[inference failed: openai/gpt-5 auth: credentials rejected]"));
    }

    #[test]
    fn json_handler_emits_inference_failed_and_sets_error() {
        let session_id = Uuid::new_v4();
        let mut out = Vec::new();
        let mut stderr = Vec::new();
        let mut outcome = RunOutcome::new(false);
        let action = handle_run_event(
            session_id,
            &proto::Event::InferenceFailed {
                session_id,
                agent: "Build".into(),
                provider: "openai".into(),
                model: "gpt-5".into(),
                error_class: proto::InferenceErrorClass::Other("auth".into()),
                detail: "credentials rejected".into(),
                auth_failure: None,
            },
            OutputFormat::Json,
            false,
            false,
            &mut out,
            &mut stderr,
            &mut outcome,
        );

        assert_eq!(action, RunEventAction::Continue);
        assert!(outcome.terminal_failure);
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
        let mut stderr = Vec::new();
        let mut outcome = RunOutcome::new(false);
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
            &mut stderr,
            &mut outcome,
        );

        assert_eq!(action, RunEventAction::Break);
        assert!(outcome.terminal_failure);
        let text = String::from_utf8(stderr).unwrap();
        assert!(text.contains("[session ended: done]"));
    }

    #[test]
    fn default_handler_streams_drained_assistant_deltas_once() {
        let session_id = Uuid::new_v4();
        let mut out = Vec::new();
        let mut stderr = Vec::new();
        let mut outcome = RunOutcome::new(false);
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
                &mut stderr,
                &mut outcome,
            );
            assert_eq!(action, RunEventAction::Continue);
        }

        assert!(!outcome.terminal_failure);
        assert_eq!(String::from_utf8(out).unwrap(), "hello world");
    }

    #[test]
    fn default_handler_strips_terminal_control_sequences_for_tty() {
        let session_id = Uuid::new_v4();
        let mut out = Vec::new();
        let mut stderr = Vec::new();
        let mut outcome = RunOutcome::new(false);
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
            &mut stderr,
            &mut outcome,
        );

        assert_eq!(action, RunEventAction::Continue);
        assert_eq!(String::from_utf8(out).unwrap(), "red\tok\nx");
    }

    #[test]
    fn json_handler_preserves_raw_control_sequences() {
        let session_id = Uuid::new_v4();
        let mut out = Vec::new();
        let mut stderr = Vec::new();
        let mut outcome = RunOutcome::new(false);
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
            &mut stderr,
            &mut outcome,
        );

        assert_eq!(action, RunEventAction::Continue);
        let line: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(line["delta"], "\u{1b}[31mred\u{1b}[0m");
    }
}
