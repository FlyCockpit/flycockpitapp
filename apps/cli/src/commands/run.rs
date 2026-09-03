//! `cockpit run` — one-shot non-interactive prompt through the daemon.
//!
//! Lifecycle: attach to a shareable daemon when one is already up; otherwise
//! this command starts a shared ephemeral daemon for the duration of the run.
//! Ctrl+C cancels the agent and exits; it does not promote the owner. TUI
//! `/exit` still offers in-place background promotion.
//!
//! Behavior:
//!
//! 1. Resolve project root (cwd or `--project`).
//! 2. Build the prompt (argv + stdin).
//! 3. acquire an owned daemon session, attach a new session.
//! 4. Send the prompt and pump events until `TurnComplete`.
//! 5. In `default` format we stream assistant text to stdout; in
//!    `json` format we emit one envelope per line.
//! 6. On ordinary exit an ephemeral owner reaps after the final client; a run
//!    attached to an existing daemon leaves that owner up.

use std::io::{IsTerminal, Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::approval::store::GrantKind;
use crate::cli::{OutputFormat, RunArgs};
use crate::daemon::client::{OwnedDaemonRunError, OwnedSessionMode, ScopedDaemonClient};
use crate::daemon::proto::{self, Request, Response, send_user_message_v2::MessageIngressV2};

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
struct RunWorkspaceTrustError(String);

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
struct RunUsageError(String);

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
struct RunTurnFailure(String);

#[derive(Debug, thiserror::Error)]
#[error("{message}")]
struct RunPreflightFailure {
    exit_code: i32,
    code: &'static str,
    message: String,
}

impl RunPreflightFailure {
    fn new(exit_code: i32, code: &'static str, error: impl std::fmt::Display) -> Self {
        Self {
            exit_code,
            code,
            message: error.to_string(),
        }
    }
}

async fn emit_org_logging_indicator_via_daemon(client: &ScopedDaemonClient<'_>, cwd: &Path) {
    let project_root = cwd.display().to_string();
    let response = client
        .request(crate::daemon::proto::Request::GetStartupDisclosures { project_root })
        .await;
    let disclosures = match response {
        Ok(Ok(crate::daemon::proto::Response::StartupDisclosures {
            org_sync: Some(disclosure),
            ..
        })) => disclosure,
        _ => return,
    };
    eprintln!(
        "Organization logging is active for {}: session content may be uploaded.",
        disclosures.org_id
    );
}

async fn enforce_noninteractive_workspace_trust_via_daemon(
    client: &ScopedDaemonClient<'_>,
    cwd: &Path,
    seed_if_unset: bool,
) -> Result<()> {
    let trust_root = crate::config::trust::resolve_trust_root(cwd)?;
    let project_root = trust_root.root.display().to_string();
    let response = client
        .request(crate::daemon::proto::Request::GetWorkspaceTrust {
            project_root: project_root.clone(),
        })
        .await
        .context("requesting workspace trust from daemon")?
        .map_err(|error| anyhow::anyhow!("daemon rejected workspace trust request: {error}"))?;
    let mode = match response {
        crate::daemon::proto::Response::WorkspaceTrust {
            mode: Some(mode), ..
        } => mode,
        crate::daemon::proto::Response::WorkspaceTrust {
            mode: None,
            config_generation,
        } => {
            if !seed_if_unset {
                bail!(
                    "{}",
                    crate::config::trust::WorkspaceTrustError::Unset {
                        root: trust_root.root,
                    }
                );
            }
            let set = client
                .request(crate::daemon::proto::Request::SetWorkspaceTrust {
                    project_root,
                    mode: crate::daemon::proto::WorkspaceTrustMode::IgnoreConfig,
                    expected_config_generation: config_generation,
                })
                .await
                .context("seeding default workspace trust on the owned daemon")?
                .map_err(|error| {
                    anyhow::anyhow!("daemon rejected workspace trust persist: {error}")
                })?;
            if !matches!(
                set,
                crate::daemon::proto::Response::WorkspaceTrustSet { .. }
            ) {
                bail!("daemon returned unexpected workspace trust persist response: {set:?}");
            }
            crate::config::trust::set_runtime_policy(
                trust_root,
                crate::db::workspace_trust::WorkspaceTrustMode::IgnoreConfig,
            );
            return Ok(());
        }
        other => bail!("daemon returned unexpected response to workspace trust: {other:?}"),
    };
    use crate::daemon::proto::WorkspaceTrustMode as ProtoMode;
    let runtime_mode = match mode {
        ProtoMode::Trust => crate::db::workspace_trust::WorkspaceTrustMode::Trust,
        ProtoMode::IgnoreConfig => crate::db::workspace_trust::WorkspaceTrustMode::IgnoreConfig,
        ProtoMode::Untrusted => {
            bail!(
                "workspace {} is untrusted; run `cockpit trust set` to trust it",
                trust_root.root.display()
            )
        }
    };
    crate::config::trust::set_runtime_policy(trust_root, runtime_mode);
    Ok(())
}

async fn resolve_requested_session_via_daemon(
    args: &RunArgs,
    client: &ScopedDaemonClient<'_>,
    root: &Path,
) -> Result<Option<Uuid>> {
    if let Some(session) = &args.session {
        let session_id = Uuid::parse_str(session).context("parsing --session")?;
        // Resolve from the durable session index rather than the live-worker
        // status RPC: an ephemeral daemon may have persisted the session and
        // then exited before this command resumes it on the shared daemon.
        let response = client
            .request(crate::daemon::proto::Request::ListSessions {
                project_id: None,
                parent_session_id: None,
                assistant_id: None,
                compaction_lineage_root_id: None,
            })
            .await
            .context("looking up --session via daemon")?
            .map_err(|error| anyhow::anyhow!("daemon rejected session lookup: {error}"))?;
        let sessions = match response {
            crate::daemon::proto::Response::Sessions { sessions } => sessions,
            other => bail!("daemon returned unexpected response to session lookup: {other:?}"),
        };
        let session = sessions
            .iter()
            .find(|summary| summary.session_id == session_id)
            .ok_or_else(|| anyhow::anyhow!("unknown session {session_id}"))?;
        // Validate the session's project root matches the requested cwd/project
        // (Finding 4): `cockpit run --session <id>` from workspace B must not
        // attach to a session created for workspace A. The v10
        // session summary carries the durable canonical project_root for this
        // check, including sessions whose previous daemon has exited.
        {
            let session_project_root = &session.project_root;
            let requested_root = root
                .canonicalize()
                .with_context(|| format!("canonicalizing run cwd {}", root.display()))?;
            let session_root = Path::new(session_project_root)
                .canonicalize()
                .with_context(|| {
                    format!("canonicalizing session project root {session_project_root}")
                })?;
            if session_root != requested_root {
                anyhow::bail!(
                    "session {session_id} belongs to {}, not {}; \
                     run from that workspace or drop --session",
                    session_root.display(),
                    requested_root.display()
                );
            }
        }
        return Ok(Some(session_id));
    }
    if !args.continue_session {
        return Ok(None);
    }
    // For --continue, list sessions and find the most recent for this project.
    let project_id = crate::session::project_id_for(root)?;
    let response = client
        .request(crate::daemon::proto::Request::ListSessions {
            project_id: Some(project_id),
            parent_session_id: None,
            assistant_id: None,
            compaction_lineage_root_id: None,
        })
        .await
        .context("listing sessions for --continue via daemon")?
        .map_err(|error| anyhow::anyhow!("daemon rejected session list: {error}"))?;
    let sessions = match response {
        crate::daemon::proto::Response::Sessions { sessions } => sessions,
        other => bail!("daemon returned unexpected response to session list: {other:?}"),
    };
    sessions
        .first()
        .map(|s| Some(s.session_id))
        .ok_or_else(|| anyhow::anyhow!("no previous session for workspace {}", root.display()))
}

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
    /// A generic session resume promoted its daemon before Attach established
    /// the durable mode. Presentation remains deferred until that response.
    pub(crate) assistant_promotion_notice: bool,
    /// When set, `cockpit run` marks the submission as a durable run
    /// invocation. `init`/`learn` leave this `None` (unbounded, no state).
    pub(crate) run_invocation_options: Option<proto::RunInvocationOptions>,
}

pub async fn run(args: RunArgs, no_sandbox: bool, project_alias: Option<&Path>) -> Result<()> {
    let format = args.output_format();
    let json_mode = matches!(format, OutputFormat::Json);
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

    let seed_unset_trust = args.cwd.is_none() && project_alias.is_none();

    // A session id is mode-blind until Attach reads its durable row. Acquire
    // a persistent-capable owner first so an Assistant resume cannot enter a
    // private one-shot daemon; Code and Computer remain valid persistent
    // sessions as well.
    let result = if args.session.is_some() {
        crate::daemon::client::run_assistant_daemon(move |client, promoted_from_ephemeral| {
            Box::pin(async move {
                run_with_daemon(
                    client,
                    &args,
                    prompt,
                    no_sandbox,
                    &cwd,
                    seed_unset_trust,
                    promoted_from_ephemeral,
                )
                .await
            })
        })
        .await
    } else {
        crate::daemon::client::run_owned_daemon(
            OwnedSessionMode::AttachOrEphemeral,
            move |client| {
                Box::pin(async move {
                    run_with_daemon(
                        client,
                        &args,
                        prompt,
                        no_sandbox,
                        &cwd,
                        seed_unset_trust,
                        false,
                    )
                    .await
                })
            },
        )
        .await
    };

    let result = match result {
        Err(OwnedDaemonRunError::Connect(error)) => {
            exit_run_error(format, 4, "daemon_connection", &format!("{error:#}"))
        }
        Err(error) => Err(error.into_inner()),
        Ok(value) => Ok(value),
    };

    let exit_code = match result {
        Ok(code) => code,
        Err(error) if error.downcast_ref::<RunPreflightFailure>().is_some() => {
            let failure = error
                .downcast_ref::<RunPreflightFailure>()
                .expect("preflight failure checked above");
            if json_mode {
                emit_json(&json!({
                    "event": "error",
                    "code": failure.code,
                    "message": failure.message
                }))?;
                emit_run_complete(false, failure.exit_code)?;
            } else {
                eprintln!("{}", failure.message);
            }
            failure.exit_code
        }
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
                emit_run_complete(false, 5)?;
            } else {
                eprintln!("{message}");
            }
            5
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

async fn run_with_daemon(
    client: ScopedDaemonClient<'_>,
    args: &RunArgs,
    prompt: String,
    no_sandbox: bool,
    cwd: &Path,
    seed_unset_trust: bool,
    promoted_from_ephemeral: bool,
) -> Result<i32> {
    // Preflight via daemon RPCs — the CLI never opens SQLite.
    emit_org_logging_indicator_via_daemon(&client, cwd).await;
    enforce_noninteractive_workspace_trust_via_daemon(&client, cwd, seed_unset_trust)
        .await
        .map_err(|error| RunPreflightFailure::new(3, "workspace_trust", error))?;
    let requested_session = resolve_requested_session_via_daemon(args, &client, cwd)
        .await
        .map_err(|error| RunPreflightFailure::new(2, "invalid_arguments", error))?;
    let image_files = resolve_attachment_paths(cwd, &args.file)
        .map_err(|error| RunPreflightFailure::new(2, "invalid_arguments", error))?;
    let image_data = load_and_validate_images(&image_files)
        .map_err(|error| RunPreflightFailure::new(2, "invalid_attachment", format!("{error:#}")))?;

    run_turn(
        &client,
        args,
        prompt,
        no_sandbox,
        cwd,
        requested_session,
        &image_data,
        promoted_from_ephemeral,
    )
    .await
}

#[cfg(test)]
fn finish_owned_run<T>(
    command: anyhow::Result<T>,
    shutdown: impl FnOnce() -> anyhow::Result<()>,
) -> anyhow::Result<T> {
    match (command, shutdown()) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(shutdown)) => Err(shutdown).context("shutting down owned daemon"),
        (Err(command), Err(shutdown)) => Err(anyhow::anyhow!(
            "command failed: {command:#}; owned daemon shutdown also failed: {shutdown:#}"
        )),
    }
}

/// Attach, send the prompt, pump events. Split out so the `?` operators
/// unwind through [`run`]'s guard rather than skipping it.
async fn run_turn(
    client: &ScopedDaemonClient<'_>,
    args: &RunArgs,
    prompt: String,
    no_sandbox: bool,
    project_root: &Path,
    requested_session: Option<Uuid>,
    image_data: &[Vec<u8>],
    promoted_from_ephemeral: bool,
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
            assistant_promotion_notice: promoted_from_ephemeral,
            run_invocation_options: Some(args.run_invocation_options()),
        },
    )
    .await
}

/// Attach a fresh headless session, send `prompt`, and pump events to
/// completion, returning the run exit code. Shared by `cockpit run` and
/// `cockpit init` so both drive the identical non-interactive turn over
/// the daemon. The caller owns the daemon lifecycle (probe/spawn +
/// one-shot owner guard).
pub(crate) async fn attach_send_pump(
    client: &ScopedDaemonClient<'_>,
    prompt: String,
    no_sandbox: bool,
    format: OutputFormat,
    options: RunPumpOptions<'_>,
) -> Result<i32> {
    let cwd = match options.project_root {
        Some(root) => root.to_path_buf(),
        None => std::env::current_dir().context("resolving cwd")?,
    };
    enforce_noninteractive_workspace_trust_via_daemon(client, &cwd, true).await?;
    let project_root = cwd.to_string_lossy().into_owned();
    let requested_session = options.session;
    let model_override = parse_model_override(options.model_override, requested_session.is_some())?;
    let env_snapshot = crate::env_snapshot::EnvSnapshot::from_process(
        crate::env_snapshot::EnvSnapshotSource::ExplicitCli,
    );

    // Attach a fresh session. `no_sandbox` (sandboxing part 2) makes this
    // noninteractive session start unsandboxed unless the daemon was
    // launched `--no-sandbox` (which wins). `model_override` (`--model`, the
    // plan executor passes the plan's pinned model) is both the authoritative
    // initial session selection and the pin that overrides every spawned
    // agent's frontmatter model for this session's run.
    let request = match requested_session {
        Some(session_id) => proto::attach_existing_code_root_v1_request(
            session_id,
            None,
            model_override.clone(),
            no_sandbox,
            false,
            model_override,
            client.negotiated().version,
            Some(env_snapshot.to_wire()),
            crate::env_snapshot::EnvDriftPolicy::Daemon,
        ),
        None => proto::create_code_root_v1_request(
            project_root,
            model_override.clone(),
            no_sandbox,
            false,
            model_override,
            client.negotiated().version,
            Some(env_snapshot.to_wire()),
            crate::env_snapshot::EnvDriftPolicy::Daemon,
        ),
    };
    let attached = match client.request(request).await? {
        Ok(response) => response.into_first_party_attached(),
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
    let (session_id, session_entry_mode, repair_required) = match attached {
        Response::Attached {
            session_id,
            session_entry_mode,
            repair_required,
            ..
        } => (
            session_id,
            session_entry_mode,
            repair_required.map(|repair| *repair),
        ),
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
    if options.assistant_promotion_notice
        && session_entry_mode == proto::SessionEntryMode::Assistant
    {
        eprintln!(
            "{}",
            cockpit_core::daemon::client::ASSISTANT_PERSISTENCE_NOTICE
        );
    }
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
    // Sole invocation identity: allocated once before the V2 message send.
    let client_submission_id = Uuid::now_v7();
    if submitted_message {
        let use_bulk = cockpit_client::bulk_upload::user_message_needs_bulk(&prompt, None);
        if use_bulk && !options.image_data.is_empty() {
            return Err(RunUsageError(
                "media/file submissions cannot carry text over the 64 KiB artifact threshold"
                    .to_owned(),
            )
            .into());
        }
        // Never place a source that will become an FCM2 artifact in the
        // NDJSON control request.  The bulk helper emits bounded chunks and
        // returns a digest-bound opaque ref; the daemon consumes it atomically
        // with the eventual SendUserMessageBulk receipt. `cockpit run` always
        // includes the run marker; init/learn omit options and create no
        // RunInvocationState.
        let send_result = if use_bulk {
            let transfer = cockpit_client::bulk_upload::stage_opaque_user_text(client, &prompt)
                .await
                .map_err(|error| RunUsageError(error.to_string()))?;
            client
                .request(Request::SendUserMessageBulk {
                    expected_model_state_generation: None,
                    expected_model: None,
                    client_submission_id,
                    origin: Default::default(),
                    transfer,
                    display_text: None,
                    display_transfer: None,
                    tag_expansions: Vec::new(),
                    forced_skill: None,
                    delivery_class_override: None,
                    run_invocation_options: options.run_invocation_options.clone(),
                })
                .await
        } else {
            let images = options
                .image_data
                .iter()
                .cloned()
                .map(cockpit_client::image_upload::SubmissionImage::png)
                .collect::<Vec<_>>();
            let attachments =
                cockpit_client::image_upload::upload_submission_images(client, session_id, &images)
                    .await
                    .map_err(classify_v2_image_upload_error)?;
            client
                .request(Request::SendUserMessageV2 {
                    ingress: MessageIngressV2::local_direct(
                        Uuid::now_v7(),
                        session_id.to_string(),
                        None,
                        None,
                        options.run_invocation_options.clone(),
                        crate::daemon::proto::send_user_message_v2::SendUserMessageV2 {
                            client_submission_id,
                            origin: Default::default(),
                            text: prompt,
                            display_text: None,
                            tag_expansions: Vec::new(),
                            forced_skill: None,
                            delivery_class_override: None,
                            resolved_delivery_class: None,
                            resolved_queue_target: None,
                            attachments,
                        },
                    ),
                })
                .await
        }
        .context("sending user message")?;
        match send_result {
            Ok(_) => {}
            Err(error)
                if matches!(
                    error.code,
                    proto::ErrorCode::ClientSubmissionIdUnavailable
                        | proto::ErrorCode::InvocationCapacityExceeded
                        | proto::ErrorCode::IdempotencyConflict
                ) =>
            {
                anyhow::bail!("daemon error: {error}");
            }
            Err(error) => anyhow::bail!("daemon error: {error}"),
        }
        if matches!(format, OutputFormat::Json) {
            emit_json(&json!({
                "event": "message_sent",
                "session_id": session_id,
                "client_submission_id": client_submission_id
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
        options
            .run_invocation_options
            .as_ref()
            .map(|_| client_submission_id),
    )
    .await
}

fn parse_model_override(
    raw: Option<&str>,
    resuming: bool,
) -> Result<Option<cockpit_core::config::providers::ActiveModelRef>> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    if resuming {
        return Err(RunUsageError(
            "--model cannot be combined with --continue or --session; resume first and change the durable session model explicitly"
                .to_string(),
        )
        .into());
    }
    let (provider, model) =
        cockpit_core::config::provider::split_provider_model(raw).ok_or_else(|| {
            RunUsageError(format!(
                "invalid --model `{raw}`; expected provider/model-id"
            ))
        })?;
    Ok(Some(cockpit_core::config::providers::ActiveModelRef {
        provider,
        model,
        reasoning_effort: None,
        thinking_mode: None,
        prompt_cache_retention: None,
    }))
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
    if paths.len() > proto::send_user_message_v2::MAX_MESSAGE_ATTACHMENTS {
        return Err(RunUsageError(format!(
            "too many images: {} exceeds {} image limit",
            paths.len(),
            proto::send_user_message_v2::MAX_MESSAGE_ATTACHMENTS
        ))
        .into());
    }
    let images: Vec<Vec<u8>> = paths
        .iter()
        .map(|path| {
            // Bound the read with the same image cap the wire enforces, and
            // refuse non-regular files before any content is accumulated, so
            // an oversized or FIFO/device attachment fails here instead of
            // allocating or blocking the CLI.
            let bytes =
                cockpit_host::bounded::read_at_most(path, proto::MAX_SINGLE_IMAGE_BYTES as u64)
                    .map_err(|error| match error {
                        cockpit_host::bounded::BoundedIoError::Limit { actual, limit, .. } => {
                            RunUsageError(format!(
                                "image is too large: {actual} bytes exceeds {limit} byte limit"
                            ))
                            .into()
                        }
                        other => anyhow::Error::new(other)
                            .context(format!("reading attachment {}", path.display())),
                    })?;
            crate::daemon::server::validate_png_attachment_blocking(bytes)
                .map(|validated| validated.bytes)
                .map_err(|error| anyhow::anyhow!(error.message))
        })
        .collect::<Result<_>>()?;
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

fn classify_v2_image_upload_error(
    error: cockpit_client::image_upload::ImageUploadError,
) -> anyhow::Error {
    match error {
        cockpit_client::image_upload::ImageUploadError::Usage(message) => {
            RunUsageError(message).into()
        }
        cockpit_client::image_upload::ImageUploadError::Daemon(message)
        | cockpit_client::image_upload::ImageUploadError::Transport(message) => {
            anyhow::anyhow!(message)
        }
    }
}

fn exit_run_error(format: OutputFormat, exit_code: i32, code: &str, message: &str) -> ! {
    if matches!(format, OutputFormat::Json) {
        let mut stdout = std::io::stdout().lock();
        let _ = writeln!(
            stdout,
            "{}",
            sorted_json_string(&json!({ "event": "error", "code": code, "message": message }))
                .unwrap_or_default()
        );
        let _ = writeln!(
            stdout,
            "{}",
            sorted_json_string(
                &json!({ "event": "run_complete", "ok": false, "exit_code": exit_code })
            )
            .unwrap_or_default()
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
            sorted_json_string(&json!({
                "event": "session_attached",
                "session_id": session_id,
                "resumed": resumed
            }))?
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
        // Bound the read with the message-text cap the daemon's ingress
        // enforces, so an oversized or non-regular prompt file fails here
        // instead of allocating or blocking the CLI before any cap runs.
        let bytes = cockpit_host::bounded::read_at_most(
            &path,
            proto::send_user_message_v2::MAX_MESSAGE_TEXT_BYTES as u64,
        )
        .with_context(|| format!("reading prompt file {}", path.display()))?;
        return String::from_utf8(bytes)
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

pub(crate) async fn pump_events(
    client: &ScopedDaemonClient<'_>,
    mut session_id: Uuid,
    format: OutputFormat,
    verbose_json: bool,
    approve: &[GrantKind],
    expect_submitted_message: bool,
    run_invocation_id: Option<Uuid>,
) -> Result<i32> {
    let mut stdout = std::io::stdout().lock();
    let mut stderr = std::io::stderr().lock();
    let mut outcome = RunOutcome::new(expect_submitted_message);
    let mut sigint_count = 0u8;
    let mut sigint = std::pin::pin!(tokio::signal::ctrl_c());

    loop {
        let event = tokio::select! {
            biased;
            _ = &mut sigint => {
                sigint_count = sigint_count.saturating_add(1);
                if let Some(id) = run_invocation_id {
                    if sigint_count >= 2 {
                        writeln!(stderr, "{}", second_interrupt_unknown_guidance(id))?;
                        return Ok(130);
                    }
                    let proto::Response::ExitGuardStatus {
                        ephemeral_owner,
                        has_live_work,
                    } = client
                        .request_ok(Request::ExitGuardStatus)
                        .await
                        .context("reading authoritative daemon exit state")?
                    else {
                        anyhow::bail!("unexpected daemon exit-state response");
                    };
                    if has_live_work && ephemeral_owner {
                        // Ctrl+C on `cockpit run` is stop-all: cancel the agent,
                        // tear down owned processes, and exit. Backgrounding is
                        // the TUI `/exit` guard's job, not this command.
                        client
                            .request_ok(Request::CancelAllSessionWork)
                            .await
                            .context("cancelling all attached session work")?;
                    } else if has_live_work {
                        writeln!(
                            stderr,
                            "This session is still running in the background; reattach with cockpit run --session {session_id}"
                        )?;
                        return Ok(130);
                    }
                    // Either StopAll was explicitly selected, or the daemon
                    // confirmed no live work at detach time. Normal Ctrl-C
                    // cancellation remains invocation-scoped in this helper.
                    return reconcile_after_interrupt(client, id, format, &mut stderr).await;
                }
                return Ok(130);
            }
            event = client.next_event() => event,
        };
        let Some(event) = event else {
            break;
        };
        // Filter to this session's events. CompactReady is stamped with the
        // predecessor so it passes this check; retarget afterwards so later
        // events (stamped with the successor) are not dropped.
        if event_session(&event) != Some(session_id) {
            continue;
        }
        if let proto::Event::CompactReady { new_session_id, .. } = &event {
            session_id = *new_session_id;
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
                        sorted_json_string(
                            &json!({ "event": "run_complete", "ok": false, "exit_code": code })
                        )?
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
        if let Some(id) = run_invocation_id {
            writeln!(stderr, "{}", disconnect_status_guidance(id))?;
        }
        if matches!(format, OutputFormat::Json) {
            writeln!(
                stdout,
                "{}",
                sorted_json_string(&json!({
                    "event": "error",
                    "code": "daemon_connection",
                    "message": "daemon connection closed before run completed"
                }))?
            )?;
        } else {
            writeln!(stderr, "[daemon connection closed before run completed]")?;
        }
    }
    if matches!(format, OutputFormat::Default) && code == 5 && outcome.is_empty_turn() {
        writeln!(
            stderr,
            "[run failed: turn completed without inference, assistant output, or tool progress]"
        )?;
    }
    if matches!(format, OutputFormat::Json) {
        writeln!(
            stdout,
            "{}",
            sorted_json_string(
                &json!({ "event": "run_complete", "ok": code == 0, "exit_code": code })
            )?
        )?;
        stdout.flush()?;
    }
    Ok(code)
}

/// Map an authoritative terminal lifecycle state after interrupt reconciliation.
fn interrupt_reconcile_exit_code(state: proto::RunInvocationLifecycleState) -> i32 {
    match state {
        proto::RunInvocationLifecycleState::Succeeded => 0,
        proto::RunInvocationLifecycleState::Cancelled => 130,
        _ => 5,
    }
}

/// Content-free recovery guidance for second SIGINT / unknown state.
fn second_interrupt_unknown_guidance(id: Uuid) -> String {
    format!(
        "invocation {id}: final state is unknown\ncockpit invocation status {id}\ncockpit invocation cancel {id}"
    )
}

/// Recovery guidance when a disconnect leaves outcome unknown.
fn disconnect_status_guidance(id: Uuid) -> String {
    format!("cockpit invocation status {id}")
}

/// First-SIGINT reconciliation: cancel then status on the same identity.
async fn reconcile_after_interrupt(
    client: &ScopedDaemonClient<'_>,
    id: Uuid,
    format: OutputFormat,
    stderr: &mut impl Write,
) -> Result<i32> {
    let _ = client
        .request(Request::CancelRunInvocation {
            client_submission_id: id,
        })
        .await;
    // Reconcile via status even when cancel ack is lost. No replacement start.
    loop {
        match client
            .request(Request::GetRunInvocationStatus {
                client_submission_id: id,
            })
            .await
        {
            Ok(Ok(Response::RunInvocationStatus { status })) => {
                if status.state.is_terminal() {
                    let code = interrupt_reconcile_exit_code(status.state);
                    if matches!(format, OutputFormat::Default) {
                        writeln!(stderr, "invocation {id}: {}", status.state.as_str())?;
                    }
                    return Ok(code);
                }
                // Still active: retry cancel while active, then status again.
                let _ = client
                    .request(Request::CancelRunInvocation {
                        client_submission_id: id,
                    })
                    .await;
                tokio::task::yield_now().await;
            }
            Ok(Err(error)) if error.code == proto::ErrorCode::InvocationNotFound => {
                writeln!(stderr, "invocation {id}: no durable run record was found")?;
                return Ok(130);
            }
            Ok(Err(_)) | Err(_) => {
                writeln!(
                    stderr,
                    "cockpit invocation status {id}\n\
                     cockpit invocation cancel {id}"
                )?;
                return Ok(4);
            }
            Ok(Ok(_)) => {
                writeln!(stderr, "cockpit invocation status {id}")?;
                return Ok(4);
            }
        }
    }
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
            | proto::Event::AssistantDisplayTextDelta { .. }
            | proto::Event::AssistantDisplayReasoningDelta { .. }
            | proto::Event::AssistantDisplayComplete { .. }
            | proto::Event::AssistantText { .. }
            | proto::Event::ReasoningDelta { .. }
            | proto::Event::ToolStart { .. }
            | proto::Event::ToolEnd { .. } => self.progress = true,
            proto::Event::AssistantDisplayAttemptReset { .. } => {
                // Replacement attempt may buffer until Complete (translation).
                self.streamed_text = false;
                self.progress = true;
            }
            proto::Event::AssistantDisplayError { .. }
            | proto::Event::InferenceFailed { .. }
            | proto::Event::ToolError { .. } => {
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
        // Authoritative non-success terminals use exit 5 (replacing legacy 1).
        if !self.ready_to_finish() || self.terminal_failure || self.is_empty_turn() {
            5
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
            proto::Event::AssistantTextDelta { delta, .. }
            | proto::Event::AssistantDisplayTextDelta { delta, .. } => {
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
            // Translation / buffered paths suppress live deltas until Complete.
            // Print once when nothing was streamed, avoiding duplicate bodies.
            proto::Event::AssistantDisplayComplete {
                text,
                presentation_text,
                ..
            } => {
                if outcome.streamed_text {
                    // Already printed via typed deltas.
                } else {
                    let body = presentation_text.as_deref().unwrap_or(text.as_str());
                    if !body.is_empty() {
                        outcome.streamed_text = true;
                        if sanitize_tty {
                            let _ = stdout.write_all(sanitize_terminal_text(body).as_bytes());
                        } else {
                            let _ = stdout.write_all(body.as_bytes());
                        }
                        let _ = stdout.flush();
                    }
                }
            }
            proto::Event::ToolError { tool, error, .. } => {
                let _ = writeln!(stderr, "[error: {tool}: {error}]");
            }
            proto::Event::AssistantDisplayError { message, .. } => {
                let _ = writeln!(stderr, "[assistant display error: {message}]");
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
            proto::Event::Notice { text, .. }
            | proto::Event::CommandCapabilityUnavailable { text, .. } => {
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
                && let Ok(line) = sorted_json_string(&value)
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

async fn is_processing(client: &ScopedDaemonClient<'_>, session_id: Uuid) -> Result<bool> {
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
    println!("{}", sorted_json_string(value)?);
    Ok(())
}

/// Serialize a JSON value with object keys sorted alphabetically so NDJSON
/// output is deterministic regardless of whether the `serde_json`
/// `preserve_order` feature is active in the build graph.
fn sorted_json_string(value: &Value) -> Result<String> {
    fn sort_keys(value: &Value) -> Value {
        match value {
            Value::Object(map) => {
                let mut sorted = serde_json::Map::new();
                let mut keys: Vec<&String> = map.keys().collect();
                keys.sort();
                for key in keys {
                    sorted.insert(key.clone(), sort_keys(&map[key]));
                }
                Value::Object(sorted)
            }
            Value::Array(arr) => Value::Array(arr.iter().map(sort_keys).collect()),
            _ => value.clone(),
        }
    }
    Ok(serde_json::to_string(&sort_keys(value))?)
}

fn normalized_event(session_id: Uuid, event: &proto::Event, verbose: bool) -> Option<Value> {
    let mut value = match event {
        proto::Event::ThinkingStarted { agent, .. } => {
            json!({ "event": "thinking_started", "session_id": session_id, "agent": agent })
        }
        proto::Event::AssistantTextDelta { agent, delta, .. } => {
            json!({ "event": "assistant_delta", "session_id": session_id, "agent": agent, "delta": delta })
        }
        proto::Event::AssistantDisplayTextDelta {
            agent,
            attempt_id,
            delta,
            ..
        } => json!({
            "event": "assistant_display_text_delta",
            "session_id": session_id,
            "agent": agent,
            "attempt_id": attempt_id,
            "delta": delta
        }),
        proto::Event::AssistantDisplayReasoningDelta {
            agent,
            attempt_id,
            delta,
            ..
        } => json!({
            "event": "assistant_display_reasoning_delta",
            "session_id": session_id,
            "agent": agent,
            "attempt_id": attempt_id,
            "delta": delta
        }),
        proto::Event::AssistantDisplayAttemptReset {
            agent,
            failed_attempt_id,
            replacement_attempt_id,
            reason,
            ..
        } => json!({
            "event": "assistant_display_attempt_reset",
            "session_id": session_id,
            "agent": agent,
            "failed_attempt_id": failed_attempt_id,
            "replacement_attempt_id": replacement_attempt_id,
            "reason": reason
        }),
        proto::Event::AssistantDisplayComplete {
            agent,
            attempt_id,
            text,
            presentation_text,
            reasoning,
            seq,
            response_performance,
            ..
        } => {
            let shown = presentation_text.as_deref().unwrap_or(text.as_str());
            let mut obj = json!({
                "event": "assistant_display_complete",
                "session_id": session_id,
                "agent": agent,
                "attempt_id": attempt_id,
                "text": shown,
                "reasoning": reasoning,
                "seq": seq
            });
            if let Some(perf) = response_performance {
                obj["response_performance"] = serde_json::to_value(perf).unwrap_or(Value::Null);
            }
            if presentation_text.is_some() {
                obj["presentation_text"] = json!(presentation_text);
                obj["raw_text"] = json!(text);
            }
            obj
        }
        proto::Event::AssistantDisplayError {
            agent,
            attempt_id,
            kind,
            message,
            presentation_text,
            ..
        } => {
            let mut obj = json!({
                "event": "assistant_display_error",
                "session_id": session_id,
                "agent": agent,
                "attempt_id": attempt_id,
                "kind": kind,
                "message": message
            });
            if let Some(text) = presentation_text {
                obj["presentation_text"] = json!(text);
            }
            obj
        }
        proto::Event::ReasoningDelta { agent, delta, .. } => {
            json!({ "event": "reasoning_delta", "session_id": session_id, "agent": agent, "delta": delta })
        }
        proto::Event::AssistantText {
            agent,
            text,
            presentation_text,
            reasoning,
            seq,
            ..
        } => {
            let shown = presentation_text.as_deref().unwrap_or(text.as_str());
            json!({
                "event": "assistant_message",
                "session_id": session_id,
                "agent": agent,
                "text": shown,
                "reasoning": reasoning,
                "seq": seq
            })
        }
        proto::Event::UserMessageRecorded { seq, .. } => {
            json!({ "event": "user_message_recorded", "session_id": session_id, "seq": seq })
        }
        proto::Event::UserMessageRemoved { seq, .. } => {
            json!({ "event": "user_message_removed", "session_id": session_id, "seq": seq })
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
        proto::Event::ToolProgress {
            call_id,
            done,
            total,
            unit,
            ..
        } => json!({
            "event": "tool_progress",
            "session_id": session_id,
            "call_id": call_id,
            "done": done,
            "total": total,
            "unit": unit
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
        | ModelSelectionResult { session_id, .. }
        | Reconnecting { session_id, .. }
        | AssistantTextDelta { session_id, .. }
        | ReasoningDelta { session_id, .. }
        | AssistantDisplayTextDelta { session_id, .. }
        | AssistantDisplayReasoningDelta { session_id, .. }
        | AssistantDisplayAttemptReset { session_id, .. }
        | AssistantDisplayComplete { session_id, .. }
        | AssistantDisplayError { session_id, .. }
        | AssistantText { session_id, .. }
        | UserMessageRecorded { session_id, .. }
        | UserMessageRemoved { session_id, .. }
        | QueuedUserMessagesFolded { session_id, .. }
        | SessionPersistFailed { session_id, .. }
        | SessionDriverFailed { session_id, .. }
        | PreflightStarted { session_id, .. }
        | UserMessagesTerminated { session_id, .. }
        | UserMessageRetracted { session_id, .. }
        | Notice { session_id, .. }
        | SkillAutoInjected { session_id, .. }
        | ToolStart { session_id, .. }
        | ToolProgress { session_id, .. }
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
        | AgentTreeChanged { session_id, .. }
        | GoalSupervisionProgress { session_id, .. }
        | PrimarySwapped { session_id, .. }
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
        | LongcacheState { session_id, .. }
        | ApprovalModeState { session_id, .. }
        | DelegationRecursionState { session_id, .. }
        | TandemState { session_id, .. }
        | GitignoreAllow { session_id, .. }
        | PausedWorkAvailable { session_id, .. }
        | DefaultModelUpdateResult { session_id, .. }
        | WaitingForLock { session_id, .. }
        | WorkspaceTrustReconciliation { session_id, .. } => *session_id,
        EventStreamLagged {
            session_id: Some(session_id),
            ..
        } => *session_id,
        // Daemon-global events (no session_id) — irrelevant to a headless
        // one-shot run, so they're filtered out by the session check.
        CaffeinateState { .. }
        | DaemonDraining { .. }
        | DaemonLifetimeChanged { .. }
        | TerminalOutput { .. }
        | TerminalClipboard { .. }
        | TerminalViewers { .. }
        | TerminalClosed { .. }
        | Osc52ProtocolViolation { .. }
        | HostCapabilitiesChanged { .. }
        | LspNotice { .. }
        | EventStreamLagged {
            session_id: None, ..
        }
        | EnvDriftWarning { .. }
        | Unknown => {
            return None;
        }
        #[cfg(feature = "extended")]
        ImageControlConfigChanged { .. } => return None,
        #[cfg(feature = "remote")]
        ConnectorStatus { .. } => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preflight_failure_still_finishes_owned_shutdown_before_render_or_exit() {
        let shutdown_called = std::cell::Cell::new(false);
        let result: anyhow::Result<()> = finish_owned_run(
            Err(RunPreflightFailure::new(3, "workspace_trust", "denied").into()),
            || {
                shutdown_called.set(true);
                Ok(())
            },
        );
        assert!(shutdown_called.get());
        assert!(result.unwrap_err().is::<RunPreflightFailure>());
    }

    #[test]
    fn injected_signal_cleanup_during_preflight_is_joined_before_exit_selection() {
        let cleanup_complete = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let signal_complete = cleanup_complete.clone();
        let signal_cleanup = std::thread::spawn(move || {
            signal_complete.store(true, std::sync::atomic::Ordering::SeqCst);
        });
        let result: anyhow::Result<()> = finish_owned_run(
            Err(RunPreflightFailure::new(2, "invalid_arguments", "injected").into()),
            || {
                signal_cleanup.join().unwrap();
                assert!(cleanup_complete.load(std::sync::atomic::Ordering::SeqCst));
                Ok(())
            },
        );
        assert!(cleanup_complete.load(std::sync::atomic::Ordering::SeqCst));
        assert!(result.unwrap_err().is::<RunPreflightFailure>());
    }

    #[cfg(feature = "extended")]
    #[test]
    fn image_control_config_changed_is_filtered_as_daemon_global() {
        let event = proto::Event::ImageControlConfigChanged {
            event: proto::image_control::ImageControlEventV1::config_changed(
                "daemon".into(),
                "project".into(),
                "/canonical/project".into(),
                "/canonical/project/config.json".into(),
                "revision".into(),
                proto::image_control::ImageConfigMutationCapabilityV1::new("cc".repeat(32)),
                1,
                proto::image_control::ImageConfigChangeSetSafeV1::new("1".into(), vec![]),
            ),
        };

        assert_eq!(event_session(&event), None);
    }

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
            max_turns: None,
            timeout: None,
            permission_mode: None,
        }
    }

    #[test]
    fn run_cli_bounds_contract() {
        use crate::cli::{Cli, Command};
        use clap::Parser;

        // Omitted dimensions encode None (unbounded for that dimension).
        let plain = Cli::try_parse_from(["cockpit", "run", "hi"]).unwrap();
        let Command::Run(args) = plain.command.unwrap() else {
            panic!("expected run");
        };
        assert_eq!(args.max_turns, None);
        assert_eq!(args.timeout, None);
        let opts = args.run_invocation_options();
        assert_eq!(opts.max_turns, None);
        assert_eq!(opts.timeout_ms, None);

        // Boundaries: 1 and 10000 max-turns.
        let low = Cli::try_parse_from(["cockpit", "run", "--max-turns", "1", "hi"]).unwrap();
        let Command::Run(args) = low.command.unwrap() else {
            panic!();
        };
        assert_eq!(args.max_turns, Some(1));
        let high = Cli::try_parse_from(["cockpit", "run", "--max-turns", "10000", "hi"]).unwrap();
        let Command::Run(args) = high.command.unwrap() else {
            panic!();
        };
        assert_eq!(args.max_turns, Some(10_000));

        // 0 / 10001 / overflow / sign / fraction are usage errors (exit 2 path).
        for bad in ["0", "10001", "999999999999", "-1", "1.5", "1s", "+2"] {
            assert!(
                Cli::try_parse_from(["cockpit", "run", "--max-turns", bad, "hi"]).is_err(),
                "max-turns {bad} must fail"
            );
        }

        // Timeout: 1 and 604800 seconds; checked ms conversion.
        let t1 = Cli::try_parse_from(["cockpit", "run", "--timeout", "1", "hi"]).unwrap();
        let Command::Run(args) = t1.command.unwrap() else {
            panic!();
        };
        assert_eq!(args.timeout, Some(1));
        assert_eq!(args.run_invocation_options().timeout_ms, Some(1000));
        let t_max = Cli::try_parse_from(["cockpit", "run", "--timeout", "604800", "hi"]).unwrap();
        let Command::Run(args) = t_max.command.unwrap() else {
            panic!();
        };
        assert_eq!(args.timeout, Some(604_800));
        assert_eq!(
            args.run_invocation_options().timeout_ms,
            Some(604_800 * 1000)
        );

        for bad in [
            "0",
            "604801",
            "-1",
            "1.5",
            "1s",
            "+2",
            "99999999999999999999",
        ] {
            assert!(
                Cli::try_parse_from(["cockpit", "run", "--timeout", bad, "hi"]).is_err(),
                "timeout {bad} must fail"
            );
        }

        // Zero never means unbounded: parser rejects zero rather than mapping to None.
        assert!(Cli::try_parse_from(["cockpit", "run", "--timeout", "0", "hi"]).is_err());
        assert!(Cli::try_parse_from(["cockpit", "run", "--max-turns", "0", "hi"]).is_err());
    }

    #[test]
    fn permission_mode_parses_exact_variants() {
        use crate::cli::{Cli, Command, PermissionModeArg};
        use crate::daemon::proto::ApprovalMode;
        use clap::{CommandFactory, Parser};

        for (raw, expected) in [
            ("manual", PermissionModeArg::Manual),
            ("auto", PermissionModeArg::Auto),
            ("yolo", PermissionModeArg::Yolo),
        ] {
            let cli =
                Cli::try_parse_from(["cockpit", "run", "--permission-mode", raw, "hi"]).unwrap();
            let Command::Run(args) = cli.command.unwrap() else {
                panic!("expected run");
            };
            assert_eq!(args.permission_mode, Some(expected));
            assert_eq!(
                args.run_invocation_options().approval_mode,
                Some(ApprovalMode::from(expected))
            );
        }

        // Omitted → no override (session/default).
        let plain = Cli::try_parse_from(["cockpit", "run", "hi"]).unwrap();
        let Command::Run(args) = plain.command.unwrap() else {
            panic!("expected run");
        };
        assert_eq!(args.permission_mode, None);
        assert_eq!(args.run_invocation_options().approval_mode, None);

        // Invalid values are clap usage errors.
        for bad in ["Manual", "AUTO", "yes", "1", "full", ""] {
            assert!(
                Cli::try_parse_from(["cockpit", "run", "--permission-mode", bad, "hi"]).is_err(),
                "permission-mode {bad:?} must fail"
            );
        }

        // Help lists the exact variants.
        let mut cmd = Cli::command();
        let help = cmd
            .find_subcommand_mut("run")
            .unwrap()
            .render_long_help()
            .to_string();
        assert!(help.contains("--permission-mode"), "{help}");
        for variant in ["manual", "auto", "yolo"] {
            assert!(
                help.to_lowercase().contains(variant),
                "help must list {variant}: {help}"
            );
        }
    }

    #[test]
    fn run_permission_mode_uses_submission_id_and_immutable_options() {
        use crate::daemon::proto::send_user_message_v2::MessageIngressV2;
        use crate::daemon::proto::{ApprovalMode, Request, RunInvocationOptions};
        use uuid::Uuid;

        // Run path constructs SendUserMessage with client_submission_id + options.
        // Never SetApprovalMode; approval_mode is client-owned immutable input.
        let id = Uuid::new_v4();
        let options = RunInvocationOptions {
            max_turns: None,
            timeout_ms: None,
            approval_mode: Some(ApprovalMode::Yolo),
        };
        let send = Request::SendUserMessageV2 {
            ingress: MessageIngressV2::local_direct(
                Uuid::now_v7(),
                "session",
                None,
                None,
                Some(options.clone()),
                crate::daemon::proto::send_user_message_v2::SendUserMessageV2 {
                    client_submission_id: id,
                    origin: Default::default(),
                    text: "go".into(),
                    display_text: None,
                    tag_expansions: Vec::new(),
                    forced_skill: None,
                    delivery_class_override: None,
                    resolved_delivery_class: None,
                    resolved_queue_target: None,
                    attachments: Vec::new(),
                },
            ),
        };
        let json = serde_json::to_value(&send).unwrap();
        assert_eq!(json["request"], "send_user_message");
        assert_eq!(
            json["params"]["ingress"]["request"]["client_submission_id"],
            id.to_string()
        );
        assert_eq!(
            json["params"]["ingress"]["run_invocation_options"]["approval_mode"],
            "yolo"
        );
        // Sole identity: no parallel invocation_id; no daemon-owned state fields.
        assert!(json["params"].get("invocation_id").is_none());
        assert!(json["params"].get("state_version").is_none());
        assert!(json["params"].get("remaining_ms").is_none());
        assert!(json["params"].get("checkpoint").is_none());
        // approval_mode is only under options — not a sibling state field.
        assert!(json["params"].get("approval_mode").is_none());

        // Run ordering rejects SetApprovalMode as the run permission mechanism.
        let set = Request::SetApprovalMode {
            mode: ApprovalMode::Yolo,
        };
        assert_eq!(set.wire_tag(), "set_approval_mode");
        assert_ne!(set.wire_tag(), send.wire_tag());
        // Shared envelope requires SendUserMessageV2 with options marker.
        match send {
            Request::SendUserMessageV2 {
                ingress:
                    cockpit_proto::send_user_message_v2::MessageIngressV2::LocalOwnerDirect(local),
            } => {
                assert_eq!(local.request.client_submission_id, id);
                assert_eq!(
                    local.run_invocation_options.as_ref().unwrap().approval_mode,
                    Some(ApprovalMode::Yolo)
                );
            }
            other => panic!("run path must send SendUserMessageV2, got {other:?}"),
        }
    }

    #[test]
    fn no_override_default() {
        use crate::cli::{Cli, Command};
        use clap::Parser;
        let cli = Cli::try_parse_from(["cockpit", "run", "hi"]).unwrap();
        let Command::Run(args) = cli.command.unwrap() else {
            panic!();
        };
        let opts = args.run_invocation_options();
        assert!(opts.approval_mode.is_none());
        // Marker is still Some for cockpit run (bounds dimensions may be None).
        assert!(matches!(
            Some(opts),
            Some(crate::daemon::proto::RunInvocationOptions {
                approval_mode: None,
                ..
            })
        ));
    }

    #[test]
    fn init_learn_no_override() {
        use crate::cli::Cli;
        use clap::{CommandFactory, Parser};

        // Init/learn have no --permission-mode / --max-turns / --timeout flags.
        for sub in ["init", "assistants"] {
            let mut root = Cli::command();
            let help = if sub == "assistants" {
                root.find_subcommand_mut("assistants")
                    .unwrap()
                    .find_subcommand_mut("learn")
                    .unwrap()
                    .render_long_help()
                    .to_string()
            } else {
                root.find_subcommand_mut("init")
                    .unwrap()
                    .render_long_help()
                    .to_string()
            };
            assert!(
                !help.contains("--permission-mode"),
                "{sub} must not expose --permission-mode: {help}"
            );
            assert!(
                !help.contains("--max-turns"),
                "{sub} must not expose --max-turns"
            );
            assert!(
                !help.contains("--timeout"),
                "{sub} must not expose --timeout"
            );
        }

        // Pump options for init/learn leave run_invocation_options as None.
        let pump = RunPumpOptions::default();
        assert!(pump.run_invocation_options.is_none());

        // Parse paths still work without the flag.
        assert!(Cli::try_parse_from(["cockpit", "init"]).is_ok());
        assert!(Cli::try_parse_from(["cockpit", "assistants", "learn", "how we deploy"]).is_ok());
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
    #[test]
    fn model_override_is_a_complete_new_session_selection() {
        let selection = parse_model_override(Some(" openai/gpt-5 "), false)
            .unwrap()
            .expect("model override");
        assert_eq!(selection.provider, "openai");
        assert_eq!(selection.model, "gpt-5");
        assert_eq!(selection.reasoning_effort, None);
        assert_eq!(selection.thinking_mode, None);
        assert_eq!(selection.prompt_cache_retention, None);
    }

    #[test]
    fn model_override_rejects_malformed_or_resumed_session_use() {
        let malformed = parse_model_override(Some("missing-provider"), false).unwrap_err();
        assert!(malformed.downcast_ref::<RunUsageError>().is_some());
        assert!(malformed.to_string().contains("expected provider/model-id"));

        let resumed = parse_model_override(Some("openai/gpt-5"), true).unwrap_err();
        assert!(resumed.downcast_ref::<RunUsageError>().is_some());
        assert!(resumed.to_string().contains("cannot be combined"));
    }

    #[test]
    fn attachment_limits_and_daemon_bad_requests_are_usage_errors() {
        let paths = (0..=proto::send_user_message_v2::MAX_MESSAGE_ATTACHMENTS)
            .map(|index| PathBuf::from(format!("unread-image-{index}.png")))
            .collect::<Vec<_>>();
        let error = load_and_validate_images(&paths).unwrap_err();
        assert!(error.downcast_ref::<RunUsageError>().is_some());
        assert!(error.to_string().contains("too many images"));

        let error =
            classify_v2_image_upload_error(cockpit_client::image_upload::ImageUploadError::Usage(
                "configured V2 attachment limit rejected the image".into(),
            ));
        assert!(error.downcast_ref::<RunUsageError>().is_some());

        let error = classify_v2_image_upload_error(
            cockpit_client::image_upload::ImageUploadError::Transport("socket closed".into()),
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
            client_submission_ids: Vec::new(),
        });
        outcome.observe(&proto::Event::AgentIdle {
            session_id,
            turn_id: None,
            reason: crate::engine::IdleReason::Completed,
        });
        assert!(outcome.is_empty_turn());
        assert_eq!(outcome.exit_code(), 5);
    }

    #[test]
    fn daemon_disconnect_is_exit_four() {
        let session_id = Uuid::new_v4();
        let mut outcome = RunOutcome::new(true);
        outcome.observe(&proto::Event::UserMessageRecorded {
            session_id,
            seq: 1,
            preflight_cleaned: None,
            client_submission_ids: Vec::new(),
        });
        outcome.observe(&proto::Event::ThinkingStarted {
            session_id,
            agent: "Build".into(),
            turn_id: None,
        });
        assert_eq!(terminal_exit_code(&outcome), 4);
    }

    #[test]
    fn attached_snapshot_does_not_finish_before_submission() {
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
            client_submission_ids: Vec::new(),
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
    fn run_approve_command_cannot_grant_unclassified_owner_network_authority() {
        let mut question = approval_question(GrantKind::Command);
        let proto::InterruptQuestion::Single { approval_class, .. } = &mut question else {
            panic!("approval fixture must be a single question");
        };
        *approval_class = None;
        let resolution = resolve_run_interrupt(Some(&question), None, &[GrantKind::Command]);
        assert!(!resolution.approved);
        assert_eq!(resolution.class, None);
        assert!(matches!(
            resolution.response,
            proto::ResolveResponse::Freetext { ref text }
                if text == crate::approval::NONINTERACTIVE_RUN_DENIAL
        ));
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
                client_submission_ids: Vec::new(),
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
    fn default_handler_surfaces_generic_notice_on_stderr() {
        let session_id = Uuid::new_v4();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut outcome = RunOutcome::new(false);
        let action = handle_run_event(
            session_id,
            &proto::Event::Notice {
                session_id,
                text: "Firecrawl request leaves this machine".into(),
            },
            OutputFormat::Default,
            false,
            false,
            &mut stdout,
            &mut stderr,
            &mut outcome,
        );
        assert_eq!(action, RunEventAction::Continue);
        assert!(stdout.is_empty());
        assert_eq!(
            String::from_utf8(stderr).unwrap(),
            "[notice: Firecrawl request leaves this machine]\n"
        );
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
    #[test]
    fn run_interrupt_reconciles_same_identity() {
        use crate::daemon::proto::RunInvocationLifecycleState;
        // Cancelled → 130
        assert_eq!(
            interrupt_reconcile_exit_code(RunInvocationLifecycleState::Cancelled),
            130
        );
        // Terminal success race → 0
        assert_eq!(
            interrupt_reconcile_exit_code(RunInvocationLifecycleState::Succeeded),
            0
        );
        // Terminal failure race → 5
        assert_eq!(
            interrupt_reconcile_exit_code(RunInvocationLifecycleState::Failed),
            5
        );
        assert_eq!(
            interrupt_reconcile_exit_code(RunInvocationLifecycleState::TimeoutExpired),
            5
        );
        assert_eq!(
            interrupt_reconcile_exit_code(RunInvocationLifecycleState::MaxTurnsExceeded),
            5
        );
        // NotFound is handled as 130 by reconcile path; guidance does not claim cancel success.
        let id = Uuid::parse_str("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").unwrap();
        let g = second_interrupt_unknown_guidance(id);
        assert!(g.contains("final state is unknown"));
        assert!(g.contains(&format!("cockpit invocation status {id}")));
        assert!(g.contains(&format!("cockpit invocation cancel {id}")));
        assert!(!g.contains("cancelled successfully"));
        assert!(!g.contains("cancellation succeeded"));
        // Disconnect prints status only (no replacement start).
        assert_eq!(
            disconnect_status_guidance(id),
            format!("cockpit invocation status {id}")
        );
    }

    #[test]
    fn run_second_interrupt_exits_unknown() {
        let id = Uuid::parse_str("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb").unwrap();
        let guidance = second_interrupt_unknown_guidance(id);
        // Exact recovery command strings (content-free, ID-bearing).
        assert!(
            guidance.starts_with(&format!("invocation {id}: final state is unknown")),
            "{guidance}"
        );
        assert!(
            guidance.contains(&format!("cockpit invocation status {id}")),
            "{guidance}"
        );
        assert!(
            guidance.contains(&format!("cockpit invocation cancel {id}")),
            "{guidance}"
        );
        // Second interrupt always exits 130 (documented exit code).
        assert_eq!(130, 130);
        // Does not claim cancelled-success.
        assert!(!guidance.to_lowercase().contains("success"));
        assert!(!guidance.contains("cancellation succeeded"));
    }
}
