//! Library entry points for the `cockpit` binary and integration tests.
//!
//! Most product logic still lives in the per-subcommand modules. The library
//! target exists so process-boundary tests can exercise the daemon protocol
//! without duplicating wire types.

// rig 0.41's completion/message types deepen the async layout of long CLI
// command futures (notably `commands::ask::run`) past rustc's default query
// depth of 128. 256 matches the compiler's own suggestion for this crate.
#![recursion_limit = "256"]

pub(crate) mod acp;
mod cli;
mod commands;
pub use cockpit_config as config;
#[cfg(test)]
pub mod test_env {
    pub use cockpit_test_support::TestEnvGuard;

    pub fn lock() -> TestEnvGuard {
        TestEnvGuard::blocking_lock()
    }

    pub async fn lock_async() -> TestEnvGuard {
        TestEnvGuard::lock().await
    }
}
pub(crate) mod daemon {
    pub(crate) use cockpit_core::daemon::{
        DaemonPaths, DaemonProbe, DaemonStatus, EventSender, SharedRedactionTable, caffeinate,
        daemon_pid, derive_restart_no_sandbox, discover, proto, restart_release_timeout,
        run_foreground, run_foreground_with_resume, send_current_event, server, session_worker,
        spawn_detached_with_resume, stop, terminal, wait_for_restart_release,
    };
    pub(crate) mod client {
        pub(crate) use cockpit_core::daemon::client::{
            OwnedDaemonRunError, OwnedSessionMode, ScopedDaemonClient, ensure_persistent_daemon,
            run_owned_daemon,
        };
    }
    #[cfg(test)]
    pub(crate) use cockpit_core::daemon::{
        boot_test_persistent_daemon, enable_in_process_auto_promote,
    };
}
pub use cockpit_core::{
    agents, approval, assistants, auth, auto_title, browser, computer, container, credentials,
    diagnostics, embeddings, engine, env_snapshot, envref, git, gitignore, harness, intel,
    knowledge, locks, mcp, media_reservation, model_system_prompt, packages, providers, redact,
    secret_ref, session, skills, startup, sync, tokens, tools, user_agent, welcome, wizard,
};
pub use cockpit_host::{sysinfo, text};

/// Narrow process-boundary fixtures used by the CLI's integration tests.
/// Production consumers must not gain access to the daemon lifecycle module.
#[doc(hidden)]
pub mod integration_test_api {
    pub use cockpit_core::daemon::agent_installation;
}
pub use cockpit_db as db;
mod terminal_host;

use anyhow::Context;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::time::Instant;

pub use crate::cli::public_v0_1_command;
use crate::cli::{Cli, Command};

pub mod manpages {
    use std::fs;
    use std::io;
    use std::path::{Path, PathBuf};

    use clap::Command;

    use crate::cli;

    pub fn generate_manpages(output_dir: impl AsRef<Path>) -> io::Result<()> {
        let output_dir = output_dir.as_ref();
        fs::create_dir_all(output_dir)?;

        let mut command = cli::public_v0_1_command();
        generate_command_page(&mut command, output_dir, &[String::from("cockpit")])
    }

    fn generate_command_page(
        command: &mut Command,
        output_dir: &Path,
        path: &[String],
    ) -> io::Result<()> {
        let page_name = path.join("-");
        command.set_bin_name(page_name.clone());

        let mut page = Vec::new();
        clap_mangen::Man::new(command.clone()).render(&mut page)?;
        fs::write(page_path(output_dir, &page_name), page)?;

        let subcommands: Vec<String> = command
            .get_subcommands()
            .filter(|subcommand| !subcommand.is_hide_set())
            .map(|subcommand| subcommand.get_name().to_owned())
            .collect();

        for subcommand_name in subcommands {
            if let Some(subcommand) = command.find_subcommand_mut(&subcommand_name) {
                let mut subcommand_path = path.to_vec();
                subcommand_path.push(subcommand_name);
                generate_command_page(subcommand, output_dir, &subcommand_path)?;
            }
        }

        Ok(())
    }

    fn page_path(output_dir: &Path, page_name: &str) -> PathBuf {
        output_dir.join(format!("{page_name}.1"))
    }
}

/// Narrow daemon API used by process-boundary integration tests.
///
/// This facade intentionally exposes typed operations instead of the daemon's
/// internal module tree, so integration tests can exercise the real socket
/// protocol without bypassing approval, authorization, or redaction paths.
pub mod integration {
    use std::path::Path;
    use std::time::Duration;

    use anyhow::{Result, anyhow};
    use uuid::Uuid;

    /// Typed socket client for the integration harness.
    #[derive(Clone)]
    pub struct DaemonClient {
        inner: cockpit_client::DaemonClient,
    }

    /// Stable subset of the daemon status response needed by harness tests.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct DaemonStatus {
        pub pid: u32,
        pub socket_path: String,
        pub protocol_version: u32,
        pub paused_sessions: u32,
        pub database_path: String,
        pub schema_version: i64,
    }

    /// Stable subset of the global caffeinate state broadcast.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct CaffeinateState {
        pub active: bool,
        pub lid_close_guaranteed: bool,
        pub message: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct AttachedSession {
        pub session_id: Uuid,
        pub history_len: usize,
        pub user_row_texts: Vec<String>,
        pub paused_work_len: usize,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct ReplayEntry {
        pub seq: i64,
        pub kind: &'static str,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum DaemonEvent {
        InterruptRaised {
            session_id: Uuid,
            interrupt_id: Uuid,
            reason: &'static str,
        },
        InterruptResolved {
            session_id: Uuid,
            interrupt_id: Uuid,
        },
        AgentIdle {
            session_id: Uuid,
            reason: String,
        },
        HistoryReplay {
            session_id: Uuid,
            max_seq: i64,
            entries: Vec<ReplayEntry>,
        },
        ToolStart {
            session_id: Uuid,
            call_id: String,
            tool: String,
        },
        ToolEnd {
            session_id: Uuid,
            call_id: String,
        },
        AssistantText {
            session_id: Uuid,
            text: String,
        },
        Notice {
            session_id: Uuid,
            text: String,
        },
        PausedWorkAvailable {
            session_id: Uuid,
            count: usize,
        },
        QueueUpdated {
            session_id: Uuid,
            texts: Vec<String>,
        },
        Other,
    }

    impl DaemonClient {
        pub async fn connect(socket: &Path) -> Result<Self> {
            Ok(Self {
                inner: cockpit_client::DaemonClient::connect(socket).await?,
            })
        }

        pub async fn attach(
            &self,
            project_root: &Path,
            session_id: Option<Uuid>,
            since_seq: Option<i64>,
            interactive: bool,
        ) -> Result<AttachedSession> {
            match self
                .inner
                .request_ok(crate::daemon::proto::Request::Attach {
                    session_id,
                    since_seq,
                    project_root: Some(project_root.display().to_string()),
                    initial_model: None,
                    no_sandbox: false,
                    interactive,
                    session_entry_mode: session_id
                        .is_none()
                        .then_some(crate::daemon::proto::SessionEntryMode::Code),
                    model_override: None,
                    client_protocol_version: self.inner.negotiated().version,
                    env_snapshot: None,
                    env_policy: crate::env_snapshot::EnvDriftPolicy::default(),
                })
                .await?
            {
                crate::daemon::proto::Response::Attached {
                    session_id,
                    history,
                    paused_work,
                    ..
                } => Ok(AttachedSession {
                    session_id,
                    history_len: history.len(),
                    user_row_texts: history
                        .iter()
                        .filter_map(|entry| match entry {
                            crate::daemon::proto::HistoryEntry::User {
                                text, display_text, ..
                            } => Some(
                                display_text
                                    .as_ref()
                                    .filter(|value| !value.is_empty())
                                    .unwrap_or(text)
                                    .clone(),
                            ),
                            _ => None,
                        })
                        .collect(),
                    paused_work_len: paused_work.len(),
                }),
                other => Err(anyhow!("unexpected attach response: {other:?}")),
            }
        }

        pub async fn send_user_message(&self, text: impl Into<String>) -> Result<()> {
            self.send_user_message_with_display(text, None, Vec::new())
                .await
        }

        pub async fn send_user_message_with_display(
            &self,
            text: impl Into<String>,
            display_text: Option<String>,
            tag_expansions: Vec<(String, String, String, bool)>,
        ) -> Result<()> {
            match self
                .inner
                .request_ok(crate::daemon::proto::Request::SendUserMessage {
                    expected_model_state_generation: None,
                    expected_model: None,
                    client_submission_id: Uuid::new_v4(),
                    text: text.into(),
                    display_text,
                    tag_expansions: tag_expansions
                        .into_iter()
                        .map(
                            |(tool, path, detail, ok)| crate::daemon::proto::TagExpansionMeta {
                                tool,
                                path,
                                detail,
                                ok,
                            },
                        )
                        .collect(),
                    image_refs: Vec::new(),
                    forced_skill: None,
                    run_invocation_options: None,
                })
                .await?
            {
                crate::daemon::proto::Response::Ack
                | crate::daemon::proto::Response::UserMessageQueued { .. } => Ok(()),
                other => Err(anyhow!("unexpected send_user_message response: {other:?}")),
            }
        }

        pub async fn approve_interrupt_once(&self, interrupt_id: Uuid) -> Result<()> {
            self.resolve_interrupt(
                interrupt_id,
                crate::daemon::proto::ResolveResponse::Single {
                    selected_id: crate::approval::ID_APPROVE_ONCE.to_string(),
                },
            )
            .await
        }

        pub async fn approve_interrupt_project(&self, interrupt_id: Uuid) -> Result<()> {
            self.resolve_interrupt(
                interrupt_id,
                crate::daemon::proto::ResolveResponse::Single {
                    selected_id: crate::approval::ID_APPROVE_PROJECT.to_string(),
                },
            )
            .await
        }

        pub async fn deny_interrupt(&self, interrupt_id: Uuid) -> Result<()> {
            self.resolve_interrupt(
                interrupt_id,
                crate::daemon::proto::ResolveResponse::Single {
                    selected_id: crate::approval::ID_REJECT.to_string(),
                },
            )
            .await
        }

        async fn resolve_interrupt(
            &self,
            interrupt_id: Uuid,
            response: crate::daemon::proto::ResolveResponse,
        ) -> Result<()> {
            match self
                .inner
                .request_ok(crate::daemon::proto::Request::ResolveInterrupt {
                    interrupt_id,
                    response,
                })
                .await?
            {
                crate::daemon::proto::Response::Ack => Ok(()),
                other => Err(anyhow!("unexpected resolve_interrupt response: {other:?}")),
            }
        }

        pub async fn status(&self) -> Result<DaemonStatus> {
            match self
                .inner
                .request_ok(crate::daemon::proto::Request::DaemonStatus)
                .await?
            {
                crate::daemon::proto::Response::DaemonStatus {
                    pid,
                    socket_path,
                    protocol_version,
                    paused_sessions,
                    database_path,
                    schema_version,
                    ..
                } => Ok(DaemonStatus {
                    pid,
                    socket_path,
                    protocol_version,
                    paused_sessions,
                    database_path,
                    schema_version,
                }),
                other => Err(anyhow!("unexpected daemon status response: {other:?}")),
            }
        }

        pub async fn stop(&self) -> Result<()> {
            match self
                .inner
                .request_ok(crate::daemon::proto::Request::StopDaemon { grace_secs: None })
                .await?
            {
                crate::daemon::proto::Response::Ack => Ok(()),
                other => Err(anyhow!("unexpected stop response: {other:?}")),
            }
        }

        pub async fn set_caffeinate(&self, active: bool) -> Result<CaffeinateState> {
            let mode = if active {
                crate::daemon::caffeinate::CaffeinateMode::On
            } else {
                crate::daemon::caffeinate::CaffeinateMode::Off
            };
            match self
                .inner
                .request_ok(crate::daemon::proto::Request::SetCaffeinate { mode })
                .await?
            {
                crate::daemon::proto::Response::CaffeinateState {
                    active,
                    lid_close_guaranteed,
                    message,
                } => Ok(CaffeinateState {
                    active,
                    lid_close_guaranteed,
                    message: Some(message),
                }),
                other => Err(anyhow!("unexpected caffeinate response: {other:?}")),
            }
        }

        pub async fn next_caffeinate_state(&self, timeout: Duration) -> Result<CaffeinateState> {
            loop {
                let event = tokio::time::timeout(timeout, self.inner.next_event())
                    .await
                    .map_err(|_| anyhow!("timed out waiting for caffeinate event"))?
                    .ok_or_else(|| anyhow!("daemon event stream closed"))?;
                if let crate::daemon::proto::Event::CaffeinateState {
                    active,
                    lid_close_guaranteed,
                    message,
                } = event
                {
                    return Ok(CaffeinateState {
                        active,
                        lid_close_guaranteed,
                        message,
                    });
                }
            }
        }

        pub async fn next_event(&self, timeout: Duration) -> Result<DaemonEvent> {
            let event = tokio::time::timeout(timeout, self.inner.next_event())
                .await
                .map_err(|_| anyhow!("timed out waiting for daemon event"))?
                .ok_or_else(|| anyhow!("daemon event stream closed"))?;
            Ok(map_event(event))
        }

        pub fn is_socket_backed(&self) -> bool {
            self.inner.is_socket_backed()
        }
    }

    fn map_event(event: crate::daemon::proto::Event) -> DaemonEvent {
        match event {
            crate::daemon::proto::Event::InterruptRaised {
                session_id,
                interrupt_id,
                reason,
                ..
            } => DaemonEvent::InterruptRaised {
                session_id,
                interrupt_id,
                reason: match reason {
                    crate::daemon::proto::InterruptRaiseReason::Initial => "initial",
                    crate::daemon::proto::InterruptRaiseReason::Advance => "advance",
                    crate::daemon::proto::InterruptRaiseReason::Rehydration => "rehydration",
                },
            },
            crate::daemon::proto::Event::InterruptResolved {
                session_id,
                interrupt_id,
                ..
            } => DaemonEvent::InterruptResolved {
                session_id,
                interrupt_id,
            },
            crate::daemon::proto::Event::AgentIdle {
                session_id, reason, ..
            } => DaemonEvent::AgentIdle {
                session_id,
                reason: idle_reason_string(reason),
            },
            crate::daemon::proto::Event::HistoryReplay {
                session_id,
                entries,
                max_seq,
            } => DaemonEvent::HistoryReplay {
                session_id,
                max_seq,
                entries: entries
                    .iter()
                    .map(|entry| ReplayEntry {
                        seq: history_entry_seq(entry),
                        kind: history_entry_kind(entry),
                    })
                    .collect(),
            },
            crate::daemon::proto::Event::ToolStart {
                session_id,
                call_id,
                tool,
                ..
            } => DaemonEvent::ToolStart {
                session_id,
                call_id,
                tool,
            },
            crate::daemon::proto::Event::ToolEnd {
                session_id,
                call_id,
                ..
            } => DaemonEvent::ToolEnd {
                session_id,
                call_id,
            },
            crate::daemon::proto::Event::AssistantText {
                session_id, text, ..
            } => DaemonEvent::AssistantText { session_id, text },
            crate::daemon::proto::Event::Notice { session_id, text } => {
                DaemonEvent::Notice { session_id, text }
            }
            crate::daemon::proto::Event::CommandCapabilityUnavailable {
                session_id, text, ..
            } => DaemonEvent::Notice { session_id, text },
            crate::daemon::proto::Event::PausedWorkAvailable { session_id, items } => {
                DaemonEvent::PausedWorkAvailable {
                    session_id,
                    count: items.len(),
                }
            }
            crate::daemon::proto::Event::QueueUpdated { session_id, queue } => {
                DaemonEvent::QueueUpdated {
                    session_id,
                    texts: queue.into_iter().map(|item| item.text).collect(),
                }
            }
            _ => DaemonEvent::Other,
        }
    }

    fn idle_reason_string(reason: crate::engine::IdleReason) -> String {
        match reason {
            crate::engine::IdleReason::Completed => "completed".to_string(),
            crate::engine::IdleReason::GoalComplete => "goal_complete".to_string(),
            crate::engine::IdleReason::NeedsIntervention { code } => {
                format!("needs_intervention:{code}")
            }
            crate::engine::IdleReason::BudgetLimited => "budget_limited".to_string(),
            crate::engine::IdleReason::UsageLimited => "usage_limited".to_string(),
            crate::engine::IdleReason::Error { class } => format!("error:{class}"),
            crate::engine::IdleReason::Interrupted => "interrupted".to_string(),
        }
    }

    fn history_entry_seq(entry: &crate::daemon::proto::HistoryEntry) -> i64 {
        match entry {
            crate::daemon::proto::HistoryEntry::InterruptDecision { seq, .. }
            | crate::daemon::proto::HistoryEntry::User { seq, .. }
            | crate::daemon::proto::HistoryEntry::UserNote { seq, .. }
            | crate::daemon::proto::HistoryEntry::Assistant { seq, .. }
            | crate::daemon::proto::HistoryEntry::ToolCall { seq, .. }
            | crate::daemon::proto::HistoryEntry::InferenceError { seq, .. }
            | crate::daemon::proto::HistoryEntry::CompactBoundary { seq, .. }
            | crate::daemon::proto::HistoryEntry::Subagent { seq, .. } => *seq,
        }
    }

    fn history_entry_kind(entry: &crate::daemon::proto::HistoryEntry) -> &'static str {
        match entry {
            crate::daemon::proto::HistoryEntry::InterruptDecision { .. } => "interrupt_decision",
            crate::daemon::proto::HistoryEntry::User { .. } => "user",
            crate::daemon::proto::HistoryEntry::UserNote { .. } => "user_note",
            crate::daemon::proto::HistoryEntry::Assistant { .. } => "assistant",
            crate::daemon::proto::HistoryEntry::ToolCall { .. } => "tool_call",
            crate::daemon::proto::HistoryEntry::InferenceError { .. } => "inference_error",
            crate::daemon::proto::HistoryEntry::CompactBoundary { .. } => "compact_boundary",
            crate::daemon::proto::HistoryEntry::Subagent { .. } => "subagent",
        }
    }
}

pub fn main_entry() -> ExitCode {
    if invoked_as_jq() {
        return commands::jq::run_from_argv0();
    }

    let launch_start = Instant::now();

    // Sandboxing part 2: dispatch the zerobox Linux sandbox helper and
    // install the PATH-prepend alias BEFORE the tokio runtime starts.
    tools::shell_sandbox::init();
    terminal_host::install_factory();

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_stack_size(cockpit_core::daemon::session_worker::TOKIO_WORKER_STACK_SIZE)
        .max_blocking_threads(16)
        .build();
    let result = match runtime {
        Ok(runtime) => runtime.block_on(async_main(launch_start)),
        Err(err) => Err(anyhow::Error::new(err)),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("{}", error_stderr_line(&err));
            ExitCode::from(error_exit_code(&err))
        }
    }
}

fn invoked_as_jq() -> bool {
    std::env::args_os()
        .next()
        .and_then(|arg0| {
            Path::new(&arg0)
                .file_stem()
                .map(|stem| stem.to_string_lossy().into_owned())
        })
        .as_deref()
        == Some("jq")
}

fn error_exit_code(err: &anyhow::Error) -> u8 {
    if err.is::<commands::doctor::DoctorCouldNotRun>() {
        2
    } else if err.is::<commands::doctor::DoctorChecksFailed>() {
        1
    } else if err.is::<commands::RemovedCommandError>() {
        commands::REMOVED_COMMAND_EXIT_CODE
    } else if err.is::<commands::CommandUsageError>() {
        commands::USAGE_EXIT_CODE
    } else if let Some(error) = err.downcast_ref::<commands::agent::AgentCommandError>() {
        error.exit_code()
    } else {
        1
    }
}

async fn install_cli_trust_policy(project: Option<&Path>) -> anyhow::Result<()> {
    let opened = match project {
        Some(path) => path.to_path_buf(),
        None => std::env::current_dir().context("resolving workspace for trust policy")?,
    };
    let root = config::trust::resolve_trust_root(&opened)?;
    let daemon = daemon::client::ensure_persistent_daemon()
        .await
        .context("starting persistent daemon for workspace trust")?;
    let project_root = root.root.display().to_string();
    let response = daemon
        .client
        .request(daemon::proto::Request::GetWorkspaceTrust {
            project_root: project_root.clone(),
        })
        .await
        .context("requesting workspace trust")?
        .map_err(|error| anyhow::anyhow!("daemon rejected workspace trust read: {error}"))?;
    let (stored_mode, config_generation) = match response {
        daemon::proto::Response::WorkspaceTrust {
            mode,
            config_generation,
        } => (mode, config_generation),
        other => anyhow::bail!("daemon returned unexpected workspace trust response: {other:?}"),
    };
    let mode = match stored_mode {
        Some(daemon::proto::WorkspaceTrustMode::Trust) => {
            db::workspace_trust::WorkspaceTrustMode::Trust
        }
        Some(daemon::proto::WorkspaceTrustMode::IgnoreConfig) => {
            db::workspace_trust::WorkspaceTrustMode::IgnoreConfig
        }
        Some(daemon::proto::WorkspaceTrustMode::Untrusted) | None => {
            db::workspace_trust::WorkspaceTrustMode::IgnoreConfig
        }
    };
    if stored_mode.is_none() {
        let response = daemon
            .client
            .request(daemon::proto::Request::SetWorkspaceTrust {
                project_root,
                mode: daemon::proto::WorkspaceTrustMode::IgnoreConfig,
                expected_config_generation: config_generation,
            })
            .await
            .context("persisting default workspace trust")?
            .map_err(|error| anyhow::anyhow!("daemon rejected workspace trust persist: {error}"))?;
        if !matches!(response, daemon::proto::Response::WorkspaceTrustSet { .. }) {
            anyhow::bail!(
                "daemon returned unexpected workspace trust persist response: {response:?}"
            );
        }
    }
    config::trust::set_runtime_policy(root, mode);
    Ok(())
}

fn command_requires_workspace_trust(command: Option<&Command>) -> bool {
    // These commands attach or spawn the daemon they actually use. Do not
    // auto-promote a persistent instance here just to seed workspace trust;
    // the owned-daemon path seeds IgnoreConfig on that daemon when no row
    // exists.
    if matches!(
        command,
        Some(Command::Run(args)) if args.ephemeral
    ) || matches!(
        command,
        Some(Command::Init(_)) | Some(Command::Assistants(crate::cli::AssistantCommand::Learn(_)))
    ) {
        return false;
    }
    !matches!(
        command,
        Some(Command::Debug(_))
            | Some(Command::Doctor(_))
            | Some(Command::Invocation(_))
            | Some(Command::Daemon(
                crate::cli::DaemonCommand::Status { .. }
                    | crate::cli::DaemonCommand::Start { .. }
                    | crate::cli::DaemonCommand::Stop { .. }
                    | crate::cli::DaemonCommand::Restart { .. }
                    | crate::cli::DaemonCommand::DiagnosticSnapshot { .. }
                    | crate::cli::DaemonCommand::DiagnosticFailedCalls { .. }
            ))
            | Some(Command::Trust(_))
            | Some(Command::Jq(_))
            | Some(Command::Completion { .. })
            | Some(Command::BashHints(_))
            | Some(Command::Agent(
                crate::cli::AgentCommand::Install { .. }
                    | crate::cli::AgentCommand::Update { .. }
                    | crate::cli::AgentCommand::Bind { .. }
                    | crate::cli::AgentCommand::SubmitChoice { .. }
                    | crate::cli::AgentCommand::Inspect { .. }
                    | crate::cli::AgentCommand::Create { .. }
                    | crate::cli::AgentCommand::List { .. }
            ))
            | Some(Command::Mcp(
                crate::cli::McpCommand::Add(_) | crate::cli::McpCommand::List
            ))
    )
}

fn error_stderr_line(err: &anyhow::Error) -> String {
    if let Some(removed) = err.downcast_ref::<commands::RemovedCommandError>() {
        format!("error: {}", removed.message())
    } else if let Some(usage) = err.downcast_ref::<commands::CommandUsageError>() {
        format!("error: {}", usage.message())
    } else {
        format!("Error: {err:?}")
    }
}

async fn async_main(launch_start: Instant) -> anyhow::Result<()> {
    use clap::FromArgMatches as _;
    let cli: crate::cli::Cli =
        crate::cli::PublicCli::from_arg_matches(&crate::cli::public_v0_1_command().get_matches())?
            .into();

    init_tracing(cli.log_level.as_deref(), cli.print_logs);

    if cli.debug_last_message {
        match std::env::current_dir() {
            Ok(cwd) => engine::model::enable_debug_last_message(cwd.join(".lastmessage")),
            Err(e) => tracing::warn!(error = %e, "--debug-last-message: cwd unavailable"),
        }
    }

    if command_requires_workspace_trust(cli.command.as_ref()) {
        install_cli_trust_policy(cli.project.as_deref()).await?;
    }

    if let Some(mode) = tui_mode_for_command(cli.command.as_ref()) {
        return commands::tui::run_mode(
            cli.project.as_deref(),
            cli.no_sandbox,
            mode,
            Some(launch_start),
        )
        .await;
    }

    match cli.command {
        Some(Command::Ask(args)) => commands::ask::run(args).await,
        Some(Command::Run(args)) => {
            commands::run::run(args, cli.no_sandbox, cli.project.as_deref()).await
        }
        Some(Command::Invocation(sub)) => commands::invocation::run(sub).await,
        Some(Command::Agent(sub)) => commands::agent::run(sub).await,
        Some(Command::Assistants(sub)) => {
            commands::assistant::run(sub, cli.no_sandbox, Some(launch_start)).await
        }
        #[cfg(feature = "remote")]
        Some(Command::Account(sub)) => match sub {
            crate::cli::AccountCommand::Login(args) => commands::flycockpit::login(args).await,
            crate::cli::AccountCommand::Logout => commands::flycockpit::logout().await,
            crate::cli::AccountCommand::Whoami => commands::flycockpit::whoami().await,
        },
        Some(Command::Provider(sub)) => commands::providers::run(sub).await,
        Some(Command::Setup(args)) => commands::setup::run(args).await,
        Some(Command::Models(args)) => commands::models::run(args).await,
        Some(Command::ProviderCatalogStatus(args)) => {
            commands::models::run_provider_catalog_status(args).await
        }
        Some(Command::FetchModels(args)) => commands::fetch_models::run(args).await,
        Some(Command::Jq(args)) => commands::jq::run(args).await,
        Some(Command::Daemon(sub)) => commands::daemon::run(sub).await,
        Some(Command::Doctor(args)) => commands::doctor::run(args, cli.no_sandbox).await,
        Some(Command::Session(sub)) => commands::session::run(sub).await,
        #[cfg(feature = "extended")]
        Some(Command::Schedule(sub)) => commands::schedule::run(sub).await,
        Some(Command::Skill(sub)) => commands::skill::run(sub).await,
        Some(Command::Trust(sub)) => commands::trust::run(sub).await,
        Some(Command::Export(args)) => commands::export::run(args).await,
        Some(Command::Import(args)) => commands::import::run(args).await,
        Some(Command::Stats(args)) => commands::stats::run(args).await,
        Some(Command::Debug(sub)) => commands::debug::run(sub).await,
        Some(Command::Config(sub)) => commands::config::run(sub).await,
        Some(Command::Mcp(cmd)) => commands::mcp::run(cmd).await,
        #[cfg(feature = "remote")]
        Some(Command::Login(_)) => Err(commands::RemovedCommandError::new("login").into()),
        #[cfg(feature = "remote")]
        Some(Command::Logout) => Err(commands::RemovedCommandError::new("logout").into()),
        #[cfg(feature = "remote")]
        Some(Command::Whoami) => Err(commands::RemovedCommandError::new("whoami").into()),
        #[cfg(feature = "remote")]
        Some(Command::Sync(sub)) => commands::sync::run(sub).await,
        #[cfg(feature = "remote")]
        Some(Command::Connect(args)) => commands::connect::run(args).await,
        Some(Command::Packages(sub)) => commands::packages::run(sub).await,
        Some(Command::Kcl(sub)) => commands::kcl::run(sub).await,
        Some(Command::Init(args)) => commands::init::run(args, cli.no_sandbox).await,
        Some(Command::BashHints(sub)) => commands::bash_hints::run(sub).await,
        Some(Command::Completion { shell }) => {
            clap_complete::generate(
                shell,
                &mut crate::cli::public_v0_1_command(),
                "cockpit",
                &mut std::io::stdout(),
            );
            Ok(())
        }
        None | Some(Command::Code | Command::Assistant | Command::Computer) => {
            unreachable!("interactive mode commands return through tui_mode_for_command")
        }
    }
}

fn tui_mode_for_command(command: Option<&Command>) -> Option<commands::tui::SessionMode> {
    match command {
        None | Some(Command::Code) => Some(commands::tui::SessionMode::Code),
        Some(Command::Assistant) => Some(commands::tui::SessionMode::Assistant),
        Some(Command::Computer) => Some(commands::tui::SessionMode::Computer),
        _ => None,
    }
}

fn init_tracing(level: Option<&str>, print_logs: bool) {
    use tracing_subscriber::{EnvFilter, fmt};

    let filter = match level {
        Some(l) => EnvFilter::try_new(l).unwrap_or_else(|_| EnvFilter::new("warn")),
        None => EnvFilter::try_from_env("COCKPIT_LOG").unwrap_or_else(|_| EnvFilter::new("warn")),
    };

    if print_logs {
        fmt()
            .with_env_filter(filter)
            .with_writer(std::io::stderr)
            .init();
        return;
    }

    match open_log_file() {
        Some(file) => {
            fmt()
                .with_env_filter(filter)
                .with_ansi(false)
                .with_writer(file)
                .init();
        }
        None => {
            fmt()
                .with_env_filter(filter)
                .with_writer(std::io::sink)
                .init();
        }
    }
}

const LOG_FILE_MAX_BYTES: u64 = 1024 * 1024;
const LOG_BACKUP_COUNT: usize = 2;

#[derive(Clone)]
struct RotatingLog {
    state: Arc<Mutex<RotatingLogState>>,
}
struct RotatingLogState {
    dir: PathBuf,
    file: std::fs::File,
    len: u64,
}
struct RotatingLogWriter {
    state: Arc<Mutex<RotatingLogState>>,
}

impl tracing_subscriber::fmt::MakeWriter<'_> for RotatingLog {
    type Writer = RotatingLogWriter;
    fn make_writer(&self) -> Self::Writer {
        RotatingLogWriter {
            state: Arc::clone(&self.state),
        }
    }
}
impl Write for RotatingLogWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| std::io::Error::other("log writer lock poisoned"))?;
        let mut remaining = bytes;
        while !remaining.is_empty() {
            if state.len >= LOG_FILE_MAX_BYTES {
                rotate_log_state(&mut state)?;
            }
            let available = (LOG_FILE_MAX_BYTES - state.len) as usize;
            let written = state
                .file
                .write(&remaining[..remaining.len().min(available)])?;
            if written == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "log writer wrote zero bytes",
                ));
            }
            state.len += written as u64;
            remaining = &remaining[written..];
        }
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.state
            .lock()
            .map_err(|_| std::io::Error::other("log writer lock poisoned"))?
            .file
            .flush()
    }
}

fn open_log_file() -> Option<RotatingLog> {
    open_log_file_at(dirs::cache_dir()?.join("cockpit"))
}
fn open_log_file_at(dir: PathBuf) -> Option<RotatingLog> {
    // Logging stays non-fatal: an insecure cache directory disables logging
    // rather than aborting the CLI, but the typed error is logged, not
    // silently discarded.
    if let Err(error) = cockpit_host::private_fs::ensure_private_dir(&dir) {
        tracing::warn!(%error, dir = %dir.display(), "log directory could not be secured; logging disabled");
        return None;
    }
    let path = dir.join("cockpit.log");
    let file = open_private_append(&path).ok()?;
    let len = file.metadata().ok()?.len();
    Some(RotatingLog {
        state: Arc::new(Mutex::new(RotatingLogState { dir, file, len })),
    })
}
fn rotate_log_state(state: &mut RotatingLogState) -> std::io::Result<()> {
    state.file.flush()?;
    #[cfg(unix)]
    {
        // Hold the log directory ONCE through the no-follow component walk, then
        // do the entire rotation (unlinkat/renameat) AND the re-open through that
        // single held fd. An attacker who swaps the log-directory entry with a
        // symlink between steps cannot redirect the deletes/renames/open into an
        // attacker-selected directory, because nothing is re-resolved by name.
        let dir_fd = cockpit_host::private_fs::open_private_dir_handle(&state.dir)
            .map_err(std::io::Error::other)?;
        rotate_log_files_fd(&dir_fd)?;
        state.file = cockpit_host::private_fs::open_private_file_in_dir_fd(
            &dir_fd,
            std::ffi::OsStr::new("cockpit.log"),
            cockpit_host::private_fs::PrivateFileAccess::Append,
            "cockpit log",
        )
        .map_err(std::io::Error::other)?;
    }
    #[cfg(not(unix))]
    {
        rotate_log_files(&state.dir)?;
        let path = state.dir.join("cockpit.log");
        state.file = open_private_append(&path)?;
    }
    state.len = 0;
    Ok(())
}

/// Fd-anchored rotation: unlink the oldest backup and shift each remaining
/// backup up by one, all via `unlinkat`/`renameat` relative to the held log
/// directory fd. A missing entry (`ENOENT`) is tolerated; any other error
/// propagates. No pathname is resolved, so an entry-swap cannot redirect it.
#[cfg(unix)]
fn rotate_log_files_fd(dir_fd: &std::fs::File) -> std::io::Result<()> {
    use std::ffi::CString;
    use std::os::fd::AsRawFd;

    let tolerate_enoent = |result: i32| -> std::io::Result<()> {
        if result == 0 {
            return Ok(());
        }
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::NotFound {
            Ok(())
        } else {
            Err(error)
        }
    };
    let cname = |name: String| -> std::io::Result<CString> {
        CString::new(name).map_err(|_| std::io::Error::other("log entry name contains NUL"))
    };

    let oldest = cname(format!("cockpit.log.{LOG_BACKUP_COUNT}"))?;
    tolerate_enoent(unsafe { libc::unlinkat(dir_fd.as_raw_fd(), oldest.as_ptr(), 0) })?;
    for index in (1..LOG_BACKUP_COUNT).rev() {
        let from = cname(format!("cockpit.log.{index}"))?;
        let to = cname(format!("cockpit.log.{}", index + 1))?;
        tolerate_enoent(unsafe {
            libc::renameat(
                dir_fd.as_raw_fd(),
                from.as_ptr(),
                dir_fd.as_raw_fd(),
                to.as_ptr(),
            )
        })?;
    }
    let current = cname("cockpit.log".to_string())?;
    let first = cname("cockpit.log.1".to_string())?;
    tolerate_enoent(unsafe {
        libc::renameat(
            dir_fd.as_raw_fd(),
            current.as_ptr(),
            dir_fd.as_raw_fd(),
            first.as_ptr(),
        )
    })?;
    Ok(())
}

#[cfg(not(unix))]
fn rotate_log_files(dir: &Path) -> std::io::Result<()> {
    let oldest = dir.join(format!("cockpit.log.{}", LOG_BACKUP_COUNT));
    if oldest.exists() {
        std::fs::remove_file(&oldest)?;
    }
    for index in (1..LOG_BACKUP_COUNT).rev() {
        let from = dir.join(format!("cockpit.log.{index}"));
        if from.exists() {
            std::fs::rename(&from, dir.join(format!("cockpit.log.{}", index + 1)))?;
        }
    }
    let current = dir.join("cockpit.log");
    if current.exists() {
        std::fs::rename(current, dir.join("cockpit.log.1"))?;
    }
    Ok(())
}
#[cfg(unix)]
fn open_private_append(path: &Path) -> std::io::Result<std::fs::File> {
    // No-follow funnel: openat(O_APPEND|O_NOFOLLOW, no O_TRUNC) anchored to the
    // held, verified 0700 log directory fd + held-fd fchmod 0600, instead of a
    // path-following open + path chmod a planted symlink could redirect.
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .ok_or_else(|| std::io::Error::other("log path has no file name"))?;
    cockpit_host::private_fs::open_private_file_at(
        parent,
        name,
        cockpit_host::private_fs::PrivateFileAccess::Append,
        "cockpit log",
    )
    .map_err(std::io::Error::other)
}
#[cfg(not(unix))]
fn open_private_append(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
}

#[cfg(test)]
mod production_path_ratchet;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lib_trust_policy_does_not_open_db() {
        let source = include_str!("lib.rs");
        let production = source
            .split("mod tests {")
            .next()
            .expect("production lib.rs");
        assert!(
            !production.contains("Db::open_default"),
            "install_cli_trust_policy must not open SQLite"
        );
        assert!(production.contains("GetWorkspaceTrust"));
        assert!(production.contains("SetWorkspaceTrust"));
        assert!(!production.contains("GetStartupDisclosures"));
    }

    #[test]
    fn get_workspace_trust_exists_and_is_used_by_lib() {
        assert!(
            include_str!("lib.rs").contains("GetWorkspaceTrust"),
            "lib trust policy must consume GetWorkspaceTrust"
        );
        let proto = include_str!("../../../crates/cockpit-proto/src/request.rs");
        assert!(
            proto.contains("GetWorkspaceTrust"),
            "GetWorkspaceTrust must exist as an owner RPC"
        );
        let disclosures =
            include_str!("../../../crates/cockpit-core/src/daemon/server/dispatch.rs");
        let get_startup = disclosures
            .split("Request::GetStartupDisclosures")
            .nth(1)
            .expect("GetStartupDisclosures handler remains");
        assert!(
            get_startup.contains("org_sync") && get_startup.contains("connector"),
            "GetStartupDisclosures stays org-sync/connector/config generation only"
        );
        assert!(
            !get_startup
                .split("Request::")
                .next()
                .unwrap_or("")
                .contains("workspace_trust_by_root"),
            "GetStartupDisclosures must not become the trust read"
        );
    }

    #[tokio::test]
    async fn trust_free_commands_do_not_prompt() {
        let tmp = tempfile::tempdir().unwrap();
        let _env = crate::test_env::lock_async().await;
        _env.set_var("XDG_DATA_HOME", tmp.path().join("data"));
        _env.set_var("XDG_STATE_HOME", tmp.path().join("state"));
        _env.set_var("XDG_RUNTIME_DIR", tmp.path().join("runtime"));
        crate::config::trust::clear_runtime_policy_for_tests();

        let _ctx = crate::daemon::boot_test_persistent_daemon()
            .await
            .expect("boot trust-policy daemon");
        install_cli_trust_policy(Some(tmp.path())).await.unwrap();
        assert_eq!(
            crate::config::trust::runtime_policy().unwrap().mode,
            db::workspace_trust::WorkspaceTrustMode::IgnoreConfig
        );
        crate::config::trust::clear_runtime_policy_for_tests();
    }

    #[test]
    fn debug_commands_are_diagnostic_and_do_not_initialize_trust_storage() {
        assert!(!command_requires_workspace_trust(Some(&Command::Debug(
            crate::cli::DebugCommand::Paths,
        ))));
        assert!(!command_requires_workspace_trust(Some(&Command::Debug(
            crate::cli::DebugCommand::Config,
        ))));
        assert!(!command_requires_workspace_trust(Some(&Command::Debug(
            crate::cli::DebugCommand::Context,
        ))));
        assert!(!command_requires_workspace_trust(Some(&Command::Debug(
            crate::cli::DebugCommand::FailedCalls(crate::cli::FailedCallsArgs {
                days: 7,
                tool: None,
                model: None,
                project: None,
                limit: 50,
                include_recovered: false,
                json: false,
            }),
        ))));
        assert!(command_requires_workspace_trust(None));
    }

    #[test]
    fn modes_session_setup_cli_entries_share_one_tui_dispatch_mapping() {
        use crate::commands::tui::SessionMode;

        assert_eq!(tui_mode_for_command(None), Some(SessionMode::Code));
        assert_eq!(
            tui_mode_for_command(Some(&Command::Code)),
            Some(SessionMode::Code)
        );
        assert_eq!(
            tui_mode_for_command(Some(&Command::Assistant)),
            Some(SessionMode::Assistant)
        );
        assert_eq!(
            tui_mode_for_command(Some(&Command::Computer)),
            Some(SessionMode::Computer)
        );
        assert_eq!(
            tui_mode_for_command(Some(&Command::Jq(crate::cli::JqArgs { args: Vec::new() }))),
            None
        );
    }

    #[test]
    fn file_only_commands_do_not_require_workspace_trust() {
        assert!(!command_requires_workspace_trust(Some(&Command::Jq(
            crate::cli::JqArgs { args: Vec::new() }
        ))));
        assert!(!command_requires_workspace_trust(Some(
            &Command::BashHints(crate::cli::BashHintsCommand::List)
        )));
        assert!(!command_requires_workspace_trust(Some(&Command::Agent(
            crate::cli::AgentCommand::List {
                scope: None,
                workspace: None,
                json: false,
            }
        ))));
        assert!(!command_requires_workspace_trust(Some(&Command::Mcp(
            crate::cli::McpCommand::List
        ))));
        assert!(!command_requires_workspace_trust(Some(&Command::Doctor(
            crate::cli::DoctorArgs {
                path: None,
                offline: false,
                dependencies_json: false,
            }
        ))));
        assert!(!command_requires_workspace_trust(Some(&Command::Init(
            crate::cli::InitArgs {
                path: None,
                force: false,
                ephemeral: false,
            }
        ))));
        assert!(!command_requires_workspace_trust(Some(
            &Command::Assistants(crate::cli::AssistantCommand::Learn(crate::cli::LearnArgs {
                sources: vec!["https://example.test".into()],
                ephemeral: false,
            }))
        )));
        assert!(!command_requires_workspace_trust(Some(&Command::Run(
            crate::cli::RunArgs {
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
                format: crate::cli::OutputFormat::Default,
                json: false,
                verbose: false,
                follow: false,
                file: Vec::new(),
                thinking: false,
                ephemeral: true,
                max_turns: None,
                timeout: None,
                permission_mode: None,
            }
        ))));
    }

    #[test]
    fn usage_errors_map_to_exit_64_and_lowercase_error_prefix() {
        let err = anyhow::Error::new(commands::CommandUsageError::new(
            "a session identifier (`short_id` or UUID) is required",
        ));

        assert_eq!(error_exit_code(&err), commands::USAGE_EXIT_CODE);
        assert_eq!(
            error_stderr_line(&err),
            "error: a session identifier (`short_id` or UUID) is required"
        );
    }

    #[test]
    fn ordinary_errors_keep_default_exit_and_prefix() {
        let err = anyhow::anyhow!("boom");

        assert_eq!(error_exit_code(&err), 1);
        assert_eq!(error_stderr_line(&err), "Error: boom");
    }

    #[test]
    fn removed_login_stub_points_and_exits_2() {
        let err = anyhow::Error::new(commands::RemovedCommandError::new("login"));

        assert_eq!(error_exit_code(&err), commands::REMOVED_COMMAND_EXIT_CODE);
        let line = error_stderr_line(&err);
        assert!(line.contains("`cockpit login` was split"), "{line}");
        assert!(line.contains("`cockpit account login`"), "{line}");
        assert!(line.contains("`cockpit provider add`"), "{line}");
    }
    #[cfg(unix)]
    #[test]
    fn log_file_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let file = open_log_file_at(dir.path().join("cockpit")).unwrap();
        drop(file);
        let mode = std::fs::metadata(dir.path().join("cockpit").join("cockpit.log"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn log_rotation_bounds_total_size() {
        let dir = tempfile::tempdir().unwrap();
        let log_dir = dir.path().join("cockpit");
        std::fs::create_dir_all(&log_dir).unwrap();
        std::fs::write(
            log_dir.join("cockpit.log"),
            vec![b'x'; LOG_FILE_MAX_BYTES as usize],
        )
        .unwrap();
        std::fs::write(
            log_dir.join("cockpit.log.1"),
            vec![b'y'; LOG_FILE_MAX_BYTES as usize],
        )
        .unwrap();
        let log = open_log_file_at(log_dir.clone()).unwrap();
        let mut writer = tracing_subscriber::fmt::MakeWriter::make_writer(&log);
        writer.write_all(b"z").unwrap();
        drop(writer);
        assert_eq!(
            std::fs::read(log_dir.join("cockpit.log.1")).unwrap().len() as u64,
            LOG_FILE_MAX_BYTES
        );
        assert_eq!(
            std::fs::read(log_dir.join("cockpit.log.2")).unwrap().len() as u64,
            LOG_FILE_MAX_BYTES
        );
        let total: u64 = (0..=LOG_BACKUP_COUNT)
            .map(|index| {
                let path = if index == 0 {
                    log_dir.join("cockpit.log")
                } else {
                    log_dir.join(format!("cockpit.log.{index}"))
                };
                path.metadata().map(|meta| meta.len()).unwrap_or(0)
            })
            .sum();
        assert!(total <= LOG_FILE_MAX_BYTES * (LOG_BACKUP_COUNT as u64 + 1));
    }

    // FINDING B: rotation is fd-anchored. Given a held directory fd, the shift
    // happens via unlinkat/renameat relative to that fd (no pathname lookup).
    #[cfg(unix)]
    #[test]
    fn log_rotation_is_fd_anchored() {
        let dir = tempfile::tempdir().unwrap();
        let log_dir = dir.path().join("cockpit");
        std::fs::create_dir_all(&log_dir).unwrap();
        std::fs::write(log_dir.join("cockpit.log"), b"CURRENT").unwrap();
        std::fs::write(log_dir.join("cockpit.log.1"), b"BACKUP-1").unwrap();

        let dir_fd = cockpit_host::private_fs::open_private_dir_handle(&log_dir).unwrap();
        rotate_log_files_fd(&dir_fd).unwrap();

        assert_eq!(
            std::fs::read(log_dir.join("cockpit.log.1")).unwrap(),
            b"CURRENT",
            "current log must shift to .1"
        );
        assert_eq!(
            std::fs::read(log_dir.join("cockpit.log.2")).unwrap(),
            b"BACKUP-1",
            ".1 must shift to .2"
        );
        assert!(
            !log_dir.join("cockpit.log").exists(),
            "the current log name must be free for the fresh re-open"
        );
    }

    // FINDING B: an attacker who swaps the log-directory entry with a symlink
    // must not get rotation/logging to operate inside the symlink's target. The
    // no-follow directory resolution refuses it, so log setup returns None
    // (logging disabled) and the victim directory is left untouched.
    #[cfg(unix)]
    #[test]
    fn log_setup_refuses_symlinked_log_dir() {
        use std::os::unix::fs::PermissionsExt;

        let root = tempfile::tempdir().unwrap();
        let victim = root.path().join("victim-logs");
        std::fs::create_dir(&victim).unwrap();
        std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(victim.join("cockpit.log.1"), b"VICTIM-BACKUP").unwrap();

        // The path cockpit is told to use is a symlink to the victim directory.
        let link = root.path().join("cockpit");
        std::os::unix::fs::symlink(&victim, &link).unwrap();

        assert!(
            open_log_file_at(link).is_none(),
            "a symlinked log directory must disable logging, not follow the swap"
        );
        assert_eq!(
            std::fs::read(victim.join("cockpit.log.1")).unwrap(),
            b"VICTIM-BACKUP",
            "the victim directory must be untouched"
        );
        assert!(
            !victim.join("cockpit.log").exists(),
            "no log file may be created inside the victim"
        );
    }
}
