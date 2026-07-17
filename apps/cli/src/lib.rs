//! Library entry points for the `cockpit` binary and integration tests.
//!
//! Most product logic still lives in the per-subcommand modules. The library
//! target exists so process-boundary tests can exercise the daemon protocol
//! without duplicating wire types.

mod agents;
mod approval;
mod auth;
mod auto_title;
mod banner;
mod browser;
mod cli;
mod clipboard;
mod commands;
pub use cockpit_config as config;
mod container;
mod credentials;
mod daemon;
pub use cockpit_db as db;
mod diagnostics;
pub mod embeddings;
mod engine;
mod env_snapshot;
mod envref;
mod git;
mod gitignore;
mod harness;
mod intel;
mod locks;
mod mcp;
mod model_system_prompt;
mod packages;
mod private_fs;
mod process;
mod providers;
mod redact;
mod secret_ref;
mod session;
mod skills;
mod startup;
mod sync;
mod sysinfo;
#[cfg(test)]
mod test_env;
mod text;
mod tokens;
mod tools;
mod tui;
pub mod user_agent;
mod welcome;
pub mod wizard;

use clap::Parser;
use std::process::ExitCode;

use crate::cli::{Cli, Command};

pub mod manpages {
    use std::fs;
    use std::io;
    use std::path::{Path, PathBuf};

    use clap::{Command, CommandFactory};

    use crate::cli::Cli;

    pub fn generate_manpages(output_dir: impl AsRef<Path>) -> io::Result<()> {
        let output_dir = output_dir.as_ref();
        fs::create_dir_all(output_dir)?;

        let mut command = Cli::command();
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
        inner: crate::daemon::client::DaemonClient,
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
                inner: crate::daemon::client::DaemonClient::connect(socket).await?,
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
                    no_sandbox: false,
                    interactive,
                    model_override: None,
                    client_protocol_version: crate::daemon::proto::PROTOCOL_VERSION,
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
            crate::daemon::proto::HistoryEntry::Assistant { .. } => "assistant",
            crate::daemon::proto::HistoryEntry::ToolCall { .. } => "tool_call",
            crate::daemon::proto::HistoryEntry::InferenceError { .. } => "inference_error",
            crate::daemon::proto::HistoryEntry::CompactBoundary { .. } => "compact_boundary",
            crate::daemon::proto::HistoryEntry::Subagent { .. } => "subagent",
        }
    }
}

pub fn main_entry() -> ExitCode {
    // Sandboxing part 2: dispatch the zerobox Linux sandbox helper and
    // install the PATH-prepend alias BEFORE the tokio runtime starts.
    tools::shell_sandbox::init();

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build();
    let result = match runtime {
        Ok(runtime) => runtime.block_on(async_main()),
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

fn error_exit_code(err: &anyhow::Error) -> u8 {
    if err.is::<commands::RemovedCommandError>() {
        commands::REMOVED_COMMAND_EXIT_CODE
    } else if err.is::<commands::CommandUsageError>() {
        commands::USAGE_EXIT_CODE
    } else {
        1
    }
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

async fn async_main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    init_tracing(cli.log_level.as_deref(), cli.print_logs);

    if cli.debug_last_message {
        match std::env::current_dir() {
            Ok(cwd) => engine::model::enable_debug_last_message(cwd.join(".lastmessage")),
            Err(e) => tracing::warn!(error = %e, "--debug-last-message: cwd unavailable"),
        }
    }

    match cli.command {
        None => commands::tui::run(cli.project.as_deref(), cli.no_sandbox).await,

        Some(Command::Ask(args)) => commands::ask::run(args).await,
        Some(Command::Run(args)) => {
            commands::run::run(args, cli.no_sandbox, cli.project.as_deref()).await
        }
        Some(Command::Agent(sub)) => commands::agent::run(sub).await,
        Some(Command::Assistant(crate::cli::AssistantCommand::Learn(args))) => {
            commands::learn::run(args, cli.no_sandbox).await
        }
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
        Some(Command::Daemon(sub)) => commands::daemon::run(sub).await,
        Some(Command::Doctor(args)) => commands::doctor::run(args, cli.no_sandbox).await,
        Some(Command::Session(sub)) => commands::session::run(sub).await,
        Some(Command::Trust(sub)) => commands::trust::run(sub).await,
        Some(Command::Export(args)) => commands::export::run(args).await,
        Some(Command::Import(args)) => commands::import::run(args).await,
        Some(Command::Stats(args)) => commands::stats::run(args).await,
        Some(Command::Debug(sub)) => commands::debug::run(sub).await,
        Some(Command::Config(sub)) => commands::config::run(sub).await,
        Some(Command::Meta(args)) => commands::meta::run(args).await,
        Some(Command::Mcp(cmd)) => commands::mcp::run(cmd).await,
        Some(Command::Login(_)) => Err(commands::RemovedCommandError::new("login").into()),
        Some(Command::Logout) => Err(commands::RemovedCommandError::new("logout").into()),
        Some(Command::Whoami) => Err(commands::RemovedCommandError::new("whoami").into()),
        Some(Command::Sync(sub)) => commands::sync::run(sub).await,
        Some(Command::Connect(args)) => commands::connect::run(args).await,
        Some(Command::Pr(args)) => commands::pr::run(args).await,
        Some(Command::Packages(sub)) => commands::packages::run(sub).await,
        Some(Command::Package(sub)) => commands::packages::run_singular(sub).await,
        Some(Command::Kcl(sub)) => commands::kcl::run(sub).await,
        Some(Command::Init(args)) => commands::init::run(args, cli.no_sandbox).await,
        Some(Command::BashHints(sub)) => commands::bash_hints::run(sub).await,
        Some(Command::Completion { shell }) => {
            use clap::CommandFactory;
            clap_complete::generate(
                shell,
                &mut Cli::command(),
                "cockpit",
                &mut std::io::stdout(),
            );
            Ok(())
        }
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
                .with_writer(std::sync::Mutex::new(file))
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

fn open_log_file() -> Option<std::fs::File> {
    let dir = dirs::cache_dir()?.join("cockpit");
    std::fs::create_dir_all(&dir).ok()?;
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join("cockpit.log"))
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
