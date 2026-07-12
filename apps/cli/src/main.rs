//! `cockpit` — entry point.
//!
//! Most actual logic lives in the per-subcommand files in `commands/`. This
//! file only does:
//! 1. Parse argv with clap.
//! 2. Initialize logging.
//! 3. Dispatch to the matching command.

mod agents;
mod approval;
mod auth;
mod auto_title;
mod banner;
mod browser;
mod cli;
mod clipboard;
mod commands;
mod config;
mod container;
mod credentials;
mod daemon;
mod db;
mod diagnostics;
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
mod session;
mod skills;
mod startup;
mod sync;
mod sysinfo;
mod text;
mod tokens;
mod tools;
mod tui;
mod welcome;

use clap::Parser;
use std::process::ExitCode;

use crate::cli::{Cli, Command};

fn main() -> ExitCode {
    // Sandboxing part 2: dispatch the zerobox Linux sandbox helper and
    // install the PATH-prepend alias BEFORE the tokio runtime starts —
    // the dispatch can re-exec this binary as the helper (never
    // returning) and the PATH mutation is only sound single-threaded.
    // No-op on non-Linux. Must precede `Cli::parse` so a helper re-entry
    // doesn't try to parse cockpit's CLI.
    tools::shell_sandbox::init();

    // Build the multi-thread runtime by hand (the `#[tokio::main]`
    // equivalent) so the helper dispatch above runs first.
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
    if err.is::<commands::CommandUsageError>() {
        commands::USAGE_EXIT_CODE
    } else {
        1
    }
}

fn error_stderr_line(err: &anyhow::Error) -> String {
    if let Some(usage) = err.downcast_ref::<commands::CommandUsageError>() {
        format!("error: {}", usage.message())
    } else {
        format!("Error: {err:?}")
    }
}

async fn async_main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    init_tracing(cli.log_level.as_deref(), cli.print_logs);

    if cli.debug_last_message {
        // Resolve `<cwd>/.lastmessage` once at startup so the engine
        // task doesn't depend on `current_dir()` from inside a tokio
        // worker. If cwd resolution fails (rare — chdir to a deleted
        // directory), the flag is a silent no-op and a warning lands
        // in the log.
        match std::env::current_dir() {
            Ok(cwd) => engine::model::enable_debug_last_message(cwd.join(".lastmessage")),
            Err(e) => tracing::warn!(error = %e, "--debug-last-message: cwd unavailable"),
        }
    }

    match cli.command {
        // Bare `cockpit` (no subcommand) launches the TUI in cwd, or in
        // `--project <path>` when explicitly supplied. `--no-sandbox`
        // (sandboxing part 2) disables filesystem sandboxing for sessions
        // this client creates.
        None => commands::tui::run(cli.project.as_deref(), cli.no_sandbox).await,

        Some(Command::Ask(args)) => commands::ask::run(args).await,
        Some(Command::Run(args)) => commands::run::run(args, cli.no_sandbox).await,
        Some(Command::Agent(sub)) => commands::agent::run(sub).await,
        Some(Command::Providers(sub)) => commands::providers::run(sub).await,
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
        Some(Command::Login(args)) => commands::flycockpit::login(args).await,
        Some(Command::Logout) => commands::flycockpit::logout().await,
        Some(Command::Whoami) => commands::flycockpit::whoami().await,
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

    // Interactive mode: capture warnings and panics in a file the user
    // can read after closing the TUI. Per `implementation notes` §5 this will
    // grow into a rotating logger under `~/.local/state/cockpit/logs/`;
    // for now a single appended file under the cache dir is enough.
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
}
