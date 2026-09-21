//! Minimal `cockpit daemon start --foreground` entry for detached-spawn tests.
//!
//! Production `spawn_detached*` uses `current_exe()`, which is the `cockpit`
//! binary. Unit/integration tests discover this harness under the Cargo
//! `target/` tree so spawn paths exercise a real wire-backed foreground daemon
//! without depending on `apps/cli`.

use std::process::ExitCode;

use anyhow::{Context, Result, bail};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error:#}");
            ExitCode::from(cockpit_core::daemon::daemon_error_exit_code(&error))
        }
    }
}

fn run() -> Result<()> {
    cockpit_core::daemon::supervisor::prepare_process_entry_environment()?;
    let args: Vec<String> = std::env::args().collect();
    let role = args.get(2).map(String::as_str);
    if args.get(1).map(String::as_str) != Some("daemon")
        || !matches!(role, Some("start" | "supervise" | "worker"))
    {
        let argv0 = args
            .first()
            .map(String::as_str)
            .unwrap_or("cockpit-daemon-spawn-harness");
        bail!("usage: {argv0} daemon <supervise|worker>");
    }
    if std::env::var_os("COCKPIT_WORKER_WATCH_TEST_HOLD").is_some() {
        std::thread::sleep(std::time::Duration::from_secs(30));
        return Ok(());
    }
    if std::env::var_os("COCKPIT_WORKER_WATCH_TEST_EXIT_SUCCESS").is_some() {
        std::thread::sleep(std::time::Duration::from_millis(100));
        return Ok(());
    }
    let no_sandbox = args.iter().any(|arg| arg == "--no-sandbox");
    let resume_all_sessions = args.iter().any(|arg| arg == "--resume-all-sessions");
    if no_sandbox {
        // SAFETY: exported before the runtime starts worker tasks, matching
        // `apps/cli` foreground daemon startup.
        unsafe {
            std::env::set_var(
                cockpit_core::daemon::session_worker::DAEMON_NO_SANDBOX_ENV,
                "1",
            );
        }
    }

    let paths = cockpit_core::daemon::DaemonPaths::resolve()?;
    let terminal_factory = cockpit_core::daemon::terminal::default_host_factory();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_stack_size(cockpit_core::daemon::session_worker::TOKIO_WORKER_STACK_SIZE)
        .build()
        .context("building daemon spawn harness runtime")?;
    runtime.block_on(async move {
        if role == Some("worker") {
            if resume_all_sessions {
                cockpit_core::daemon::run_foreground_with_resume(paths, true, terminal_factory)
                    .await
            } else {
                cockpit_core::daemon::run_foreground(paths, terminal_factory).await
            }
        } else {
            cockpit_core::daemon::supervisor::run(paths, no_sandbox, resume_all_sessions).await
        }
    })
}
