//! Minimal `cockpit daemon start --foreground` entry for detached-spawn tests.
//!
//! Production `spawn_detached*` uses `current_exe()`, which is the `cockpit`
//! binary. Unit/integration tests build this harness beside the libtest binary
//! so spawn paths exercise a real wire-backed foreground daemon without
//! depending on `apps/cli`.

use std::process::ExitCode;

use anyhow::{Context, Result, bail};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error:#}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) != Some("daemon")
        || args.get(2).map(String::as_str) != Some("start")
    {
        let argv0 = args
            .first()
            .map(String::as_str)
            .unwrap_or("cockpit-daemon-spawn-harness");
        bail!("usage: {argv0} daemon start --foreground");
    }
    if !args.iter().any(|arg| arg == "--foreground") {
        bail!("daemon spawn harness requires --foreground");
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
    runtime.block_on(async {
        if resume_all_sessions {
            cockpit_core::daemon::run_foreground_with_resume(paths, true, terminal_factory).await
        } else {
            cockpit_core::daemon::run_foreground(paths, terminal_factory).await
        }
    })
}
