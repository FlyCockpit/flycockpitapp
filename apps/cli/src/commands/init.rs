//! `cockpit init` — agentically generate the project instructions file.
//!
//! Mirrors opencode's `/init`: runs an agent (the normal `Build` →
//! `builder` delegation path, single-writer) that explores the project and
//! writes a concise, genuinely-useful instructions file at the target.
//! The write goes through the real `writeunlock` tool path — never a
//! canned template.
//!
//! Deliberately does **not** touch `config.json` or set up
//! providers: cockpit config is created lazily by the cockpit-specific
//! commands that need it (`cockpit harness add`, `cockpit redact
//! disable`, …). The shared prompt-builder + target-resolver live in
//! `cockpit_core::init` and are reused by the TUI `/init` slash command so
//! both surfaces drive the identical work; this module owns only the
//! headless subcommand around them.

use anyhow::{Context, Result};
use cockpit_core::init::{InitMode, build_init_prompt, display_target, resolve_target};

use crate::cli::InitArgs;
use crate::daemon::client::{LifecycleMode, probe_or_spawn};
use crate::daemon::ephemeral_guard::{EphemeralDaemonGuard, spawn_signal_shutdown};

/// `cockpit init [path]` — headless. Resolves the target, refuses to
/// clobber an existing file unless `--force` (no interactive prompt in
/// this path), then drives the agent to explore + write through the
/// normal delegation/tool path. Never touches `config.json`.
pub async fn run(args: InitArgs, no_sandbox: bool) -> Result<()> {
    let cwd = std::env::current_dir().context("resolving cwd")?;
    let explicit = args
        .path
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let target = resolve_target(&cwd, explicit);
    let shown = display_target(&cwd, &target);

    // Existing-file policy for the headless path: refuse rather than
    // silently overwrite. `--force` opts into a from-scratch overwrite.
    let exists = target.exists();
    let mode = if exists {
        if !args.force {
            anyhow::bail!(
                "`{shown}` already exists — refusing to overwrite. \
                 Re-run with `--force` to regenerate it, or use the `/init` \
                 slash command in the TUI to update it in place."
            );
        }
        InitMode::Overwrite
    } else {
        InitMode::Create
    };

    let prompt = build_init_prompt(&shown, mode);

    let mode_lc = if args.ephemeral {
        LifecycleMode::AlwaysEphemeral
    } else {
        LifecycleMode::AttachOrEphemeral
    };
    let daemon = probe_or_spawn(mode_lc).await?;
    let client = daemon.client.clone();

    let guard = daemon
        .owns_daemon
        .then(|| EphemeralDaemonGuard::new(daemon.socket.clone()));
    let signal_task = spawn_signal_shutdown(guard.as_ref(), true);

    eprintln!("Exploring the project and writing `{shown}`…");
    let result = crate::commands::run::attach_send_pump(
        &client,
        prompt,
        no_sandbox,
        crate::cli::OutputFormat::Default,
        crate::commands::run::RunPumpOptions::default(),
    )
    .await;

    if let Some(task) = signal_task {
        task.abort();
    }
    if let Some(guard) = &guard {
        guard.shutdown();
    }
    drop(guard);

    let exit_code = result?;
    if exit_code != 0 {
        anyhow::bail!("`cockpit init` ran but the agent reported an error");
    }
    if target.exists() {
        eprintln!("Wrote `{shown}`.");
    } else {
        anyhow::bail!("the agent finished but `{shown}` was not written");
    }
    Ok(())
}
