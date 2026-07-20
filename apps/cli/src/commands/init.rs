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
//! disable`, …). The shared prompt-builder + target-resolver below are
//! reused by the TUI `/init` slash command so both surfaces drive the
//! identical work.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::cli::InitArgs;
use crate::daemon::client::{LifecycleMode, probe_or_spawn};
use crate::daemon::ephemeral_guard::{EphemeralDaemonGuard, spawn_signal_shutdown};

/// What the agent should do with the target file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitMode {
    /// The file does not exist yet — write it fresh.
    Create,
    /// The file exists — revise/extend it, preserving useful content.
    #[allow(dead_code)]
    Update,
    /// The file exists — replace it from scratch.
    Overwrite,
}

/// Resolve the target instructions file for `/init [path]` at `cwd`.
///
/// - An explicit arg is taken verbatim: absolute paths as-is, relative
///   paths joined under `cwd`.
/// - No arg → the **first configured** guidance filename
///   (`agent_guidance_files[0]`, default `AGENTS.md`) joined under `cwd`
///   — the first *configured* name, not the first that happens to exist.
pub fn resolve_target(cwd: &Path, explicit: Option<&str>) -> PathBuf {
    match explicit.map(str::trim).filter(|s| !s.is_empty()) {
        Some(arg) => {
            let p = Path::new(arg);
            if p.is_absolute() {
                p.to_path_buf()
            } else {
                cwd.join(p)
            }
        }
        None => {
            let cfg = crate::config::extended::load_for_cwd(cwd);
            let name = cfg
                .agent_guidance_files
                .first()
                .cloned()
                .unwrap_or_else(|| "AGENTS.md".to_string());
            cwd.join(name)
        }
    }
}

/// The path to show the user / hand the agent: relative to `cwd` when the
/// target lives under it, else the absolute path.
pub fn display_target(cwd: &Path, target: &Path) -> String {
    target
        .strip_prefix(cwd)
        .unwrap_or(target)
        .display()
        .to_string()
}

/// Build the user message that drives the init agent. `target` is the
/// path the file must be written to (as shown to the user); `mode`
/// selects fresh-write vs. revise-in-place vs. overwrite wording. The
/// message instructs the agent to explore first and write through the
/// normal tool path — no canned template — and to leave `config.json`
/// alone.
pub fn build_init_prompt(target: &str, mode: InitMode) -> String {
    let action = match mode {
        InitMode::Create => format!("Write a new project instructions file at `{target}`."),
        InitMode::Update => format!(
            "Update the existing project instructions file at `{target}` in place: \
             revise and extend it, preserving the content that is still accurate."
        ),
        InitMode::Overwrite => format!(
            "Overwrite the project instructions file at `{target}` from scratch, \
             replacing its current content entirely."
        ),
    };
    format!(
        "{action}\n\n\
         First explore this project — its structure, the build/test/lint commands, \
         the languages and frameworks in use, and any conventions a contributor must \
         follow. Then write the file via the normal file-write tool path (delegate to \
         `builder`, the single writer). Keep it concise and genuinely useful: terse, \
         high-signal guidance an agent or new contributor needs, not padding. \
         Do not create or modify `config.json` or any other config file — \
         only the instructions file at `{target}`."
    )
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_relative_arg_joins_under_cwd() {
        let cwd = Path::new("/proj");
        let t = resolve_target(cwd, Some("docs/GUIDE.md"));
        assert_eq!(t, Path::new("/proj/docs/GUIDE.md"));
    }

    #[test]
    fn explicit_absolute_arg_taken_verbatim() {
        let cwd = Path::new("/proj");
        let t = resolve_target(cwd, Some("/etc/elsewhere.md"));
        assert_eq!(t, Path::new("/etc/elsewhere.md"));
    }

    #[test]
    fn no_arg_targets_first_configured_name_under_cwd() {
        // No/blank arg → `cwd.join(agent_guidance_files[0])`: the first
        // *configured* name (resolved from layered config for `cwd`), not
        // "first that happens to exist". Pin against the same config the
        // resolver reads so the test is independent of ambient config.
        let cwd = Path::new("/nonexistent-cockpit-init-test-dir");
        let first = crate::config::extended::load_for_cwd(cwd)
            .agent_guidance_files
            .first()
            .cloned()
            .unwrap_or_else(|| "AGENTS.md".to_string());
        assert_eq!(resolve_target(cwd, None), cwd.join(&first));
        assert_eq!(resolve_target(cwd, Some("   ")), cwd.join(&first));
    }

    #[test]
    fn display_target_is_relative_under_cwd() {
        let cwd = Path::new("/proj");
        assert_eq!(display_target(cwd, &cwd.join("AGENTS.md")), "AGENTS.md");
        assert_eq!(display_target(cwd, Path::new("/other/x.md")), "/other/x.md");
    }

    #[test]
    fn prompt_carries_target_mode_and_config_guard() {
        let create = build_init_prompt("AGENTS.md", InitMode::Create);
        assert!(create.contains("AGENTS.md"));
        assert!(create.contains("new project instructions file"));
        // Always forbids touching config + names the single writer.
        assert!(create.contains("config.json"));
        assert!(create.contains("builder"));

        let update = build_init_prompt("AGENTS.md", InitMode::Update);
        assert!(update.contains("in place"));
        let overwrite = build_init_prompt("AGENTS.md", InitMode::Overwrite);
        assert!(overwrite.contains("from scratch"));
    }
}
