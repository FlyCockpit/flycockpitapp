//! Shared `/learn` and `cockpit assistant learn` request construction.
//!
//! Learning is deliberately an ordinary agent turn. The agent inspects the
//! supplied sources with its existing tools and persists the result through
//! `skill_manage`, so validation, approvals, and foreground provenance stay
//! centralized in the mutation tool.

use anyhow::{Context, Result};

use crate::cli::LearnArgs;
use crate::daemon::client::{LifecycleMode, probe_or_spawn};
use crate::daemon::ephemeral_guard::{EphemeralDaemonGuard, spawn_signal_shutdown};

const TRANSCRIPT_SOURCE: &str =
    "the reusable workflow we just completed in this conversation transcript";

pub fn subject_from_parts(parts: &[String]) -> String {
    let subject = parts.join(" ");
    let subject = subject.trim();
    if subject.is_empty() {
        TRANSCRIPT_SOURCE.to_string()
    } else {
        subject.to_string()
    }
}

/// Compose the single ordinary user turn shared by the slash and CLI forms.
pub fn build_learn_prompt(subject: &str) -> String {
    let subject = subject.trim();
    let subject = if subject.is_empty() {
        TRANSCRIPT_SOURCE
    } else {
        subject
    };
    format!(
        "Create a reusable Agent Skill from the following source request:\n\n\
         <learn-source>\n{subject}\n</learn-source>\n\n\
         This is a user-initiated `/learn` turn. Work through the normal live-agent flow and \
         save the finished package with the `skill_manage` tool so its validation, optional \
         write approval, and foreground provenance apply. If this frame does not expose \
         `skill_manage`, hand off to the Build primary before saving. Do not write SKILL.md \
         directly.\n\n\
         Gather evidence before authoring: use read/search for local paths, web fetch/search \
         for URLs, the current conversation transcript for a just-completed workflow, and \
         the supplied text for pasted steps. Multiple sources normally produce one skill \
         unless the user explicitly asks for more. Do not guess missing facts.\n\n\
         House authoring rules:\n\
         - Choose a conformant lowercase skill name and a concrete description of at most 60 characters.\n\
         - Use these body sections in this order: `## When to Use`, `## Procedure`, `## Pitfalls`, `## Verification`.\n\
         - Frame actions in terms of Cockpit's available tools and ordinary shell commands.\n\
         - Never invent commands, flags, paths, APIs, or verification results; confirm them from the sources.\n\
         - Keep the procedure concise, actionable, and reusable rather than narrating this conversation.\n\
         - Save through `skill_manage` and report the created skill name and source evidence when done."
    )
}

pub async fn run(args: LearnArgs, no_sandbox: bool) -> Result<()> {
    let subject = subject_from_parts(&args.sources);
    let prompt = build_learn_prompt(&subject);
    let mode = if args.ephemeral {
        LifecycleMode::AlwaysEphemeral
    } else {
        LifecycleMode::AttachOrEphemeral
    };
    let daemon = probe_or_spawn(mode).await?;
    let client = daemon.client.clone();
    let guard = daemon
        .owns_daemon
        .then(|| EphemeralDaemonGuard::new(daemon.socket.clone()));
    let signal_task = spawn_signal_shutdown(guard.as_ref(), true);

    eprintln!("Authoring a reusable skill from the supplied sources…");
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

    let exit_code = result.context("running learn turn")?;
    if exit_code != 0 {
        anyhow::bail!("`cockpit assistant learn` ran but the agent reported an error");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;
    use crate::cli::{AssistantCommand, Cli, Command};

    #[test]
    fn learn_slash_and_cli_compose_same() {
        let cli = Cli::try_parse_from(["cockpit", "assistant", "learn", "how", "we", "deployed"])
            .unwrap();
        let Some(Command::Assistant(AssistantCommand::Learn(args))) = cli.command else {
            panic!("expected assistant learn command");
        };
        let cli_prompt = build_learn_prompt(&subject_from_parts(&args.sources));
        let slash_prompt = build_learn_prompt("how we deployed");
        assert_eq!(cli_prompt, slash_prompt);
    }

    #[test]
    fn learn_prompt_rules() {
        let prompt = build_learn_prompt("https://example.invalid/docs and ./sdk");
        for required in [
            "at most 60 characters",
            "`## When to Use`, `## Procedure`, `## Pitfalls`, `## Verification`",
            "Never invent commands, flags, paths, APIs, or verification results",
            "read/search for local paths",
            "web fetch/search for URLs",
            "current conversation transcript",
            "foreground provenance",
        ] {
            assert!(prompt.contains(required), "missing `{required}`\n{prompt}");
        }
    }
}
