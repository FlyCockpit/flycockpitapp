//! Shared `/learn` and `cockpit assistant learn` request construction.
//!
//! Learning is deliberately an ordinary agent turn. The agent inspects the
//! supplied sources with its existing tools and persists the result through
//! `skill_manage`, so validation, approvals, and foreground provenance stay
//! centralized in the mutation tool.

use anyhow::{Context, Result};

use crate::cli::LearnArgs;
use crate::daemon::client::{OwnedDaemonSession, OwnedSessionMode};
pub use crate::skills::{build_learn_prompt, subject_from_parts};

pub async fn run(args: LearnArgs, no_sandbox: bool) -> Result<()> {
    let subject = subject_from_parts(&args.sources);
    let prompt = build_learn_prompt(&subject);
    let mode = if args.ephemeral {
        OwnedSessionMode::AlwaysEphemeral
    } else {
        OwnedSessionMode::AttachOrEphemeral
    };
    let daemon = OwnedDaemonSession::connect(mode).await?;
    eprintln!("Authoring a reusable skill from the supplied sources…");
    let result = crate::commands::run::attach_send_pump(
        daemon.client(),
        prompt,
        no_sandbox,
        crate::cli::OutputFormat::Default,
        crate::commands::run::RunPumpOptions::default(),
    )
    .await;
    let exit_code = daemon.finish(result.context("running learn turn")).await?;
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
