//! `cockpit ask <package> <question>` — CLI front end for the read-only
//! dependency docs pipeline.
//!
//! The daemon owns the pipeline: `cockpit ask` starts (or reuses) the
//! persistent daemon and sends the owner-remoted `DocsAsk` RPC. The daemon
//! creates a `"docs"`-agent session, runs the existing two-stage
//! package-question pipeline, and returns the rendered answer. The CLI never
//! opens SQLite, never starts a standalone secure-key actor, and never builds
//! an in-process engine.

use std::io::Read;

use anyhow::{Context, Result, anyhow};

use crate::cli::AskArgs;
use crate::commands::CommandUsageError;
use crate::daemon::client::ensure_persistent_daemon;
use crate::daemon::proto::{Request, Response};

pub async fn run(args: AskArgs) -> Result<()> {
    let stdin = if args.question.is_empty() {
        read_stdin()?
    } else {
        String::new()
    };
    let question = assemble_question(&args.question, &stdin)?;
    let project_root = std::env::current_dir()
        .context("resolving cwd for docs ask")?
        .display()
        .to_string();
    let request = build_docs_ask_request(&args.package_id, question, Some(project_root));

    let daemon = ensure_persistent_daemon()
        .await
        .context("starting persistent daemon for docs ask")?;
    let response = daemon
        .client
        .request(request)
        .await
        .context("sending docs ask to daemon")?
        .map_err(|error| anyhow!("daemon rejected docs ask: {error}"))?;
    let Response::DocsAnswer { answer } = response else {
        return Err(anyhow!("daemon returned unexpected response to docs ask"));
    };

    print!("{answer}");
    if !answer.ends_with('\n') {
        println!();
    }
    Ok(())
}

/// Assemble the owner-remoted `DocsAsk` request the command sends. Extracted so
/// the real request can be unit-tested without a live daemon: `package` is the
/// registered package identifier, `question` the assembled prompt, and
/// `project_root` the workspace whose layered config/trust resolve the
/// answering model.
fn build_docs_ask_request(
    package_id: &str,
    question: String,
    project_root: Option<String>,
) -> Request {
    Request::DocsAsk {
        question,
        package: Some(package_id.to_string()),
        project_root,
    }
}

fn read_stdin() -> Result<String> {
    let mut input = String::new();
    std::io::stdin()
        .read_to_string(&mut input)
        .context("reading question from stdin")?;
    Ok(input)
}

fn assemble_question(args: &[String], stdin: &str) -> Result<String> {
    let question = if args.is_empty() {
        stdin.to_string()
    } else {
        args.join(" ")
    };
    if question.trim().is_empty() {
        return Err(CommandUsageError::new(
            "no question supplied (pass a question argument or pipe one on stdin)",
        )
        .into());
    }
    Ok(question)
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;
    use crate::cli::{Cli, Command};

    #[test]
    fn ask_command_parses_package_and_multi_arg_question() {
        let cli = Cli::try_parse_from(["cockpit", "ask", "tokio", "how", "spawn?"]).unwrap();
        let Some(Command::Ask(args)) = cli.command else {
            panic!("expected ask command");
        };
        assert_eq!(args.package_id, "tokio");
        assert_eq!(args.question, ["how", "spawn?"]);
    }

    #[test]
    fn assemble_question_joins_args_with_spaces() {
        let args = vec!["how".to_string(), "spawn?".to_string()];
        assert_eq!(assemble_question(&args, "ignored").unwrap(), "how spawn?");
    }

    #[test]
    fn assemble_question_uses_stdin_when_args_are_empty() {
        assert_eq!(
            assemble_question(&[], "line one\nline two\n").unwrap(),
            "line one\nline two\n"
        );
    }

    #[test]
    fn assemble_question_rejects_empty_args_and_empty_stdin() {
        let err = assemble_question(&[], " \n\t ").unwrap_err();
        assert!(err.is::<CommandUsageError>());
        assert!(err.to_string().contains("no question supplied"));
    }

    #[test]
    fn build_docs_ask_request_targets_owner_remoted_docs_ask() {
        // Drives the real request-builder the command calls: `ask` assembles an
        // owner-remoted `DocsAsk` (daemon-owned, no in-process SQLite / engine)
        // carrying the package, the assembled question, and the workspace root.
        let request = build_docs_ask_request(
            "cargo:tokio",
            "how do tasks work?".to_string(),
            Some("/w/project".to_string()),
        );
        let Request::DocsAsk {
            question,
            package,
            project_root,
        } = request
        else {
            panic!("ask must request DocsAsk");
        };
        assert_eq!(question, "how do tasks work?");
        assert_eq!(package.as_deref(), Some("cargo:tokio"));
        assert_eq!(project_root.as_deref(), Some("/w/project"));
    }

    fn production_ask_source() -> &'static str {
        let source = include_str!("ask.rs");
        source
            .split("mod tests {")
            .next()
            .expect("production ask.rs")
    }

    /// AC1: `ask` reaches the daemon through the shared `ensure_persistent_daemon`
    /// entry point (the same helper `doctor` uses), which boots a persistent
    /// daemon when none is running, and sends the owner-remoted `DocsAsk` RPC —
    /// it never builds an in-process engine.
    #[test]
    fn ask_without_daemon_starts_persistent_daemon() {
        let production = production_ask_source();
        assert!(
            production.contains("ensure_persistent_daemon"),
            "ask must start/reuse the persistent daemon"
        );
        assert!(
            production.contains("Request::DocsAsk"),
            "ask must reach the docs pipeline through the daemon RPC"
        );
        assert!(
            !production.contains("docs_pipeline"),
            "ask must not run the docs pipeline in-process"
        );
    }

    /// AC2: the rewritten command opens no CLI-side SQLite. (The workspace
    /// production-path ratchet enforces the same by dropping `ask.rs` from its
    /// allow-list; this is the local mirror.)
    #[test]
    fn ask_rs_has_no_db_open() {
        let production = production_ask_source();
        assert!(
            !production.contains("Db::open_default"),
            "ask must not open SQLite"
        );
        assert!(
            !production.contains("vault_for_db"),
            "ask must not open an in-process vault"
        );
    }

    /// AC3: no standalone `SecureKeyActor` / redaction-key resolver is started;
    /// the daemon owns the secure-key actor.
    #[test]
    fn ask_does_not_start_standalone_secure_key_actor() {
        let production = production_ask_source();
        assert!(
            !production.contains("SecureKeyActor"),
            "ask must not construct a standalone secure-key actor"
        );
        assert!(
            !production.contains("start_standalone_redaction_key_resolver"),
            "ask must not start a standalone redaction-key resolver"
        );
        assert!(
            !production.contains("Session::create"),
            "ask must not build an in-process session"
        );
    }
}
