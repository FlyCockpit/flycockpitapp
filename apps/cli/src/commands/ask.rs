//! `cockpit ask <package> <question>` — direct CLI entry point for the
//! read-only dependency docs pipeline.

use std::io::Read;
use std::sync::{Arc, RwLock};

use anyhow::{Context, Result};
use serde_json::json;

use crate::cli::AskArgs;
use crate::commands::CommandUsageError;
use crate::engine::builtin::{DelegationRecursionContext, SpawnArgs};
use crate::engine::model::{Model, ModelParams};
use crate::env_snapshot::{EnvSnapshot, EnvSnapshotSource};
use crate::session::Session;

pub async fn run(args: AskArgs) -> Result<()> {
    let stdin = if args.question.is_empty() {
        read_stdin()?
    } else {
        String::new()
    };
    let question = assemble_question(&args.question, &stdin)?;
    let answer = run_docs_ask(&args.package_id, &question).await?;
    print!("{answer}");
    if !answer.ends_with('\n') {
        println!();
    }
    Ok(())
}

async fn run_docs_ask(package_id: &str, question: &str) -> Result<String> {
    let cwd = std::env::current_dir().context("resolving cwd")?;
    let db = crate::db::Db::open_default().context("opening cockpit DB")?;
    crate::config::trust::enforce_noninteractive_workspace_trust(&db, &cwd)?;

    let (extended, providers) = crate::auto_title::load_configs_for(&cwd);
    let env = EnvSnapshot::from_process(EnvSnapshotSource::ExplicitCli);
    let session =
        Session::create(db.clone(), cwd.clone(), "docs").context("creating docs ask session")?;
    session.set_sandbox_enabled(true);
    session.set_approval_mode(extended.default_approval_mode);
    session.set_shell_compression(extended.shell_compression);
    session.set_trusted_only(extended.trusted_only);
    if let Some(active) = providers.active_model.as_ref() {
        session
            .set_active_model(&active.provider, &active.model)
            .context("recording active model for docs ask session")?;
    }

    let redact = Arc::new(
        crate::redact::RedactionTable::build_with_env(&extended.redact, &cwd, env.vars())
            .context("building redaction table")?,
    );
    let model = Arc::new(
        Model::from_config_with_env_trusted_only(
            &providers,
            redact.clone(),
            session.trusted_only_flag(),
            |name| env.vars().get(name).cloned(),
        )
        .context("resolving active model")?,
    );
    let spawn_args = SpawnArgs {
        model,
        params: ModelParams {
            additional_params: providers.resolve_active_model_reasoning_params(),
            prompt_cache_key: Some(session.id.to_string()),
            ..ModelParams::default()
        },
        env_overlay: Arc::new(RwLock::new(Default::default())),
        cwd: cwd.clone(),
        session_short_id: session.short_id.clone(),
        model_system_prompt_snapshot: session.model_system_prompt_snapshot(),
        interactive: false,
        llm_mode: extended.llm_mode,
        model_override: None,
        delegation_model: None,
        delegated: true,
        delegation_recursion: DelegationRecursionContext::default(),
        swarm_depth: 0,
        swarm_max_depth: extended.swarm.max_depth,
        granted_tools: Vec::new(),
    };
    let locks = Arc::new(crate::locks::LockManager::from_db(db).context("loading lock state")?);
    let brief = build_docs_brief(package_id, question);
    crate::engine::docs_pipeline::run(
        &brief,
        &spawn_args,
        Arc::new(session),
        locks,
        redact,
        None,
        Arc::new(crate::engine::interrupt::InterruptHub::detached()),
        tokio_util::sync::CancellationToken::new(),
        None,
        None,
        None,
    )
    .await
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

fn build_docs_brief(package_id: &str, question: &str) -> String {
    json!({
        "package": package_id,
        "question": question,
    })
    .to_string()
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
    fn docs_brief_is_structured_json() {
        let brief = build_docs_brief("cargo:tokio", "how do tasks work?");
        let value: serde_json::Value = serde_json::from_str(&brief).unwrap();
        assert_eq!(value["package"], "cargo:tokio");
        assert_eq!(value["question"], "how do tasks work?");
    }
}
