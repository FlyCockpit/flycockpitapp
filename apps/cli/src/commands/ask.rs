//! `cockpit ask <package> <question>` — direct CLI entry point for the
//! read-only dependency docs pipeline.

use std::io::Read;
use std::sync::{Arc, RwLock};

use anyhow::{Context, Result, anyhow};
use serde_json::json;

use crate::cli::AskArgs;
use crate::commands::CommandUsageError;
use crate::config::extended::DEFAULT_RECURSIVE_SPAWN_MAX_DEPTH;
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
    crate::config::trust::enforce_noninteractive_workspace_trust(&db, &cwd).await?;

    let (extended, providers) = crate::auto_title::load_configs_for(&cwd);
    let env = EnvSnapshot::from_process(EnvSnapshotSource::ExplicitCli);
    // This daemon-less command has no daemon-owned secure-key actor, but a
    // `Session` requires a key resolver (decision 16). Start a standalone actor
    // and keep it alive for the session's lifetime. The docs ask never journals
    // (see `allow_unjournaled_inference` below), so the resolver is never
    // exercised, but it must be a real resolver, never absent.
    // `start_standalone_redaction_key_resolver` boots the secure-key actor and
    // blocks on its readiness channel (`blocking_recv`), which panics on a Tokio
    // worker thread. Mirror the daemon (`daemon/server/mod.rs`
    // `start_production_with_reconciler` runs off the async worker on a dedicated
    // thread) by running the startup on a blocking thread via `spawn_blocking`.
    let (secure_key_actor, redaction_key_resolver) = {
        let db = db.clone();
        tokio::task::spawn_blocking(move || {
            crate::redact::start_standalone_redaction_key_resolver(&db)
        })
        .await
        .context("joining secure-key resolver startup for docs ask session")?
        .context("starting secure-key resolver for docs ask session")?
    };
    // Own the actor across the whole session and drain it on a blocking thread
    // afterwards. `SecureKeyActor`'s `Drop` blocks on its worker channel
    // (`blocking_recv`), which panics on a Tokio worker thread, so the session
    // body runs in an inner future and the actor is dropped off-worker on every
    // exit path (success or `?`), mirroring the daemon's off-worker actor lifecycle.
    let result: Result<String> = async move {
        let vault = cockpit_core::secure_key::vault_for_db(&db)
            .map_err(|e| anyhow!("opening docs ask session vault: {e}"))?;
        let session = Session::create(
            db.clone(),
            cwd.clone(),
            "docs",
            redaction_key_resolver,
            vault,
        )
        .context("creating docs ask session")?;
        // This legacy read-only, daemon-less command cannot safely open the
        // daemon-owned recovery spool concurrently. Its inference remains on the
        // existing primary-row audit path; daemon/session-worker turns are always
        // journal-required.
        session.allow_unjournaled_inference(
            crate::session::UnjournaledInferenceReason::DaemonlessDocsAsk,
        );
        session.set_sandbox_enabled(true);
        session.set_approval_mode(extended.default_approval_mode);
        session.set_shell_compression(extended.shell_compression);
        seed_docs_session_active_model(&session, providers.active_model.as_ref())?;

        let redact = Arc::new(
            crate::redact::RedactionTable::build_with_env_and_store(
                &extended.redact,
                &cwd,
                env.vars(),
            )
            .context("building redaction table")?,
        );
        let model = Arc::new(
            Model::from_config_with_env(&providers, redact.clone(), |name| {
                env.vars().get(name).cloned()
            })
            .context("resolving active model")?,
        );
        let reasoning_params = model.resolve_reasoning_params(&providers);
        // Session-less command: resolve config once here (the trust-aware entry
        // point already ran to produce `extended`/`providers`) and serve it to the
        // docs pipeline through a detached config handle
        // (`engine-config-snapshot-adoption`).
        let config = crate::daemon::session_worker::SessionConfigHandle::detached(
            crate::daemon::session_worker::SessionConfigSnapshot::new(
                0,
                providers.clone(),
                extended.clone(),
            ),
        );
        let spawn_args = SpawnArgs {
            model,
            params: ModelParams {
                additional_params: reasoning_params,
                prompt_cache_key: Some(session.id.to_string()),
                ..ModelParams::default()
            },
            env_overlay: Arc::new(RwLock::new(Default::default())),
            cwd: cwd.clone(),
            config: config.clone(),
            session_short_id: session.short_id.clone(),
            assistant_identity_prefix: None,
            model_system_prompt_snapshot: session.model_system_prompt_snapshot(),
            interactive: false,
            llm_mode: extended.llm_mode,
            model_override: None,
            delegation_model: None,
            delegated: true,
            delegation_recursion: DelegationRecursionContext::default(),
            swarm_depth: 0,
            swarm_max_depth: DEFAULT_RECURSIVE_SPAWN_MAX_DEPTH,
            granted_tools: Vec::new(),
            lock_identity: None,
            write_scope: None,
            credential_store: None,
        };
        let locks = Arc::new(
            crate::locks::LockManager::from_db(db)
                .await
                .context("loading lock state")?,
        );
        let brief = build_docs_brief(package_id, question);
        let outcome = crate::engine::docs_pipeline::run(
            &brief,
            &spawn_args,
            Arc::new(session),
            locks,
            redact,
            config,
            None,
            Arc::new(crate::engine::interrupt::InterruptHub::detached()),
            tokio_util::sync::CancellationToken::new(),
            None,
            None,
            None,
        )
        .await?;
        Ok(outcome.report)
    }
    .await;
    // Drain the standalone secure-key actor off the async worker; its `Drop`
    // would otherwise `blocking_recv` on a Tokio worker thread and panic.
    tokio::task::spawn_blocking(move || drop(secure_key_actor))
        .await
        .context("draining secure-key resolver for docs ask session")?;
    result
}

fn seed_docs_session_active_model(
    session: &Session,
    active: Option<&crate::config::providers::ActiveModelRef>,
) -> Result<()> {
    if let Some(active) = active {
        session
            .set_active_model_ref(active.clone())
            .context("recording active model for docs ask session")?;
    }
    Ok(())
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

    #[test]
    fn docs_ask_session_seeds_complete_active_model_selection() {
        let db = crate::db::Db::open_in_memory().unwrap();
        let (_secure_key_actor, resolver) =
            crate::redact::start_fake_redaction_key_resolver(&db).unwrap();
        let vault = cockpit_core::secure_key::vault_for_db(&db).unwrap();
        let session = Session::create(
            db,
            std::path::PathBuf::from("/docs"),
            "docs",
            resolver,
            vault,
        )
        .unwrap();
        let selection = crate::config::providers::ActiveModelRef {
            provider: "anthropic".to_string(),
            model: "claude-opus-4-7".to_string(),
            reasoning_effort: Some(crate::config::providers::ActiveReasoningEffort {
                value: "high".to_string(),
            }),
            thinking_mode: Some(crate::config::providers::ThinkingMode::High),
            prompt_cache_retention: Some(crate::config::providers::PromptCacheRetention::Extended),
        };

        seed_docs_session_active_model(&session, Some(&selection)).unwrap();

        assert_eq!(session.active_model_ref(), Some(selection));
    }
}
