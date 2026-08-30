//! On-demand, daemon-owned knowledge-base dreams.

use anyhow::{Context, Result};

use crate::cli::DreamArgs;
use crate::daemon::client::OwnedSessionMode;
use crate::daemon::proto::{KnowledgeDreamRunOutcome, Request, Response};

pub async fn run(args: DreamArgs, no_sandbox: bool) -> Result<()> {
    let knowledge_base_id = if args.all {
        None
    } else {
        args.knowledge_base_id
    };
    let exit_code = crate::daemon::client::run_owned_daemon(
        OwnedSessionMode::AttachOrEphemeral,
        |client| {
            Box::pin(async move {
                let cwd = std::env::current_dir().context("resolving dream workspace")?;
                let response = client
                    .request_ok(Request::RunKnowledgeDream {
                        project_root: cwd.to_string_lossy().into_owned(),
                        knowledge_base_id,
                        no_sandbox,
                    })
                    .await
                    .context("running knowledge dream")?;
                let Response::KnowledgeDreamRuns { results } = response else {
                    anyhow::bail!(
                        "daemon returned unexpected response to knowledge dream run: {response:?}"
                    );
                };
                if results.is_empty() {
                    eprintln!("No knowledge bases are configured for this workspace.");
                }
                for result in results {
                    match result.outcome {
                        KnowledgeDreamRunOutcome::Dreamed => {
                            let sessions = result
                                .session_ids
                                .iter()
                                .map(ToString::to_string)
                                .collect::<Vec<_>>()
                                .join(", ");
                            let commit = result.commit.as_deref().unwrap_or("no new commit");
                            eprintln!(
                                "Knowledge base `{}` dreamed {} session(s) [{}]; commit: {commit}.",
                                result.knowledge_base_id,
                                result.session_ids.len(),
                                sessions,
                            );
                        }
                        KnowledgeDreamRunOutcome::NothingToDream => eprintln!(
                            "Knowledge base `{}` has no attached, undreamed sessions; marked checked.",
                            result.knowledge_base_id,
                        ),
                        KnowledgeDreamRunOutcome::Unavailable => eprintln!(
                            "Knowledge base `{}` is unavailable for local dreaming (hosted execution is not implemented).",
                            result.knowledge_base_id,
                        ),
                    }
                }
                Ok(0)
            })
        },
    )
    .await?;
    if exit_code != 0 {
        anyhow::bail!("knowledge dream agent reported an error");
    }
    Ok(())
}
