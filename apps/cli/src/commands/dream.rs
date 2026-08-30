//! On-demand, daemon-owned knowledge-base dreams.

use anyhow::{Context, Result};

use crate::cli::DreamArgs;
use crate::daemon::client::OwnedSessionMode;
use crate::daemon::proto::{KnowledgeDreamRunOutcome, KnowledgeDreamRunReceipt, Request, Response};

pub async fn run(args: DreamArgs, no_sandbox: bool) -> Result<()> {
    let knowledge_base_id = if args.all {
        None
    } else {
        args.knowledge_base_id
    };
    let exit_code =
        crate::daemon::client::run_owned_daemon(OwnedSessionMode::AttachOrEphemeral, |client| {
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
                for line in render_results(&results) {
                    eprintln!("{line}");
                }
                Ok(0)
            })
        })
        .await?;
    if exit_code != 0 {
        anyhow::bail!("knowledge dream agent reported an error");
    }
    Ok(())
}

fn render_results(results: &[KnowledgeDreamRunReceipt]) -> Vec<String> {
    if results.is_empty() {
        return vec!["No knowledge bases are configured for this workspace.".to_string()];
    }
    results
        .iter()
        .map(|result| match result.outcome {
            KnowledgeDreamRunOutcome::Dreamed => {
                let sessions = result
                    .session_ids
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ");
                let commit = result.commit.as_deref().unwrap_or("no new commit");
                format!(
                    "Knowledge base `{}` dreamed {} session(s) [{}]; commit: {commit}.",
                    result.knowledge_base_id,
                    result.session_ids.len(),
                    sessions,
                )
            }
            KnowledgeDreamRunOutcome::NothingToDream => format!(
                "Knowledge base `{}` has no attached, undreamed sessions; marked checked.",
                result.knowledge_base_id,
            ),
            KnowledgeDreamRunOutcome::Unavailable => format!(
                "Knowledge base `{}` is unavailable for local dreaming (hosted execution is not implemented).",
                result.knowledge_base_id,
            ),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receipt_rendering_preserves_daemon_order_and_reports_each_outcome() {
        let first = uuid::Uuid::nil();
        let lines = render_results(&[
            KnowledgeDreamRunReceipt {
                knowledge_base_id: "first".to_string(),
                outcome: KnowledgeDreamRunOutcome::Dreamed,
                session_ids: vec![first],
                commit: Some("abc123".to_string()),
            },
            KnowledgeDreamRunReceipt {
                knowledge_base_id: "second".to_string(),
                outcome: KnowledgeDreamRunOutcome::NothingToDream,
                session_ids: Vec::new(),
                commit: None,
            },
            KnowledgeDreamRunReceipt {
                knowledge_base_id: "remote".to_string(),
                outcome: KnowledgeDreamRunOutcome::Unavailable,
                session_ids: Vec::new(),
                commit: None,
            },
        ]);

        assert_eq!(lines.len(), 3);
        assert!(lines[0].contains("`first`"));
        assert!(lines[0].contains(&first.to_string()));
        assert!(lines[0].contains("abc123"));
        assert!(lines[1].contains("`second`"));
        assert!(lines[1].contains("marked checked"));
        assert!(lines[2].contains("`remote`"));
        assert!(lines[2].contains("hosted execution is not implemented"));
    }
}
