//! Governed knowledge dream orchestration.

use std::collections::BTreeSet;

use anyhow::{Context, Result, ensure};

use crate::cli::KnowledgeCommand;
use crate::daemon::client::OwnedSessionMode;

pub async fn run(command: KnowledgeCommand, no_sandbox: bool) -> Result<()> {
    match command {
        KnowledgeCommand::Attach {
            knowledge_base_id,
            session_id,
        } => {
            mutate_attachment(
                cockpit_proto::request::Request::AttachKnowledgeBaseSession {
                    knowledge_base_id,
                    session_id,
                },
            )
            .await
        }
        KnowledgeCommand::Detach {
            knowledge_base_id,
            session_id,
        } => {
            mutate_attachment(
                cockpit_proto::request::Request::DetachKnowledgeBaseSession {
                    knowledge_base_id,
                    session_id,
                },
            )
            .await
        }
        KnowledgeCommand::Dream { knowledge_base_id } => {
            let prompt = cockpit_core::knowledge::build_dream_prompt(&knowledge_base_id);
            eprintln!("Dreaming knowledge base `{knowledge_base_id}`…");
            let exit_code = crate::daemon::client::run_owned_daemon(
                OwnedSessionMode::AttachOrEphemeral,
                |client| {
                    Box::pin(async move {
                        let cwd = std::env::current_dir().context("resolving dream workspace")?;
                        let before = dream_status(&client, &cwd, &knowledge_base_id).await?;
                        if before.undreamed_session_ids.is_empty() {
                            eprintln!(
                                "Knowledge base `{knowledge_base_id}` has no attached, undreamed sessions."
                            );
                            return Ok(0);
                        }
                        let source_ids = before
                            .undreamed_session_ids
                            .into_iter()
                            .collect::<BTreeSet<_>>();
                        let turn_exit_code = crate::commands::run::attach_send_pump(
                            &client,
                            prompt,
                            no_sandbox,
                            crate::cli::OutputFormat::Default,
                            crate::commands::run::RunPumpOptions {
                                model_override: Some(&before.model),
                                project_root: Some(&cwd),
                                ..Default::default()
                            },
                        )
                        .await
                        .context("running knowledge dream turn")?;
                        if turn_exit_code != 0 {
                            anyhow::bail!("knowledge dream agent reported an error");
                        }
                        let after = dream_status(&client, &cwd, &knowledge_base_id).await?;
                        let remaining = after
                            .undreamed_session_ids
                            .into_iter()
                            .collect::<BTreeSet<_>>();
                        ensure!(
                            source_ids.is_disjoint(&remaining),
                            "knowledge dream did not apply its selected source sessions; the agent must call knowledge_dream_apply"
                        );
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
    }
}

struct DreamStatus {
    model: String,
    undreamed_session_ids: Vec<uuid::Uuid>,
}

async fn dream_status(
    client: &crate::daemon::client::ScopedDaemonClient<'_>,
    cwd: &std::path::Path,
    knowledge_base_id: &str,
) -> Result<DreamStatus> {
    let response = client
        .request_ok(cockpit_proto::request::Request::KnowledgeDreamStatus {
            project_root: cwd.to_string_lossy().into_owned(),
            knowledge_base_id: knowledge_base_id.to_string(),
        })
        .await
        .context("resolving knowledge dream configuration")?;
    match response {
        cockpit_proto::Response::KnowledgeDreamStatus {
            model,
            undreamed_session_ids,
        } => Ok(DreamStatus {
            model,
            undreamed_session_ids,
        }),
        other => anyhow::bail!("daemon returned unexpected response to knowledge dream status: {other:?}"),
    }
}

async fn mutate_attachment(request: cockpit_proto::request::Request) -> Result<()> {
    crate::daemon::client::run_owned_daemon(OwnedSessionMode::AttachOrEphemeral, |client| {
        Box::pin(async move {
            client
                .request_ok(request)
                .await
                .context("updating knowledge-base session consent")?;
            Ok(())
        })
    })
    .await
}
