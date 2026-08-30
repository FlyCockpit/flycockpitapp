//! Governed knowledge dream orchestration.

use anyhow::{Context, Result};

use crate::cli::KnowledgeCommand;
use crate::daemon::client::OwnedSessionMode;
use crate::daemon::proto::{Request, Response};

pub async fn run(command: KnowledgeCommand, no_sandbox: bool) -> Result<()> {
    match command {
        KnowledgeCommand::Attach {
            knowledge_base_id,
            session_id,
        } => {
            mutate_attachment(Request::AttachKnowledgeBaseSession {
                knowledge_base_id,
                session_id,
            })
            .await
        }
        KnowledgeCommand::Detach {
            knowledge_base_id,
            session_id,
        } => {
            mutate_attachment(Request::DetachKnowledgeBaseSession {
                knowledge_base_id,
                session_id,
            })
            .await
        }
        KnowledgeCommand::Dream { knowledge_base_id } => {
            eprintln!("Dreaming knowledge base `{knowledge_base_id}`…");
            let exit_code = crate::daemon::client::run_owned_daemon(
                OwnedSessionMode::AttachOrEphemeral,
                |client| {
                    Box::pin(async move {
                        let cwd = std::env::current_dir().context("resolving dream workspace")?;
                        let response = client
                            .request_ok(Request::RunKnowledgeDream {
                                project_root: cwd.to_string_lossy().into_owned(),
                                knowledge_base_id: knowledge_base_id.clone(),
                                no_sandbox,
                            })
                            .await
                            .context("running knowledge dream turn")?;
                        if !matches!(response, Response::Ack) {
                            anyhow::bail!(
                                "daemon returned unexpected response to knowledge dream run: {response:?}"
                            );
                        }
                        let after = dream_status(&client, &cwd, &knowledge_base_id).await?;
                        match after.last_dreamed_at_unix_ms {
                            Some(timestamp) => eprintln!(
                                "Last dreamed/checked: {timestamp} ms since the Unix epoch."
                            ),
                            None => eprintln!("Knowledge base `{knowledge_base_id}` has not been dreamed yet."),
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
    }
}

struct DreamStatus {
    last_dreamed_at_unix_ms: Option<i64>,
}

async fn dream_status(
    client: &crate::daemon::client::ScopedDaemonClient<'_>,
    cwd: &std::path::Path,
    knowledge_base_id: &str,
) -> Result<DreamStatus> {
    let response = client
        .request_ok(Request::KnowledgeDreamStatus {
            project_root: cwd.to_string_lossy().into_owned(),
            knowledge_base_id: knowledge_base_id.to_string(),
        })
        .await
        .context("resolving knowledge dream configuration")?;
    match response {
        Response::KnowledgeDreamStatus {
            last_dreamed_at_unix_ms,
            ..
        } => Ok(DreamStatus {
            last_dreamed_at_unix_ms,
        }),
        other => anyhow::bail!(
            "daemon returned unexpected response to knowledge dream status: {other:?}"
        ),
    }
}

async fn mutate_attachment(request: Request) -> Result<()> {
    crate::daemon::client::run_owned_daemon(OwnedSessionMode::AttachOrEphemeral, |client| {
        Box::pin(async move {
            client
                .request_ok(request)
                .await
                .context("updating knowledge-base session consent")?;
            Ok(())
        })
    })
    .await?;
    Ok(())
}
