//! Governed knowledge dream orchestration.

use anyhow::{Context, Result};

use crate::cli::KnowledgeCommand;
use crate::daemon::client::OwnedSessionMode;
use crate::daemon::proto::Request;

pub async fn run(command: KnowledgeCommand) -> Result<()> {
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
