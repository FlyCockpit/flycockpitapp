//! Governed knowledge dream orchestration.

use anyhow::{Context, Result};

use crate::cli::KnowledgeCommand;
use crate::daemon::client::OwnedSessionMode;

pub async fn run(command: KnowledgeCommand, no_sandbox: bool) -> Result<()> {
    match command {
        KnowledgeCommand::Dream { knowledge_base_id } => {
            let prompt = cockpit_core::knowledge::build_dream_prompt(&knowledge_base_id);
            eprintln!("Dreaming knowledge base `{knowledge_base_id}`…");
            let exit_code = crate::daemon::client::run_owned_daemon(
                OwnedSessionMode::AttachOrEphemeral,
                |client| {
                    Box::pin(async move {
                        crate::commands::run::attach_send_pump(
                            &client,
                            prompt,
                            no_sandbox,
                            crate::cli::OutputFormat::Default,
                            crate::commands::run::RunPumpOptions::default(),
                        )
                        .await
                        .context("running knowledge dream turn")
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
