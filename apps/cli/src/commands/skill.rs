//! `cockpit skill` subcommands.

use anyhow::{Context, Result, bail};

use crate::cli::{
    SkillCommand, SkillCuratorCommand, SkillCuratorRollbackArgs, SkillCuratorRunArgs,
};
use crate::daemon::client::ensure_persistent_daemon;
use crate::daemon::proto::{CuratorAction, CuratorResult, Request, Response};

pub async fn run(cmd: SkillCommand) -> Result<()> {
    match cmd {
        SkillCommand::Curator(cmd) => run_curator(cmd).await,
    }
}

async fn curator_request(
    client: &cockpit_client::DaemonClient,
    project_root: &str,
    action: CuratorAction,
) -> Result<CuratorResult> {
    let response = client
        .request(Request::Curator {
            project_root: project_root.to_string(),
            action,
        })
        .await
        .context("requesting curator action from daemon")?
        .map_err(|error| anyhow::anyhow!("daemon rejected curator request: {error}"))?;
    match response {
        Response::Curator { result } => Ok(result),
        other => bail!("daemon returned unexpected response to curator: {other:?}"),
    }
}

async fn run_curator(cmd: SkillCuratorCommand) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let project_root = cwd.display().to_string();
    let daemon = ensure_persistent_daemon()
        .await
        .context("starting persistent daemon for skill curator")?;
    let client = daemon.client.clone();
    match cmd {
        SkillCuratorCommand::Status => {
            let result = curator_request(&client, &project_root, CuratorAction::Status).await?;
            match result {
                CuratorResult::Status { status } => {
                    if status.skills.is_empty() {
                        println!("no skills in usage ledger");
                    } else {
                        for skill in status.skills {
                            let archive = skill.archive_path.unwrap_or_else(|| "-".to_string());
                            println!(
                                "{}  state={}  by={}  uses={}  views={}  pinned={}  source={}  archive={}",
                                skill.name,
                                skill.state,
                                skill.created_by,
                                skill.use_count,
                                skill.view_count,
                                skill.pinned,
                                skill.source_path,
                                archive
                            );
                        }
                    }
                }
                other => bail!("unexpected curator status result: {other:?}"),
            }
            Ok(())
        }
        SkillCuratorCommand::Run(SkillCuratorRunArgs {
            dry_run,
            consolidate,
        }) => {
            let result = curator_request(
                &client,
                &project_root,
                CuratorAction::Run {
                    dry_run,
                    consolidate,
                },
            )
            .await?;
            match result {
                CuratorResult::Run { report } => {
                    println!(
                        "skill curator scanned {}; stale={}, archived={}, reactivated={}, skipped={}",
                        report.scanned,
                        report.stale.len(),
                        report.archived.len(),
                        report.reactivated.len(),
                        report.skipped.len()
                    );
                    if let Some(snapshot) = report.snapshot_id {
                        println!("snapshot={snapshot}");
                    }
                    if let Some(consolidation) = report.consolidation {
                        println!("{consolidation}");
                    }
                }
                other => bail!("unexpected curator run result: {other:?}"),
            }
            Ok(())
        }
        SkillCuratorCommand::Pin { name } => {
            let result = curator_request(
                &client,
                &project_root,
                CuratorAction::Pin { name: name.clone() },
            )
            .await?;
            match result {
                CuratorResult::Pinned { pinned: true, .. } => {
                    println!("pinned {name}");
                }
                CuratorResult::Pinned { pinned: false, .. } => {
                    bail!("daemon did not pin {name}");
                }
                other => bail!("unexpected curator pin result: {other:?}"),
            }
            Ok(())
        }
        SkillCuratorCommand::Unpin { name } => {
            let result = curator_request(
                &client,
                &project_root,
                CuratorAction::Unpin { name: name.clone() },
            )
            .await?;
            match result {
                CuratorResult::Pinned { pinned: false, .. } => {
                    println!("unpinned {name}");
                }
                CuratorResult::Pinned { pinned: true, .. } => {
                    bail!("daemon did not unpin {name}");
                }
                other => bail!("unexpected curator unpin result: {other:?}"),
            }
            Ok(())
        }
        SkillCuratorCommand::Restore { name } => {
            let result = curator_request(
                &client,
                &project_root,
                CuratorAction::Restore { name: name.clone() },
            )
            .await?;
            match result {
                CuratorResult::Restored { .. } => {
                    println!("restored {name}");
                }
                other => bail!("unexpected curator restore result: {other:?}"),
            }
            Ok(())
        }
        SkillCuratorCommand::Rollback(SkillCuratorRollbackArgs { list, id }) => {
            let result =
                curator_request(&client, &project_root, CuratorAction::Rollback { list, id })
                    .await?;
            match result {
                CuratorResult::Snapshots { snapshots } => {
                    for snapshot in snapshots {
                        println!(
                            "{}  created_at={}  reason={}  path={}",
                            snapshot.id, snapshot.created_at, snapshot.reason, snapshot.path
                        );
                    }
                }
                CuratorResult::RolledBack { snapshot } => {
                    println!("rolled back to {}", snapshot.id);
                }
                other => bail!("unexpected curator rollback result: {other:?}"),
            }
            Ok(())
        }
    }
}
