//! `cockpit skill` subcommands.

use anyhow::Result;

use crate::cli::{
    SkillCommand, SkillCuratorCommand, SkillCuratorRollbackArgs, SkillCuratorRunArgs,
};
use crate::skills::curator::{CuratorRunOptions, SkillCurator};

pub async fn run(cmd: SkillCommand) -> Result<()> {
    match cmd {
        SkillCommand::Curator(cmd) => run_curator(cmd).await,
    }
}

async fn run_curator(cmd: SkillCuratorCommand) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let db = crate::db::Db::open_default()?;
    let cfg = crate::config::extended::load_for_cwd(&cwd).skills;
    let curator = SkillCurator::new(db, cwd, cfg);
    match cmd {
        SkillCuratorCommand::Status => {
            let status = curator.status()?;
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
            Ok(())
        }
        SkillCuratorCommand::Run(SkillCuratorRunArgs {
            dry_run,
            consolidate,
        }) => {
            let report = curator.run(CuratorRunOptions {
                dry_run,
                consolidate,
            })?;
            println!("{}", report.summary());
            if let Some(snapshot) = report.snapshot_id {
                println!("snapshot={snapshot}");
            }
            if let Some(consolidation) = report.consolidation {
                println!("{consolidation}");
            }
            Ok(())
        }
        SkillCuratorCommand::Pin { name } => {
            curator.pin(&name, true)?;
            println!("pinned {name}");
            Ok(())
        }
        SkillCuratorCommand::Unpin { name } => {
            curator.pin(&name, false)?;
            println!("unpinned {name}");
            Ok(())
        }
        SkillCuratorCommand::Restore { name } => {
            curator.restore(&name)?;
            println!("restored {name}");
            Ok(())
        }
        SkillCuratorCommand::Rollback(SkillCuratorRollbackArgs { list, id }) => {
            if list {
                for snapshot in curator.snapshots()? {
                    println!(
                        "{}  created_at={}  reason={}  path={}",
                        snapshot.id, snapshot.created_at, snapshot.reason, snapshot.path
                    );
                }
                return Ok(());
            }
            let restored = curator.rollback(id.as_deref())?;
            println!("rolled back to {}", restored.id);
            Ok(())
        }
    }
}
