//! `cockpit kcl import` — one-way registry import from a local kcl
//! install (prompt `docs-agent.md` component A). Prefers kcl's portable
//! package manifest, falls back to the legacy DB read-only, and never
//! writes back.

use anyhow::Result;

use crate::cli::KclCommand;
use crate::db::Db;
use crate::packages::{KclImport, import_from_kcl};

pub async fn run(cmd: KclCommand) -> Result<()> {
    match cmd {
        KclCommand::Import => import().await,
    }
}

async fn import() -> Result<()> {
    let cwd = std::env::current_dir()?;
    let db = Db::open_default()?;
    match import_from_kcl(&db, &cwd)? {
        KclImport::Imported(n) => {
            println!("Imported {n} package(s) from kcl.");
        }
        KclImport::NoKclDb(path) => {
            println!(
                "No kcl registry found at {} — nothing to import.",
                path.display()
            );
        }
    }
    Ok(())
}
