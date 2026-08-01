use anyhow::{Context, Result};
use base64::Engine;

use crate::daemon::client::DaemonClient;
use crate::daemon::proto::{Request, Response};
use crate::daemon::{DaemonStatus, discover};

use crate::cli::ImportArgs;
use crate::db::Db;

pub async fn run(args: ImportArgs) -> Result<()> {
    let daemon = discover().await;
    let imported = if matches!(daemon.status, DaemonStatus::Running) {
        let paths = daemon.paths;
        let client = DaemonClient::connect(&paths.socket)
            .await
            .context("connecting to running daemon for session import")?;
        let bytes = std::fs::read(&args.file)
            .with_context(|| format!("reading import archive {}", args.file.display()))?;
        match client
            .request_ok(Request::ImportSessionArchive {
                archive_base64: base64::engine::general_purpose::STANDARD.encode(bytes),
                as_new: args.as_new,
            })
            .await?
        {
            Response::ImportSessionArchive { imported, redacted } => {
                cockpit_core::session::import::ImportResult { imported, redacted }
            }
            other => {
                anyhow::bail!("daemon returned unexpected response to session import: {other:?}")
            }
        }
    } else {
        let archive = cockpit_core::session::import::read_archive(&args.file)?;
        let db = Db::open_default()?;
        cockpit_core::session::import::import_archive(&db, archive, args.as_new).await?
    };
    println!(
        "Imported {} session{}{}.",
        imported.imported.len(),
        if imported.imported.len() == 1 {
            ""
        } else {
            "s"
        },
        if imported.redacted {
            "; archive content was redacted"
        } else {
            ""
        },
    );
    Ok(())
}
