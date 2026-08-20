//! `cockpit kcl import` — one-way registry import from a local kcl
//! install (prompt `docs-agent.md` component A). The daemon owns the
//! registry: this command is a socket client for `ImportKclPackages` and
//! never opens SQLite.

use anyhow::{Context, Result, bail};
use serde::Deserialize;

use crate::cli::KclCommand;
use crate::daemon::client::ensure_persistent_daemon;
use crate::daemon::proto::{Request, Response};

pub async fn run(cmd: KclCommand) -> Result<()> {
    match cmd {
        KclCommand::Import => import().await,
    }
}

/// Daemon-owned `import_kcl_packages` result projection: either the imported
/// package count, or the path where no kcl registry was found.
#[derive(Debug, Deserialize)]
struct KclImportResult {
    #[serde(default)]
    imported: Option<u64>,
    #[serde(default)]
    no_kcl_db: Option<String>,
}

async fn import() -> Result<()> {
    let cwd = std::env::current_dir()?;
    let daemon = ensure_persistent_daemon()
        .await
        .context("starting persistent daemon for kcl import")?;
    let response = daemon
        .client
        .request(Request::ImportKclPackages {
            project_root: cwd.display().to_string(),
        })
        .await
        .context("requesting kcl import from daemon")?
        .map_err(|error| anyhow::anyhow!("daemon rejected kcl import: {error}"))?;
    let Response::KclPackagesImported { result_json } = response else {
        bail!("daemon returned unexpected response to kcl import: {response:?}");
    };
    let result: KclImportResult =
        serde_json::from_str(&result_json).context("parsing kcl import result")?;
    println!("{}", format_kcl_import(&result));
    Ok(())
}

fn format_kcl_import(result: &KclImportResult) -> String {
    if let Some(path) = &result.no_kcl_db {
        format!("No kcl registry found at {path} — nothing to import.")
    } else {
        let count = result.imported.unwrap_or(0);
        format!("Imported {count} package(s) from kcl.")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn imported_count_is_rendered() {
        let result = KclImportResult {
            imported: Some(3),
            no_kcl_db: None,
        };
        assert_eq!(
            format_kcl_import(&result),
            "Imported 3 package(s) from kcl."
        );
    }

    #[test]
    fn missing_registry_reports_probe_path() {
        let result = KclImportResult {
            imported: None,
            no_kcl_db: Some("/home/u/.kcl/registry".to_string()),
        };
        assert_eq!(
            format_kcl_import(&result),
            "No kcl registry found at /home/u/.kcl/registry — nothing to import."
        );
    }

    #[test]
    fn result_parses_from_daemon_projection() {
        let imported: KclImportResult = serde_json::from_str(r#"{"imported":5}"#).unwrap();
        assert_eq!(
            format_kcl_import(&imported),
            "Imported 5 package(s) from kcl."
        );
        let absent: KclImportResult = serde_json::from_str(r#"{"no_kcl_db":"/tmp/kcl"}"#).unwrap();
        assert_eq!(
            format_kcl_import(&absent),
            "No kcl registry found at /tmp/kcl — nothing to import."
        );
    }
}
