//! `cockpit sync` subcommands.

use anyhow::{Context, Result};

use crate::auth::flycockpit::maybe_load_credential;
use crate::cli::SyncCommand;
use crate::db::Db;

pub async fn run(cmd: SyncCommand) -> Result<()> {
    match cmd {
        SyncCommand::Status => status(),
    }
}

fn status() -> Result<()> {
    let db = Db::open_default().context("opening cockpit DB")?;
    let states = db.list_org_sync_states()?;
    let credential = maybe_load_credential();
    if states.is_empty() {
        println!("session log sync: inactive");
        return Ok(());
    }

    println!("session log sync");
    for state in states {
        let current = credential
            .as_ref()
            .map(|cred| cred.server_url == state.server_url)
            .unwrap_or(false);
        println!(
            "  {}{} / {}: {}",
            state.server_url,
            if current { " (current)" } else { "" },
            state.org_id,
            if state.enabled { "active" } else { "inactive" }
        );
        println!("    cursor: {}", state.cursor_seq);
        if let Some(version) = state.policy_version.as_deref() {
            println!("    policy: {version}");
        }
        if let Some(last_synced) = state.last_synced_at_ms {
            println!("    last synced: {last_synced}");
        }
        if let Some(error) = state.last_error.as_deref() {
            println!("    last error: {error}");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sync_command_status_is_routable() {
        let command = SyncCommand::Status;
        assert!(matches!(command, SyncCommand::Status));
    }
}
