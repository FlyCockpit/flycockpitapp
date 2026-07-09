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
    let org_states = db.list_org_sync_states()?;
    let audit_states = db.list_remote_audit_upload_states()?;
    let credential = maybe_load_credential();

    if org_states.is_empty() {
        println!("session log sync: inactive");
    } else {
        println!("session log sync");
        for state in org_states {
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
    }

    if audit_states.is_empty() {
        println!("remote audit upload: inactive");
    } else {
        println!("remote audit upload");
        for state in audit_states {
            let current = credential
                .as_ref()
                .map(|cred| {
                    cred.server_url == state.server_url && cred.instance_id == state.instance_id
                })
                .unwrap_or(false);
            let connect_enabled = db
                .connector_state(&state.server_url, &state.instance_id)?
                .map(|connector| connector.enabled)
                .unwrap_or(false);
            println!(
                "  {}{} / {}: {}",
                state.server_url,
                if current { " (current)" } else { "" },
                state.instance_id,
                if connect_enabled {
                    "active"
                } else {
                    "inactive"
                }
            );
            println!("    cursor: {}", state.cursor_audit_id);
            if let Some(last_uploaded) = state.last_uploaded_at_ms {
                println!("    last uploaded: {last_uploaded}");
            }
            if let Some(error) = state.last_error.as_deref() {
                println!("    last error: {error}");
            }
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
