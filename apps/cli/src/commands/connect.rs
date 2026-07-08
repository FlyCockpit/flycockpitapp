use anyhow::{Context, Result};

use crate::auth::flycockpit::load_credential;
use crate::cli::{ConnectArgs, ConnectCommand};

pub async fn run(args: ConnectArgs) -> Result<()> {
    let credential = load_credential()?;
    let db = crate::db::Db::open_default().context("opening cockpit database")?;
    match args.command.unwrap_or(ConnectCommand::Status) {
        ConnectCommand::On => {
            db.set_connector_enabled(&credential.server_url, &credential.instance_id, true)?;
            println!(
                "Remote access enabled for instance {} on {}.",
                credential.instance_id, credential.server_url
            );
            println!("The daemon will connect outbound to the relay while it is running.");
        }
        ConnectCommand::Off => {
            db.set_connector_enabled(&credential.server_url, &credential.instance_id, false)?;
            println!(
                "Remote access disabled for instance {} on {}.",
                credential.instance_id, credential.server_url
            );
        }
        ConnectCommand::Status => {
            let state = db.connector_state(&credential.server_url, &credential.instance_id)?;
            println!("Flycockpit remote access");
            println!("  server:   {}", credential.server_url);
            println!("  instance: {}", credential.instance_id);
            match state {
                Some(state) => {
                    println!("  enabled:  {}", if state.enabled { "yes" } else { "no" });
                    println!("  status:   {}", state.status);
                    if let Some(relay_url) = state.relay_url.as_deref() {
                        println!("  relay:    {relay_url}");
                    }
                    if let Some(error) = state.last_error.as_deref() {
                        println!("  error:    {error}");
                    }
                }
                None => {
                    println!("  enabled:  no");
                    println!("  status:   off");
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_connect_command_is_status() {
        let args = ConnectArgs { command: None };
        assert_eq!(
            args.command.unwrap_or(ConnectCommand::Status),
            ConnectCommand::Status
        );
    }
}
