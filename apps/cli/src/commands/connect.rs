//! `cockpit connect {on,off,status}` — the daemon owns the FlyCockpit
//! connector state; this command is a socket client for the connector RPCs
//! and never opens SQLite or the vault.

use anyhow::{Context, Result, bail};
use serde::Deserialize;

use crate::cli::{ConnectArgs, ConnectCommand};
use crate::daemon::client::ensure_persistent_daemon;
use crate::daemon::proto::{Request, Response};

/// Non-secret projection of the daemon-owned connector state.
#[derive(Debug, Deserialize)]
struct ConnectorStateView {
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    status: String,
    #[serde(default)]
    relay_url: Option<String>,
    #[serde(default)]
    last_error: Option<String>,
}

pub async fn run(args: ConnectArgs) -> Result<()> {
    let daemon = ensure_persistent_daemon()
        .await
        .context("starting persistent daemon for FlyCockpit connector")?;
    let account = match daemon
        .client
        .request(Request::GetFlycockpitAccount)
        .await
        .context("requesting FlyCockpit account from daemon")?
        .map_err(|error| anyhow::anyhow!("daemon rejected FlyCockpit account query: {error}"))?
    {
        Response::FlycockpitAccount { account } => account,
        other => {
            bail!("daemon returned unexpected response to FlyCockpit account query: {other:?}")
        }
    };
    let Some(account) = account else {
        bail!("not logged in to FlyCockpit; run `cockpit account login` first");
    };

    match args.command.unwrap_or(ConnectCommand::Status) {
        ConnectCommand::On => {
            set_connector_enabled(&daemon.client, true).await?;
            println!(
                "Remote access enabled for instance {} on {}.",
                account.instance_id, account.server_url
            );
            println!("The daemon will connect outbound to the relay while it is running.");
        }
        ConnectCommand::Off => {
            set_connector_enabled(&daemon.client, false).await?;
            println!(
                "Remote access disabled for instance {} on {}.",
                account.instance_id, account.server_url
            );
        }
        ConnectCommand::Status => {
            let state = connector_state(&daemon.client).await?;
            print!(
                "{}",
                format_status(&account.server_url, &account.instance_id, state.as_ref())
            );
        }
    }
    Ok(())
}

async fn set_connector_enabled(client: &cockpit_client::DaemonClient, enabled: bool) -> Result<()> {
    match client
        .request(Request::SetFlycockpitConnectorEnabled { enabled })
        .await
        .context("requesting FlyCockpit connector update from daemon")?
        .map_err(|error| anyhow::anyhow!("daemon rejected FlyCockpit connector update: {error}"))?
    {
        Response::Ack => Ok(()),
        other => {
            bail!("daemon returned unexpected response to FlyCockpit connector update: {other:?}")
        }
    }
}

async fn connector_state(
    client: &cockpit_client::DaemonClient,
) -> Result<Option<ConnectorStateView>> {
    let Response::ConnectorState { connector_json } = client
        .request(Request::GetConnectorState)
        .await
        .context("requesting FlyCockpit connector state from daemon")?
        .map_err(|error| anyhow::anyhow!("daemon rejected FlyCockpit connector state: {error}"))?
    else {
        bail!("daemon returned unexpected response to FlyCockpit connector state query");
    };
    // The daemon emits `null` when no connector row exists yet.
    serde_json::from_str(&connector_json).context("parsing connector state")
}

fn format_status(
    server_url: &str,
    instance_id: &str,
    state: Option<&ConnectorStateView>,
) -> String {
    let mut out = String::new();
    out.push_str("FlyCockpit remote access\n");
    out.push_str(&format!("  server:   {server_url}\n"));
    out.push_str(&format!("  instance: {instance_id}\n"));
    match state {
        Some(state) => {
            out.push_str(&format!(
                "  enabled:  {}\n",
                if state.enabled { "yes" } else { "no" }
            ));
            out.push_str(&format!("  status:   {}\n", state.status));
            if let Some(relay_url) = state.relay_url.as_deref() {
                out.push_str(&format!("  relay:    {relay_url}\n"));
            }
            if let Some(error) = state.last_error.as_deref() {
                out.push_str(&format!("  error:    {error}\n"));
            }
        }
        None => {
            out.push_str("  enabled:  no\n");
            out.push_str("  status:   off\n");
        }
    }
    out
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

    #[test]
    fn status_without_connector_row_reports_off() {
        let rendered = format_status("https://app.example.test", "inst-1", None);
        assert!(rendered.contains("  server:   https://app.example.test\n"));
        assert!(rendered.contains("  instance: inst-1\n"));
        assert!(rendered.contains("  enabled:  no\n"));
        assert!(rendered.contains("  status:   off\n"));
    }

    #[test]
    fn status_renders_enabled_connector_with_relay_and_error() {
        let state = ConnectorStateView {
            enabled: true,
            status: "connected".to_string(),
            relay_url: Some("wss://relay.example.test/ws".to_string()),
            last_error: Some("transient reset".to_string()),
        };
        let rendered = format_status("https://app.example.test", "inst-1", Some(&state));
        assert!(rendered.contains("  enabled:  yes\n"));
        assert!(rendered.contains("  status:   connected\n"));
        assert!(rendered.contains("  relay:    wss://relay.example.test/ws\n"));
        assert!(rendered.contains("  error:    transient reset\n"));
    }

    #[test]
    fn connector_state_view_parses_null_projection() {
        let parsed: Option<ConnectorStateView> = serde_json::from_str("null").unwrap();
        assert!(parsed.is_none());
    }
}
