//! `cockpit sync` subcommands. The daemon owns org-policy sync and
//! remote-audit-upload state; this command is a socket client for
//! `GetOrgSyncStatus` and never opens SQLite or the vault.

use anyhow::{Context, Result, bail};
use serde::Deserialize;

use crate::cli::SyncCommand;
use crate::daemon::client::ensure_persistent_daemon;
use crate::daemon::proto::{Request, Response};

/// Non-secret projection of one org-policy sync state row.
#[derive(Debug, Deserialize)]
struct OrgSyncStateView {
    server_url: String,
    org_id: String,
    cursor_seq: i64,
    #[serde(default)]
    policy_version: Option<String>,
    enabled: bool,
    #[serde(default)]
    last_synced_at_ms: Option<i64>,
    #[serde(default)]
    last_error: Option<String>,
}

/// Non-secret projection of one remote-audit upload cursor row.
#[derive(Debug, Deserialize)]
struct AuditUploadStateView {
    server_url: String,
    instance_id: String,
    cursor_audit_id: i64,
    #[serde(default)]
    last_uploaded_at_ms: Option<i64>,
    #[serde(default)]
    last_error: Option<String>,
}

/// The current account's connector state, used to render the audit-upload
/// "active/inactive" flag exactly as the direct-DB path did.
#[derive(Debug, Deserialize)]
struct ConnectorForSync {
    server_url: String,
    instance_id: String,
    #[serde(default)]
    enabled: bool,
}

pub async fn run(cmd: SyncCommand) -> Result<()> {
    match cmd {
        SyncCommand::Status => status().await,
    }
}

async fn status() -> Result<()> {
    let daemon = ensure_persistent_daemon()
        .await
        .context("starting persistent daemon for org sync status")?;
    let Response::OrgSyncStatus {
        org_states_json,
        audit_states_json,
    } = daemon
        .client
        .request(Request::GetOrgSyncStatus)
        .await
        .context("requesting org sync status from daemon")?
        .map_err(|error| anyhow::anyhow!("daemon rejected org sync status: {error}"))?
    else {
        bail!("daemon returned unexpected response to org sync status query");
    };
    let org_states: Vec<OrgSyncStateView> =
        serde_json::from_str(&org_states_json).context("parsing org sync states")?;
    let audit_states: Vec<AuditUploadStateView> =
        serde_json::from_str(&audit_states_json).context("parsing audit upload states")?;

    // The account (when present) only marks the "(current)" server/instance, a
    // cosmetic disclosure, so it stays best-effort (matching the prior optional
    // credential load). The connector state, by contrast, DRIVES the
    // audit-upload active/inactive flag: a transient RPC/parse failure there
    // must surface, never silently downgrade to "inactive".
    let account = match daemon.client.request(Request::GetFlycockpitAccount).await {
        Ok(Ok(Response::FlycockpitAccount { account })) => account,
        _ => None,
    };
    let connector = fetch_connector_state(&daemon.client).await?;
    let (current_server, current_instance) = match &account {
        Some(account) => (
            Some(account.server_url.as_str()),
            Some(account.instance_id.as_str()),
        ),
        None => (None, None),
    };

    print!(
        "{}",
        format_sync_status(
            &org_states,
            &audit_states,
            current_server,
            current_instance,
            connector.as_ref(),
        )
    );
    Ok(())
}

/// Read the current account's connector state, propagating RPC and parse
/// failures instead of downgrading them to a benign "inactive". The daemon
/// emits `null` when no connector row exists yet — the only legitimate `None`.
async fn fetch_connector_state(
    client: &cockpit_client::DaemonClient,
) -> Result<Option<ConnectorForSync>> {
    let Response::ConnectorState { connector_json } = client
        .request(Request::GetConnectorState)
        .await
        .context("requesting FlyCockpit connector state from daemon")?
        .map_err(|error| anyhow::anyhow!("daemon rejected FlyCockpit connector state: {error}"))?
    else {
        bail!("daemon returned unexpected response to FlyCockpit connector state query");
    };
    parse_connector_state(&connector_json)
}

fn parse_connector_state(connector_json: &str) -> Result<Option<ConnectorForSync>> {
    serde_json::from_str(connector_json).context("parsing connector state")
}

fn format_sync_status(
    org_states: &[OrgSyncStateView],
    audit_states: &[AuditUploadStateView],
    current_server: Option<&str>,
    current_instance: Option<&str>,
    connector: Option<&ConnectorForSync>,
) -> String {
    let mut out = String::new();

    if org_states.is_empty() {
        out.push_str("session log sync: inactive\n");
    } else {
        out.push_str("session log sync\n");
        for state in org_states {
            let current = current_server == Some(state.server_url.as_str());
            out.push_str(&format!(
                "  {}{} / {}: {}\n",
                state.server_url,
                if current { " (current)" } else { "" },
                state.org_id,
                if state.enabled { "active" } else { "inactive" }
            ));
            out.push_str(&format!("    cursor: {}\n", state.cursor_seq));
            if let Some(version) = state.policy_version.as_deref() {
                out.push_str(&format!("    policy: {version}\n"));
            }
            if let Some(last_synced) = state.last_synced_at_ms {
                out.push_str(&format!("    last synced: {last_synced}\n"));
            }
            if let Some(error) = state.last_error.as_deref() {
                out.push_str(&format!("    last error: {error}\n"));
            }
        }
    }

    if audit_states.is_empty() {
        out.push_str("remote audit upload: inactive\n");
    } else {
        out.push_str("remote audit upload\n");
        for state in audit_states {
            let current = current_server == Some(state.server_url.as_str())
                && current_instance == Some(state.instance_id.as_str());
            let connect_enabled = connector
                .map(|connector| {
                    connector.server_url == state.server_url
                        && connector.instance_id == state.instance_id
                        && connector.enabled
                })
                .unwrap_or(false);
            out.push_str(&format!(
                "  {}{} / {}: {}\n",
                state.server_url,
                if current { " (current)" } else { "" },
                state.instance_id,
                if connect_enabled {
                    "active"
                } else {
                    "inactive"
                }
            ));
            out.push_str(&format!("    cursor: {}\n", state.cursor_audit_id));
            if let Some(last_uploaded) = state.last_uploaded_at_ms {
                out.push_str(&format!("    last uploaded: {last_uploaded}\n"));
            }
            if let Some(error) = state.last_error.as_deref() {
                out.push_str(&format!("    last error: {error}\n"));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sync_command_status_is_routable() {
        let command = SyncCommand::Status;
        assert!(matches!(command, SyncCommand::Status));
    }

    #[test]
    fn connector_state_null_is_none_but_malformed_surfaces() {
        // `null` is the only legitimate `None` (no connector row yet).
        assert!(parse_connector_state("null").unwrap().is_none());
        let parsed = parse_connector_state(
            r#"{"server_url":"https://app.example.test","instance_id":"inst-1","enabled":true}"#,
        )
        .unwrap()
        .expect("a populated connector row parses to Some");
        assert!(parsed.enabled);
        // A malformed payload must NOT be swallowed to None/"inactive" — a wrong
        // impl using `.ok().flatten()` would return None here.
        assert!(
            parse_connector_state(r#"{"enabled":"#).is_err(),
            "a malformed connector payload must surface as an error, not inactive"
        );
    }

    #[test]
    fn empty_states_render_inactive() {
        let rendered = format_sync_status(&[], &[], None, None, None);
        assert!(rendered.contains("session log sync: inactive\n"));
        assert!(rendered.contains("remote audit upload: inactive\n"));
    }

    #[test]
    fn current_marker_and_connector_active_flag_are_applied() {
        let org = vec![OrgSyncStateView {
            server_url: "https://app.example.test".into(),
            org_id: "org-1".into(),
            cursor_seq: 42,
            policy_version: Some("v3".into()),
            enabled: true,
            last_synced_at_ms: Some(123),
            last_error: None,
        }];
        let audit = vec![AuditUploadStateView {
            server_url: "https://app.example.test".into(),
            instance_id: "inst-1".into(),
            cursor_audit_id: 7,
            last_uploaded_at_ms: Some(456),
            last_error: Some("stalled".into()),
        }];
        let connector = ConnectorForSync {
            server_url: "https://app.example.test".into(),
            instance_id: "inst-1".into(),
            enabled: true,
        };
        let rendered = format_sync_status(
            &org,
            &audit,
            Some("https://app.example.test"),
            Some("inst-1"),
            Some(&connector),
        );
        assert!(rendered.contains("https://app.example.test (current) / org-1: active\n"));
        assert!(rendered.contains("    cursor: 42\n"));
        assert!(rendered.contains("    policy: v3\n"));
        assert!(rendered.contains("https://app.example.test (current) / inst-1: active\n"));
        assert!(rendered.contains("    last uploaded: 456\n"));
        assert!(rendered.contains("    last error: stalled\n"));
    }

    #[test]
    fn audit_inactive_when_connector_disabled_or_absent() {
        let audit = vec![AuditUploadStateView {
            server_url: "https://app.example.test".into(),
            instance_id: "inst-1".into(),
            cursor_audit_id: 7,
            last_uploaded_at_ms: None,
            last_error: None,
        }];
        // Connector present but disabled → inactive (distinguishing input: a
        // wrong impl keying off the audit row alone would show active).
        let disabled = ConnectorForSync {
            server_url: "https://app.example.test".into(),
            instance_id: "inst-1".into(),
            enabled: false,
        };
        let rendered = format_sync_status(&[], &audit, None, None, Some(&disabled));
        assert!(rendered.contains(" / inst-1: inactive\n"));
        // No connector at all → also inactive.
        let none = format_sync_status(&[], &audit, None, None, None);
        assert!(none.contains(" / inst-1: inactive\n"));
    }
}
