use anyhow::{Context, Result};

use crate::auth::flycockpit::{
    ConnectionStatus, DEFAULT_SERVER_URL, FlycockpitClient, StoredFlycockpitCredential,
    clear_credential, default_display_name, load_credential, maybe_load_credential,
    store_credential,
};
use crate::cli::LoginArgs;
use crate::daemon::DaemonStatus;
use crate::daemon::client::DaemonClient;
use crate::daemon::proto::{Request, Response};
use crate::db::connector::ConnectorDisclosure;
use crate::db::org_sync::OrgSyncDisclosure;

pub async fn login(args: LoginArgs) -> Result<()> {
    if let Some(existing) = maybe_load_credential()
        && !args.force
    {
        anyhow::bail!(
            "already logged in to Flycockpit as {} on {}; run `cockpit account logout` first or pass `--force`",
            existing.account.email,
            existing.server_url
        );
    }

    let client = FlycockpitClient::new(if args.server.trim().is_empty() {
        DEFAULT_SERVER_URL
    } else {
        args.server.as_str()
    })?;
    let display_name = args
        .name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .unwrap_or_else(default_display_name);
    let existing_instance_id = maybe_load_credential().map(|credential| credential.instance_id);

    let login = client.begin_device_code_login().await?;
    eprintln!("Open this URL to authorize Flycockpit account access:");
    eprintln!("{}", login.open_url());
    eprintln!(
        "Enter this one-time code in any browser: {}",
        login.user_code
    );
    if let Err(error) = crate::browser::open(login.open_url()) {
        eprintln!("Could not open browser ({error}). Open the URL manually.");
    }

    let credential = client
        .complete_device_code_login_without_store(login, Some(display_name), existing_instance_id)
        .await?;
    println!(
        "Logged in to Flycockpit as {} on {}",
        credential.account.email, credential.server_url
    );
    println!("Instance: {}", credential.instance_id);
    let enable_remote_access = remote_access_choice(&args)?;
    let db = crate::db::Db::open_default().ok();
    if let Some(db) = db.as_ref() {
        if let Err(error) = db.set_connector_enabled(
            &credential.server_url,
            &credential.instance_id,
            enable_remote_access,
        ) {
            tracing::warn!(error = %error, "Flycockpit account login: updating remote access setting failed");
        } else if enable_remote_access {
            println!("Remote access: enabled (use `cockpit connect off` to disable)");
        } else {
            println!("Remote access: disabled (use `cockpit connect on` to enable)");
        }
    }
    store_credential_via_daemon_or_direct(&credential).await?;
    if let Some(db) = db.as_ref()
        && let Err(error) = crate::daemon::org_sync::sync_current_credential_once(db).await
    {
        tracing::warn!(error = %error, "Flycockpit account login: best-effort org sync policy check failed");
    }
    Ok(())
}

pub async fn logout() -> Result<()> {
    let credential = match load_credential() {
        Ok(credential) => credential,
        Err(_) => {
            println!("Not logged in to Flycockpit.");
            return Ok(());
        }
    };
    if let Ok(client) = FlycockpitClient::new(&credential.server_url)
        && let Err(error) = client.revoke_instance(&credential).await
    {
        tracing::warn!(error = %error, "Flycockpit account logout: best-effort instance revoke failed");
    }
    clear_credential_via_daemon_or_direct().await?;
    if let Ok(db) = crate::db::Db::open_default()
        && let Err(error) = db.mark_org_sync_disabled(&credential.server_url)
    {
        tracing::warn!(error = %error, "Flycockpit account logout: disabling org sync state failed");
    }
    println!("Logged out of Flycockpit.");
    Ok(())
}

async fn running_persistent_daemon_client() -> Result<Option<DaemonClient>> {
    let discovered = crate::daemon::discover().await;
    if !matches!(discovered.status, DaemonStatus::Running) {
        return Ok(None);
    }
    match DaemonClient::connect(&discovered.paths.socket).await {
        Ok(client) => Ok(Some(client)),
        Err(error) => {
            tracing::warn!(error = %error, "Flycockpit credential RPC: running daemon disappeared; falling back to direct credential file write");
            eprintln!(
                "Flycockpit credential RPC failed because the daemon disappeared; writing credentials directly."
            );
            Ok(None)
        }
    }
}

async fn store_credential_via_daemon_or_direct(
    credential: &StoredFlycockpitCredential,
) -> Result<()> {
    if let Some(client) = running_persistent_daemon_client().await? {
        match client
            .request(Request::StoreFlycockpitCredential {
                credential: credential.clone(),
            })
            .await
        {
            Ok(Ok(Response::Ack)) => return Ok(()),
            Ok(Ok(other)) => anyhow::bail!(
                "daemon returned unexpected response to Flycockpit credential store: {other:?}"
            ),
            Ok(Err(error)) => {
                anyhow::bail!("daemon rejected Flycockpit credential store: {error}")
            }
            Err(error) => {
                tracing::warn!(error = %error, "Flycockpit credential RPC failed; falling back to direct credential file write");
                eprintln!("Flycockpit credential RPC failed; writing credentials directly.");
            }
        }
    }
    store_credential(credential).context("storing Flycockpit credentials")
}

async fn clear_credential_via_daemon_or_direct() -> Result<()> {
    if let Some(client) = running_persistent_daemon_client().await? {
        match client.request(Request::ClearFlycockpitCredential).await {
            Ok(Ok(Response::Ack)) => return Ok(()),
            Ok(Ok(other)) => anyhow::bail!(
                "daemon returned unexpected response to Flycockpit credential clear: {other:?}"
            ),
            Ok(Err(error)) => {
                anyhow::bail!("daemon rejected Flycockpit credential clear: {error}")
            }
            Err(error) => {
                tracing::warn!(error = %error, "Flycockpit credential clear RPC failed; falling back to direct credential file write");
                eprintln!("Flycockpit credential clear RPC failed; clearing credentials directly.");
            }
        }
    }
    clear_credential().context("clearing Flycockpit credentials")
}

pub async fn whoami() -> Result<()> {
    let credential = match load_credential() {
        Ok(credential) => credential,
        Err(_) => {
            println!("Not logged in to Flycockpit.");
            return Ok(());
        }
    };
    let status = match FlycockpitClient::new(&credential.server_url) {
        Ok(client) => client.connection_status(&credential).await,
        Err(error) => ConnectionStatus::Error(error.to_string()),
    };
    let (sync, connector) = crate::db::Db::open_default()
        .ok()
        .map(|db| {
            let sync = db
                .org_sync_disclosure_for_server(&credential.server_url)
                .ok()
                .flatten();
            let connector = db
                .connector_disclosure(&credential.server_url, &credential.instance_id)
                .ok()
                .flatten();
            (sync, connector)
        })
        .unwrap_or((None, None));
    print!(
        "{}",
        render_whoami_with_sync_and_connector(
            &credential,
            &status,
            sync.as_ref(),
            connector.as_ref(),
        )
    );
    Ok(())
}

#[cfg(test)]
pub fn render_whoami(credential: &StoredFlycockpitCredential, status: &ConnectionStatus) -> String {
    render_whoami_with_sync(credential, status, None)
}

#[cfg(test)]
pub fn render_whoami_with_sync(
    credential: &StoredFlycockpitCredential,
    status: &ConnectionStatus,
    sync: Option<&OrgSyncDisclosure>,
) -> String {
    render_whoami_with_sync_and_connector(credential, status, sync, None)
}

pub fn render_whoami_with_sync_and_connector(
    credential: &StoredFlycockpitCredential,
    status: &ConnectionStatus,
    sync: Option<&OrgSyncDisclosure>,
    connector: Option<&ConnectorDisclosure>,
) -> String {
    let mut out = String::new();
    out.push_str("Flycockpit account\n");
    out.push_str(&format!("  server:     {}\n", credential.server_url));
    out.push_str(&format!("  account:    {}\n", credential.account.email));
    out.push_str(&format!("  user id:    {}\n", credential.account.user_id));
    out.push_str(&format!("  instance:   {}\n", credential.instance_id));
    if let Some(name) = credential.display_name.as_deref().filter(|s| !s.is_empty()) {
        out.push_str(&format!("  name:       {name}\n"));
    }
    out.push_str(&format!("  connection: {}\n", status_label(status)));
    if let Some(connector) = connector {
        let label = if connector.enabled {
            match connector.relay_url.as_deref() {
                Some(url) if connector.status == "connected" => {
                    match (
                        connector.relay_id.as_deref(),
                        connector.relay_region.as_deref(),
                    ) {
                        (Some(relay_id), Some(region)) => {
                            format!("connected ({url}, {relay_id}, {region})")
                        }
                        (Some(relay_id), None) => format!("connected ({url}, {relay_id})"),
                        _ => format!("connected ({url})"),
                    }
                }
                _ => connector.status.clone(),
            }
        } else {
            "off".to_string()
        };
        out.push_str(&format!("  remote:     {label}\n"));
        if let Some(error) = connector.last_error.as_deref() {
            out.push_str(&format!("  remote err: {error}\n"));
        }
    }
    if let Some(sync) = sync {
        out.push_str(&format!(
            "  org sync:   active (org {}, cursor {})\n",
            sync.org_id, sync.cursor_seq
        ));
    }
    out
}

fn remote_access_choice(args: &LoginArgs) -> Result<bool> {
    let mut stdin = std::io::stdin().lock();
    let mut stderr = std::io::stderr();
    remote_access_choice_with_io(args, &mut stdin, &mut stderr)
}

fn remote_access_choice_with_io<R: std::io::BufRead, W: std::io::Write>(
    args: &LoginArgs,
    input: &mut R,
    output: &mut W,
) -> Result<bool> {
    if args.remote {
        return Ok(true);
    }
    if args.no_remote {
        return Ok(false);
    }
    prompt_remote_access_default_yes(input, output)
}

fn prompt_remote_access_default_yes<R: std::io::BufRead, W: std::io::Write>(
    input: &mut R,
    output: &mut W,
) -> Result<bool> {
    write!(output, "Enable remote access for this machine? [Y/n] ")?;
    let _ = output.flush();
    let mut answer = String::new();
    let read = input
        .read_line(&mut answer)
        .context("reading remote access preference")?;
    if read == 0 {
        return Ok(true);
    }
    Ok(parse_remote_access_answer(&answer))
}

fn parse_remote_access_answer(answer: &str) -> bool {
    !matches!(
        answer.trim().to_ascii_lowercase().as_str(),
        "n" | "no" | "false" | "0"
    )
}

fn status_label(status: &ConnectionStatus) -> String {
    match status {
        ConnectionStatus::Unknown => "unknown".to_string(),
        ConnectionStatus::Online { relay_url } => match relay_url.as_deref() {
            Some(url) => format!("online ({url})"),
            None => "online".to_string(),
        },
        ConnectionStatus::Revoked => "revoked (credentials cleared)".to_string(),
        ConnectionStatus::Unauthorized => "unauthorized".to_string(),
        ConnectionStatus::Error(message) => format!("error: {message}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::flycockpit::AccountInfo;
    use std::ffi::OsString;

    struct EnvRestore {
        _guard: std::sync::MutexGuard<'static, ()>,
        old_state_home: Option<OsString>,
        old_runtime_dir: Option<OsString>,
    }

    impl EnvRestore {
        fn isolate_daemon_and_credentials(root: &std::path::Path) -> Self {
            let guard = crate::test_env::lock();
            let state_home = root.join("state");
            let runtime_dir = root.join("runtime");
            std::fs::create_dir_all(&state_home).unwrap();
            std::fs::create_dir_all(&runtime_dir).unwrap();
            let old_state_home = std::env::var_os("XDG_STATE_HOME");
            let old_runtime_dir = std::env::var_os("XDG_RUNTIME_DIR");
            unsafe {
                std::env::set_var("XDG_STATE_HOME", state_home);
                std::env::set_var("XDG_RUNTIME_DIR", runtime_dir);
            }
            Self {
                _guard: guard,
                old_state_home,
                old_runtime_dir,
            }
        }
    }

    impl Drop for EnvRestore {
        fn drop(&mut self) {
            unsafe {
                match &self.old_state_home {
                    Some(value) => std::env::set_var("XDG_STATE_HOME", value),
                    None => std::env::remove_var("XDG_STATE_HOME"),
                }
                match &self.old_runtime_dir {
                    Some(value) => std::env::set_var("XDG_RUNTIME_DIR", value),
                    None => std::env::remove_var("XDG_RUNTIME_DIR"),
                }
            }
        }
    }

    fn credential() -> StoredFlycockpitCredential {
        StoredFlycockpitCredential {
            server_url: "https://app.example.test".to_string(),
            instance_id: "inst-1".to_string(),
            instance_token: "fci_secret".to_string(),
            account: AccountInfo {
                user_id: "user-1".to_string(),
                email: "user@example.test".to_string(),
            },
            display_name: Some("Workstation".to_string()),
            relay_choice: None,
        }
    }

    #[tokio::test]
    async fn store_and_clear_credential_fall_back_to_direct_write_without_daemon() {
        let tmp = tempfile::tempdir().unwrap();
        let _env = EnvRestore::isolate_daemon_and_credentials(tmp.path());
        let credential_path = tmp.path().join("state/cockpit/credentials.json");
        let credential = credential();

        store_credential_via_daemon_or_direct(&credential)
            .await
            .unwrap();
        assert_eq!(
            crate::auth::flycockpit::load_credential_from_path(credential_path.clone()).unwrap(),
            credential
        );

        clear_credential_via_daemon_or_direct().await.unwrap();
        assert!(crate::auth::flycockpit::load_credential_from_path(credential_path).is_err());
    }

    #[test]
    fn remote_access_login_answer_defaults_yes() {
        assert!(parse_remote_access_answer(""));
        assert!(parse_remote_access_answer("yes"));
        assert!(parse_remote_access_answer("Y"));
        assert!(!parse_remote_access_answer("n"));
        assert!(!parse_remote_access_answer("No"));
    }

    #[test]
    fn login_no_remote_skips_prompt() {
        struct PanicBufRead;

        impl std::io::Read for PanicBufRead {
            fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
                panic!("--no-remote must not read stdin");
            }
        }

        impl std::io::BufRead for PanicBufRead {
            fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
                panic!("--no-remote must not read stdin");
            }

            fn consume(&mut self, _amt: usize) {}
        }

        let args = LoginArgs {
            server: DEFAULT_SERVER_URL.to_string(),
            name: None,
            force: false,
            remote: false,
            no_remote: true,
        };
        let mut input = PanicBufRead;
        let mut output = Vec::new();

        assert!(!remote_access_choice_with_io(&args, &mut input, &mut output).unwrap());
        assert!(output.is_empty());
    }

    #[test]
    fn whoami_logged_in_output_is_stable_and_secret_free() {
        let out = render_whoami(
            &credential(),
            &ConnectionStatus::Online {
                relay_url: Some("wss://relay.example.test/ws".to_string()),
            },
        );
        assert!(out.contains("server:     https://app.example.test"));
        assert!(out.contains("account:    user@example.test"));
        assert!(out.contains("instance:   inst-1"));
        assert!(out.contains("name:       Workstation"));
        assert!(out.contains("connection: online (wss://relay.example.test/ws)"));
        assert!(!out.contains("fci_secret"));
    }

    #[test]
    fn whoami_revoked_output_is_stable() {
        let out = render_whoami(&credential(), &ConnectionStatus::Revoked);
        assert!(out.contains("connection: revoked (credentials cleared)"));
    }

    #[test]
    fn whoami_discloses_connector_status() {
        let connector = ConnectorDisclosure {
            enabled: true,
            status: "connected".to_string(),
            relay_url: Some("wss://relay.example.test/ws".to_string()),
            relay_id: Some("relay-1".to_string()),
            relay_region: Some("iad".to_string()),
            last_error: None,
        };
        let out = render_whoami_with_sync_and_connector(
            &credential(),
            &ConnectionStatus::Unknown,
            None,
            Some(&connector),
        );
        assert!(out.contains("remote:     connected (wss://relay.example.test/ws, relay-1, iad)"));
        assert!(!out.contains("fci_secret"));
    }

    #[test]
    fn whoami_discloses_active_org_sync() {
        let disclosure = OrgSyncDisclosure {
            org_id: "org-1".to_string(),
            cursor_seq: 42,
            last_synced_at_ms: Some(123),
        };
        let out =
            render_whoami_with_sync(&credential(), &ConnectionStatus::Unknown, Some(&disclosure));
        assert!(out.contains("org sync:   active (org org-1, cursor 42)"));
        assert!(!out.contains("fci_secret"));
    }
}
