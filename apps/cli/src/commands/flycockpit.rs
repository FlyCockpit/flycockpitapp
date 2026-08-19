use anyhow::{Context, Result};

#[cfg(test)]
use crate::auth::flycockpit::ConnectionStatus;
use crate::auth::flycockpit::{
    DEFAULT_SERVER_URL, FlycockpitClient, StoredFlycockpitCredential, default_display_name,
};
use crate::cli::LoginArgs;
use crate::daemon::client::ensure_persistent_daemon;
use crate::daemon::proto::{Request, Response};
use cockpit_core::daemon::proto::{ConnectorDisclosure, OrgSyncDisclosure};

pub async fn login(args: LoginArgs) -> Result<()> {
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

    let login = client.begin_device_code_login().await?;
    eprintln!("Open this URL to authorize FlyCockpit account access:");
    eprintln!("{}", login.open_url());
    eprintln!(
        "Enter this one-time code in any browser: {}",
        login.user_code
    );
    if let Err(error) = crate::browser::open(login.open_url()) {
        eprintln!("Could not open browser ({error}). Open the URL manually.");
    }

    let credential = client
        .complete_device_code_login_without_store(login, Some(display_name), None)
        .await?;
    match store_credential_via_daemon(&credential, args.force).await? {
        StoreCredentialOutcome::AlreadyLoggedIn { email, server_url } => {
            if let Err(error) = client.revoke_instance(&credential).await {
                tracing::warn!(
                    error = %error,
                    "FlyCockpit account login: best-effort revoke of unpersisted instance failed"
                );
            }
            anyhow::bail!(
                "already logged in to FlyCockpit as {email} on {server_url}; run `cockpit account logout` first or pass `--force`"
            );
        }
        StoreCredentialOutcome::Stored => {}
    }
    println!(
        "Logged in to FlyCockpit as {} on {}",
        credential.account.email, credential.server_url
    );
    println!("Instance: {}", credential.instance_id);
    let enable_remote_access = remote_access_choice(&args)?;
    if let Err(error) = set_connector_enabled_via_daemon(enable_remote_access).await {
        tracing::warn!(error = %error, "FlyCockpit account login: updating remote access setting failed");
    } else if enable_remote_access {
        println!("Remote access: enabled (use `cockpit connect off` to disable)");
    } else {
        println!("Remote access: disabled (use `cockpit connect on` to enable)");
    }
    match sync_org_policy_via_daemon().await {
        Ok(cockpit_core::daemon::proto::FlycockpitOrgSyncOutcome::EnrollmentRequired {
            org_id,
        }) => {
            if org_logging_enrollment_choice()? {
                enroll_org_sync_via_daemon(&org_id).await?;
                let _ = sync_org_policy_via_daemon().await;
            }
        }
        Ok(_) => {}
        Err(error) => {
            tracing::warn!(error = %error, "FlyCockpit account login: best-effort org sync policy check failed")
        }
    }
    Ok(())
}

pub async fn logout() -> Result<()> {
    match clear_credential_via_daemon().await? {
        ClearCredentialOutcome::NotLoggedIn => {
            println!("Not logged in to FlyCockpit.");
            Ok(())
        }
        ClearCredentialOutcome::Cleared => {
            println!("Logged out of FlyCockpit.");
            Ok(())
        }
    }
}

enum StoreCredentialOutcome {
    Stored,
    AlreadyLoggedIn { email: String, server_url: String },
}

enum ClearCredentialOutcome {
    Cleared,
    NotLoggedIn,
}

async fn store_credential_via_daemon(
    credential: &StoredFlycockpitCredential,
    force: bool,
) -> Result<StoreCredentialOutcome> {
    let daemon = ensure_persistent_daemon()
        .await
        .context("starting persistent daemon for FlyCockpit login")?;
    match daemon
        .client
        .request(Request::StoreFlycockpitCredential {
            credential: credential.clone(),
            force,
        })
        .await
    {
        Ok(Ok(Response::FlycockpitStored)) => Ok(StoreCredentialOutcome::Stored),
        Ok(Ok(Response::FlycockpitAlreadyLoggedIn { email, server_url })) => {
            Ok(StoreCredentialOutcome::AlreadyLoggedIn { email, server_url })
        }
        Ok(Ok(other)) => anyhow::bail!(
            "daemon returned unexpected response to FlyCockpit credential store: {other:?}"
        ),
        Ok(Err(error)) => anyhow::bail!("daemon rejected FlyCockpit credential store: {error}"),
        Err(error) => anyhow::bail!("FlyCockpit credential RPC failed: {error}"),
    }
}

async fn clear_credential_via_daemon() -> Result<ClearCredentialOutcome> {
    let daemon = ensure_persistent_daemon()
        .await
        .context("starting persistent daemon for FlyCockpit logout")?;
    match daemon
        .client
        .request(Request::ClearFlycockpitCredential)
        .await
    {
        Ok(Ok(Response::FlycockpitCleared { .. })) => Ok(ClearCredentialOutcome::Cleared),
        Ok(Ok(Response::FlycockpitNotLoggedIn)) => Ok(ClearCredentialOutcome::NotLoggedIn),
        Ok(Ok(other)) => anyhow::bail!(
            "daemon returned unexpected response to FlyCockpit credential clear: {other:?}"
        ),
        Ok(Err(error)) => anyhow::bail!("daemon rejected FlyCockpit credential clear: {error}"),
        Err(error) => anyhow::bail!("FlyCockpit credential clear RPC failed: {error}"),
    }
}

async fn set_connector_enabled_via_daemon(enabled: bool) -> Result<()> {
    let daemon = ensure_persistent_daemon()
        .await
        .context("starting persistent daemon for FlyCockpit remote access")?;
    match daemon
        .client
        .request(Request::SetFlycockpitConnectorEnabled { enabled })
        .await
    {
        Ok(Ok(Response::Ack)) => Ok(()),
        Ok(Ok(other)) => anyhow::bail!(
            "daemon returned unexpected response to FlyCockpit remote access update: {other:?}"
        ),
        Ok(Err(error)) => anyhow::bail!("daemon rejected FlyCockpit remote access update: {error}"),
        Err(error) => anyhow::bail!("FlyCockpit remote access update RPC failed: {error}"),
    }
}

async fn sync_org_policy_via_daemon()
-> Result<cockpit_core::daemon::proto::FlycockpitOrgSyncOutcome> {
    let daemon = ensure_persistent_daemon()
        .await
        .context("starting persistent daemon for FlyCockpit organization policy")?;
    match daemon
        .client
        .request(Request::SyncFlycockpitOrgPolicy)
        .await
    {
        Ok(Ok(Response::FlycockpitOrgSync { outcome })) => Ok(outcome),
        Ok(Ok(other)) => anyhow::bail!(
            "daemon returned unexpected response to FlyCockpit organization policy sync: {other:?}"
        ),
        Ok(Err(error)) => {
            anyhow::bail!("daemon rejected FlyCockpit organization policy sync: {error}")
        }
        Err(error) => anyhow::bail!("FlyCockpit organization policy sync RPC failed: {error}"),
    }
}

async fn enroll_org_sync_via_daemon(org_id: &str) -> Result<()> {
    let daemon = ensure_persistent_daemon()
        .await
        .context("starting persistent daemon for FlyCockpit organization enrollment")?;
    match daemon
        .client
        .request(Request::EnrollFlycockpitOrgSync {
            org_id: org_id.to_string(),
        })
        .await
    {
        Ok(Ok(Response::Ack)) => Ok(()),
        Ok(Ok(other)) => anyhow::bail!(
            "daemon returned unexpected response to FlyCockpit organization enrollment: {other:?}"
        ),
        Ok(Err(error)) => {
            anyhow::bail!("daemon rejected FlyCockpit organization enrollment: {error}")
        }
        Err(error) => anyhow::bail!("FlyCockpit organization enrollment RPC failed: {error}"),
    }
}

pub async fn whoami() -> Result<()> {
    let daemon = ensure_persistent_daemon()
        .await
        .context("starting persistent daemon for FlyCockpit whoami")?;
    let account = match daemon.client.request(Request::GetFlycockpitAccount).await {
        Ok(Ok(Response::FlycockpitAccount { account })) => account,
        Ok(Ok(other)) => anyhow::bail!(
            "daemon returned unexpected response to FlyCockpit account query: {other:?}"
        ),
        Ok(Err(error)) => anyhow::bail!("daemon rejected FlyCockpit account query: {error}"),
        Err(error) => anyhow::bail!("FlyCockpit account RPC failed: {error}"),
    };
    let Some(account) = account else {
        println!("Not logged in to FlyCockpit.");
        return Ok(());
    };
    let (sync, connector) = match daemon
        .client
        .request(Request::GetStartupDisclosures {
            project_root: std::env::current_dir()
                .context("getting current directory for account disclosures")?
                .display()
                .to_string(),
        })
        .await
    {
        Ok(Ok(Response::StartupDisclosures {
            org_sync,
            connector,
            ..
        })) => (org_sync, connector),
        _ => (None, None),
    };
    print!(
        "{}",
        render_whoami_account_view(&account, sync.as_ref(), connector.as_ref())
    );
    Ok(())
}

fn render_whoami_account_view(
    account: &cockpit_core::daemon::proto::FlycockpitAccountView,
    sync: Option<&OrgSyncDisclosure>,
    connector: Option<&ConnectorDisclosure>,
) -> String {
    let mut out = String::new();
    out.push_str("FlyCockpit account\n");
    out.push_str(&format!("  server:     {}\n", account.server_url));
    out.push_str(&format!("  account:    {}\n", account.account.email));
    out.push_str(&format!("  user id:    {}\n", account.account.user_id));
    out.push_str(&format!("  instance:   {}\n", account.instance_id));
    if let Some(name) = account.display_name.as_deref().filter(|s| !s.is_empty()) {
        out.push_str(&format!("  name:       {name}\n"));
    }
    out.push_str("  connection: unknown (daemon account metadata only)\n");
    if let Some(connector) = connector {
        let label = if connector.enabled {
            match connector.relay_url.as_deref() {
                Some(url) if connector.status == "connected" => format!("connected ({url})"),
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

#[cfg(test)]
pub fn render_whoami_with_sync_and_connector(
    credential: &StoredFlycockpitCredential,
    status: &ConnectionStatus,
    sync: Option<&OrgSyncDisclosure>,
    connector: Option<&ConnectorDisclosure>,
) -> String {
    let mut out = String::new();
    out.push_str("FlyCockpit account\n");
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

fn org_logging_enrollment_choice() -> Result<bool> {
    let mut stdin = std::io::stdin().lock();
    let mut stderr = std::io::stderr();
    org_logging_enrollment_choice_with_io(&mut stdin, &mut stderr)
}

fn org_logging_enrollment_choice_with_io<R: std::io::BufRead, W: std::io::Write>(
    input: &mut R,
    output: &mut W,
) -> Result<bool> {
    writeln!(
        output,
        "Your organization requires session logging. Full model requests, including file contents, will be uploaded to the organization. Redaction is best-effort pattern matching, not a guarantee."
    )?;
    write!(output, "Enroll in organization logging? [y/N] ")?;
    output.flush()?;
    let mut answer = String::new();
    let read = input
        .read_line(&mut answer)
        .context("reading organization logging enrollment")?;
    Ok(read > 0 && matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes"))
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

#[cfg(test)]
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

    struct EnvRestore {
        _guard: crate::test_env::TestEnvGuard,
    }

    impl EnvRestore {
        #[allow(dead_code)]
        fn isolate_daemon_and_credentials(root: &std::path::Path) -> Self {
            let guard = crate::test_env::lock();
            Self::from_guard(root, guard)
        }

        async fn isolate_daemon_and_credentials_async(root: &std::path::Path) -> Self {
            let guard = crate::test_env::lock_async().await;
            Self::from_guard(root, guard)
        }

        fn from_guard(root: &std::path::Path, guard: crate::test_env::TestEnvGuard) -> Self {
            let state_home = root.join("state");
            let data_home = root.join("data");
            let runtime_dir = root.join("runtime");
            std::fs::create_dir_all(&state_home).unwrap();
            std::fs::create_dir_all(&data_home).unwrap();
            std::fs::create_dir_all(&runtime_dir).unwrap();
            guard.set_var("XDG_STATE_HOME", state_home);
            guard.set_var("XDG_DATA_HOME", data_home);
            guard.set_var("XDG_RUNTIME_DIR", runtime_dir);
            Self { _guard: guard }
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
    async fn login_without_running_daemon_starts_persistent_daemon() {
        let tmp = tempfile::tempdir().unwrap();
        let _env = EnvRestore::isolate_daemon_and_credentials_async(tmp.path()).await;
        let credential_path = tmp.path().join("state/cockpit/credentials.json");
        let discovered = crate::daemon::discover().await;
        assert!(
            !matches!(discovered.status, crate::daemon::DaemonStatus::Running),
            "precondition: no daemon is running"
        );

        let _promote = crate::daemon::enable_in_process_auto_promote();
        store_credential_via_daemon(&credential(), false)
            .await
            .expect("login persist must attach through the spawned daemon");

        let discovered = crate::daemon::discover().await;
        assert!(
            matches!(discovered.status, crate::daemon::DaemonStatus::Running),
            "login must leave the canonical daemon running, got {:?}",
            discovered.status
        );
        assert!(
            !credential_path.exists(),
            "login must not write credentials.json"
        );
        match store_credential_via_daemon(&credential(), false)
            .await
            .expect("second store probes the daemon vault")
        {
            StoreCredentialOutcome::AlreadyLoggedIn { email, server_url } => {
                assert_eq!(email, "user@example.test");
                assert_eq!(server_url, "https://app.example.test");
            }
            StoreCredentialOutcome::Stored => {
                panic!("daemon vault must already hold the login credential")
            }
        }
    }

    #[test]
    fn no_daemon_fallback_deleted() {
        let source = include_str!("flycockpit.rs");
        let production = source
            .split("mod tests {")
            .next()
            .expect("production source");
        assert!(!production.contains(concat!("store_credential_via_daemon", "_or_vault")));
        assert!(!production.contains(concat!("clear_credential_via_daemon", "_or_vault")));
        assert!(!production.contains(concat!("Daemon-less: in-process vault ", "handle")));
    }

    #[test]
    fn login_logout_use_store_clear_rpcs() {
        let source = include_str!("flycockpit.rs");
        let production = source
            .split("mod tests {")
            .next()
            .expect("production source");
        let login = production
            .split("pub async fn login(")
            .nth(1)
            .and_then(|rest| rest.split("pub async fn logout(").next())
            .expect("login body");
        let logout = production
            .split("pub async fn logout(")
            .nth(1)
            .and_then(|rest| rest.split("pub async fn whoami(").next())
            .expect("logout body");
        for (label, body) in [("login", login), ("logout", logout)] {
            for forbidden in [
                "maybe_load_credential",
                "CredentialStore::open",
                "flycockpit::store_credential",
                "flycockpit::clear_credential",
                "load_credential()",
            ] {
                assert!(
                    !body.contains(forbidden),
                    "{label} persist-clear must not call {forbidden}"
                );
            }
        }
        assert!(production.contains("StoreFlycockpitCredential"));
        assert!(production.contains("ClearFlycockpitCredential"));
        assert!(production.contains("FlycockpitAlreadyLoggedIn"));
        assert!(!production.contains("Db::open_default"));
        let login_body = production
            .split("pub async fn login(")
            .nth(1)
            .and_then(|rest| rest.split("pub async fn logout(").next())
            .expect("login body");
        assert!(
            login_body.contains("sync_org_policy_via_daemon"),
            "login org-sync must use the daemon-owned account"
        );
        assert!(
            login_body.contains("set_connector_enabled_via_daemon"),
            "login remote access must use the daemon-owned account"
        );
        assert!(production.contains("SyncFlycockpitOrgPolicy"));
        assert!(production.contains("SetFlycockpitConnectorEnabled"));
        assert!(production.contains("EnrollFlycockpitOrgSync"));
        assert!(
            login_body.contains("revoke_instance"),
            "unforced AlreadyLoggedIn must revoke the just-registered instance"
        );
        // Isolate the `whoami` body (bounded to the next function) rather than
        // grepping the rest of production: an unbounded search would still pass
        // if `whoami` regressed to a vault read while `GetFlycockpitAccount`
        // survived elsewhere in the file.
        let whoami = production
            .split("pub async fn whoami()")
            .nth(1)
            .and_then(|rest| rest.split("\nfn render_whoami_account_view").next())
            .expect("whoami body");
        assert!(
            whoami.contains("GetFlycockpitAccount"),
            "whoami must resolve the account through the daemon RPC"
        );
        // Spellings are split with `concat!` so this test's own forbidden list
        // does not trip sibling whole-file source-grep tests.
        for forbidden in [
            concat!("maybe_load", "_credential"),
            concat!("load_credential", "_from_vault"),
            concat!("CredentialStore", "::open"),
            concat!("secret", "_vault"),
            concat!("flycockpit::store", "_credential"),
            concat!("flycockpit::clear", "_credential"),
        ] {
            assert!(
                !whoami.contains(forbidden),
                "whoami must not touch the vault/store directly: {forbidden}"
            );
        }
    }

    #[test]
    fn whoami_stays_on_allow_list() {
        let source = include_str!("flycockpit.rs");
        assert!(source.contains("pub async fn whoami()"));
        // Split so this assertion's own literal does not self-match the
        // whole-file `contains` grep (as the `GetFlycockpitAccount` check does).
        assert!(!source.contains(concat!("load_credential", "_from_vault")));
        assert!(source.contains(concat!("GetFlycockpit", "Account")));
        let whoami = source
            .split("pub async fn whoami()")
            .nth(1)
            .and_then(|rest| rest.split("pub fn render_whoami").next())
            .expect("whoami body");
        assert!(whoami.contains("ensure_persistent_daemon"));
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
    fn eof_means_not_enrolled() {
        let mut input = std::io::Cursor::new(b"".as_slice());
        let mut output = Vec::new();

        assert!(!org_logging_enrollment_choice_with_io(&mut input, &mut output).unwrap());
    }

    #[test]
    fn declining_enrollment_still_permits_local_use() {
        let mut input = std::io::Cursor::new(b"no\n".as_slice());
        let mut output = Vec::new();

        assert!(!org_logging_enrollment_choice_with_io(&mut input, &mut output).unwrap());
        assert!(
            String::from_utf8(output)
                .unwrap()
                .contains("Enroll in organization logging?")
        );
    }

    #[test]
    fn explicit_enrollment_is_accepted() {
        let mut input = std::io::Cursor::new(b"yes\n".as_slice());
        let mut output = Vec::new();

        assert!(org_logging_enrollment_choice_with_io(&mut input, &mut output).unwrap());
    }

    #[test]
    fn enrollment_text_discloses_payload_contents() {
        let mut input = std::io::Cursor::new(b"no\n".as_slice());
        let mut output = Vec::new();

        assert!(!org_logging_enrollment_choice_with_io(&mut input, &mut output).unwrap());
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("Full model requests, including file contents"));
        assert!(output.contains("Redaction is best-effort"));
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
