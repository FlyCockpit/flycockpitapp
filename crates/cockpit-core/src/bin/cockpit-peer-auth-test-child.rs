//! Minimal peer-auth client for issue #337 admission tests.
//!
//! Connects through the production `DaemonClient::connect` path (hello,
//! lifetime confirmation, peer-credential exchange) to
//! `COCKPIT_PEER_AUTH_SOCKET` and proves owner-class RPC admission
//! (`COCKPIT_PEER_AUTH_EXPECT=owner`) or denial
//! (`COCKPIT_PEER_AUTH_EXPECT=denied`).
//!
//! Optional env knobs: `COCKPIT_PEER_AUTH_LAUNCH_TICKET` installs the
//! process-held launch ticket the exchange presents, and
//! `COCKPIT_PEER_AUTH_GO_FILE` blocks the connect until the file exists (so
//! the test can install registry state first).

use std::path::Path;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use cockpit_proto::Request;

const WAIT_FILE_TIMEOUT: Duration = Duration::from_secs(60);
const WAIT_FILE_POLL: Duration = Duration::from_millis(20);

fn main() -> ExitCode {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("building peer-auth client runtime");
    let result = runtime.block_on(run_exchange_client());
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error:#}");
            ExitCode::FAILURE
        }
    }
}

fn install_launch_ticket_from_env() -> Result<()> {
    if let Ok(ticket) = std::env::var("COCKPIT_PEER_AUTH_LAUNCH_TICKET") {
        if ticket.is_empty() {
            bail!("COCKPIT_PEER_AUTH_LAUNCH_TICKET must not be empty");
        }
        cockpit_client::launch_provenance::set_process_launch_ticket(ticket);
    }
    Ok(())
}

async fn wait_for_file(path: &Path) -> Result<()> {
    let deadline = Instant::now() + WAIT_FILE_TIMEOUT;
    while !path.exists() {
        if Instant::now() >= deadline {
            bail!("timed out waiting for {}", path.display());
        }
        tokio::time::sleep(WAIT_FILE_POLL).await;
    }
    Ok(())
}

async fn owner_only_rpc_succeeds(client: &cockpit_client::DaemonClient) -> Result<()> {
    client
        .request_ok(Request::GetUsageCounts { project_id: None })
        .await
        .map(|_| ())
        .context("owner-only RPC through the exchanged credential")
}

async fn owner_only_rpc_is_denied(client: &cockpit_client::DaemonClient) -> Result<()> {
    match client
        .request(Request::GetUsageCounts { project_id: None })
        .await
    {
        Err(error) => Err(error.context("owner-only RPC transport")),
        Ok(Err(payload)) if payload.code == cockpit_proto::ErrorCode::Authorization => Ok(()),
        Ok(Err(payload)) => bail!("expected an authorization denial, got {payload:?}"),
        Ok(Ok(response)) => {
            bail!("owner-only RPC succeeded without a credential: {response:?}")
        }
    }
}

/// Production socket connect + exchange, then assert owner-class admission
/// or denial on the owner-only RPC.
async fn run_exchange_client() -> Result<()> {
    install_launch_ticket_from_env()?;
    let socket = std::env::var("COCKPIT_PEER_AUTH_SOCKET")
        .context("COCKPIT_PEER_AUTH_SOCKET is required")?;
    let expect = std::env::var("COCKPIT_PEER_AUTH_EXPECT")
        .context("COCKPIT_PEER_AUTH_EXPECT is required (owner | denied)")?;
    if let Ok(go_file) = std::env::var("COCKPIT_PEER_AUTH_GO_FILE") {
        wait_for_file(Path::new(&go_file)).await?;
    }

    // Production connect: hello, lifetime confirmation, peer-credential
    // exchange presenting the process-held launch ticket (if any).
    let client = cockpit_client::DaemonClient::connect(Path::new(&socket))
        .await
        .context("production daemon connect")?;

    match expect.as_str() {
        "owner" => {
            if !client.has_owner_capability() {
                bail!("expected an owner-class peer credential, got none");
            }
            owner_only_rpc_succeeds(&client).await
        }
        "denied" => {
            if client.has_owner_capability() {
                bail!("expected no owner-class credential, but the exchange minted one");
            }
            owner_only_rpc_is_denied(&client).await
        }
        other => bail!("unknown COCKPIT_PEER_AUTH_EXPECT: {other}"),
    }
}
