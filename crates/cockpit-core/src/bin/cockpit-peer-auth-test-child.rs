//! Minimal peer-auth client for issue #337 admission tests.
//!
//! Connects through the production daemon accept path, exchanges a peer-bound
//! credential, and proves owner-class RPC admission with the returned token.

use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use cockpit_proto::{Body, Envelope, ProtoStream, Request, Response};
use tokio::net::UnixStream;
use uuid::Uuid;

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<()> {
    let socket_path = std::env::var("COCKPIT_PEER_AUTH_SOCKET")
        .context("COCKPIT_PEER_AUTH_SOCKET is required")?;
    let expected_role = std::env::var("COCKPIT_PEER_AUTH_EXPECTED_ROLE")
        .context("COCKPIT_PEER_AUTH_EXPECTED_ROLE is required")?;

    let stream = UnixStream::connect(&socket_path)
        .await
        .with_context(|| format!("connecting to {socket_path}"))?;
    let mut client = ProtoStream::new(stream);

    match client.recv().await.context("receive daemon hello")? {
        cockpit_proto::RecvFrame::Envelope(envelope) => match envelope.body {
            Body::Response { response, .. }
                if matches!(*response, Response::DaemonStatus { .. }) => {}
            other => bail!("expected daemon hello, got {other:?}"),
        },
        other => bail!("expected hello envelope, got {other:?}"),
    }

    let status_id = Uuid::now_v7();
    client
        .send(&Envelope::request(status_id, Request::DaemonStatus))
        .await
        .context("send lifetime confirmation")?;
    match client
        .recv()
        .await
        .context("receive lifetime confirmation")?
    {
        cockpit_proto::RecvFrame::Envelope(envelope) => match envelope.body {
            Body::Response { id, .. } if id == status_id => {}
            other => bail!("unexpected lifetime confirmation response: {other:?}"),
        },
        other => bail!("expected lifetime confirmation envelope, got {other:?}"),
    }

    let exchange_id = Uuid::now_v7();
    client
        .send(&Envelope::request(
            exchange_id,
            Request::ExchangeLocalPeerCredential,
        ))
        .await
        .context("send peer credential exchange")?;
    let token = match client.recv().await.context("receive peer credential")? {
        cockpit_proto::RecvFrame::Envelope(envelope) => match envelope.body {
            Body::Response { id, response } if id == exchange_id => match *response {
                Response::LocalPeerCredential { token, role } => {
                    let observed = match role {
                        cockpit_proto::LocalClientRole::Tui => "tui",
                        cockpit_proto::LocalClientRole::Cli => "cli",
                        cockpit_proto::LocalClientRole::Acp => "acp",
                        cockpit_proto::LocalClientRole::AgentChild => "agent_child",
                    };
                    if observed != expected_role {
                        bail!("expected role {expected_role}, observed {observed}");
                    }
                    token
                }
                other => bail!("expected LocalPeerCredential, got {other:?}"),
            },
            other => bail!("unexpected peer credential response: {other:?}"),
        },
        other => bail!("expected peer credential envelope, got {other:?}"),
    };

    let secret_id = Uuid::now_v7();
    client
        .send(&Envelope::request_with_owner_capability(
            secret_id,
            Request::PutNamedSecret {
                name: "k".into(),
                value: "v".into(),
            },
            Some(token),
        ))
        .await
        .context("send owner-only RPC with exchanged credential")?;
    match client
        .recv()
        .await
        .context("receive owner-only RPC response")?
    {
        cockpit_proto::RecvFrame::Envelope(envelope) => match envelope.body {
            Body::Error {
                id: Some(id),
                error,
            } if id == secret_id => {
                if error.code == cockpit_proto::ErrorCode::Authorization {
                    bail!(
                        "owner-only RPC denied after credential exchange: {}",
                        error.message
                    );
                }
            }
            Body::Response { id, .. } if id == secret_id => {}
            other => bail!("unexpected owner-only RPC response: {other:?}"),
        },
        other => bail!("expected owner-only RPC envelope, got {other:?}"),
    }

    Ok(())
}
