//! Typed client over the daemon's NDJSON protocol.
//!
//! Analog of `crates/cockpit-client`. A connected [`Client`] has already
//! negotiated hello and sent `Subscribe`, so it counts as a lifetime client
//! the way Cockpit's connect path claims the ephemeral reference before the
//! caller can be cancelled.

use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use tokio::net::UnixStream;

use crate::paths::Paths;
use crate::proto::{
    Envelope, EnvelopeBody, Event, Hello, PROTOCOL_VERSION, ProtoStream, Request, Response,
};

const HELLO_TIMEOUT: Duration = Duration::from_millis(500);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    pub pid: u32,
    pub opened_at_unix_ms: u64,
    pub elapsed_ms: u64,
    pub clients: usize,
    pub worker_version: u32,
    pub generation: u32,
}

/// What a lifetime client observed on its event stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Update {
    /// A normal uptime tick.
    Tick(Event),
    /// The daemon handed off; re-attach to land on `successor_pid`.
    Reconnect { successor_pid: u32 },
    /// The daemon closed the connection with no successor.
    Closed,
}

pub struct Client {
    stream: ProtoStream,
    next_id: u64,
    pub hello: Hello,
    pub snapshot: Snapshot,
}

impl Client {
    /// Connect and become a lifetime client.
    ///
    /// Connect and hello are each bounded by `HELLO_TIMEOUT`, matching
    /// [`probe`]. Without it a wedged peer (stale socket, half-open accept)
    /// hangs forever and slips past `lifecycle::wait_for_daemon`'s deadline,
    /// which only re-checks the clock *between* attempts.
    pub async fn connect(socket: &Path) -> Result<Self> {
        let mut stream = tokio::time::timeout(HELLO_TIMEOUT, connect_stream(socket))
            .await
            .with_context(|| format!("timed out connecting to {}", socket.display()))??;
        let hello = tokio::time::timeout(HELLO_TIMEOUT, read_hello(&mut stream))
            .await
            .context("timed out waiting for daemon hello")??;
        let mut client = Self {
            stream,
            next_id: 1,
            hello,
            snapshot: Snapshot {
                pid: 0,
                opened_at_unix_ms: 0,
                elapsed_ms: 0,
                clients: 0,
                worker_version: 0,
                generation: 0,
            },
        };
        let snapshot = client.request(Request::Subscribe).await?;
        client.hello.pid = snapshot.pid;
        client.hello.opened_at_unix_ms = snapshot.opened_at_unix_ms;
        client.hello.worker_version = snapshot.worker_version;
        client.hello.generation = snapshot.generation;
        client.snapshot = Snapshot {
            pid: snapshot.pid,
            opened_at_unix_ms: snapshot.opened_at_unix_ms,
            elapsed_ms: snapshot.elapsed_ms,
            clients: snapshot.clients,
            worker_version: snapshot.worker_version,
            generation: snapshot.generation,
        };
        Ok(client)
    }

    pub async fn request(&mut self, body: Request) -> Result<Response> {
        let id = self.next_id;
        self.next_id += 1;
        self.stream.send(&Envelope::req(id, body)).await?;
        loop {
            let envelope = tokio::time::timeout(REQUEST_TIMEOUT, self.stream.recv())
                .await
                .context("timed out waiting for daemon response")?
                .context("reading daemon response")?
                .context("daemon closed during request")?;
            match envelope.body {
                EnvelopeBody::Res {
                    id: response_id,
                    body,
                } if response_id == id => return Ok(body),
                EnvelopeBody::Err {
                    id: Some(error_id),
                    message,
                } if error_id == id => bail!("{message}"),
                EnvelopeBody::Evt { .. } => continue,
                other => bail!("unexpected frame during request: {other:?}"),
            }
        }
    }

    pub async fn next_update(&mut self) -> Result<Update> {
        match self.stream.recv().await? {
            None => Ok(Update::Closed),
            Some(envelope) => match envelope.body {
                EnvelopeBody::Evt { body } => Ok(Update::Tick(body)),
                EnvelopeBody::Reconnect { successor_pid } => {
                    Ok(Update::Reconnect { successor_pid })
                }
                EnvelopeBody::Err { message, .. } => bail!("{message}"),
                EnvelopeBody::Hello { .. }
                | EnvelopeBody::Req { .. }
                | EnvelopeBody::Res { .. } => {
                    bail!("unexpected frame on event stream: {:?}", envelope.body)
                }
            },
        }
    }
}

/// A control connection that negotiates hello but never sends `Subscribe`, so
/// it does not become a lifetime client. Used for one-shot request/response
/// control verbs — `excoc reset` toward the running daemon, and the predecessor
/// driving its successor's `Promote` — where becoming a lifetime client would
/// wrongly hold the peer open (or, on a fresh successor, trip its reaper).
pub struct Control {
    stream: ProtoStream,
    next_id: u64,
    pub hello: Hello,
}

impl Control {
    pub async fn connect(socket: &Path) -> Result<Self> {
        let mut stream = tokio::time::timeout(HELLO_TIMEOUT, connect_stream(socket))
            .await
            .with_context(|| format!("timed out connecting to {}", socket.display()))??;
        let hello = tokio::time::timeout(HELLO_TIMEOUT, read_hello(&mut stream))
            .await
            .context("timed out waiting for daemon hello")??;
        Ok(Self {
            stream,
            next_id: 1,
            hello,
        })
    }

    pub async fn request(&mut self, body: Request) -> Result<Response> {
        let id = self.next_id;
        self.next_id += 1;
        self.stream.send(&Envelope::req(id, body)).await?;
        loop {
            let envelope = tokio::time::timeout(REQUEST_TIMEOUT, self.stream.recv())
                .await
                .context("timed out waiting for daemon response")?
                .context("reading daemon response")?
                .context("daemon closed during request")?;
            match envelope.body {
                EnvelopeBody::Res {
                    id: response_id,
                    body,
                } if response_id == id => return Ok(body),
                EnvelopeBody::Err {
                    id: Some(error_id),
                    message,
                } if error_id == id => bail!("{message}"),
                // A control connection never subscribes, so it should not see
                // ticks or reconnects, but skip them defensively.
                EnvelopeBody::Evt { .. } | EnvelopeBody::Reconnect { .. } => continue,
                other => bail!("unexpected frame during request: {other:?}"),
            }
        }
    }
}

/// Hello-only reachability probe. Does **not** send `Subscribe`, so it never
/// keeps an ephemeral daemon alive. Analog of Cockpit's `socket_responds`.
pub async fn probe(paths: &Paths) -> Result<Option<Snapshot>> {
    if !paths.socket.exists() {
        return Ok(None);
    }
    let mut stream =
        match tokio::time::timeout(HELLO_TIMEOUT, UnixStream::connect(&paths.socket)).await {
            Ok(Ok(stream)) => ProtoStream::new(stream),
            _ => return Ok(None),
        };
    let hello = match tokio::time::timeout(HELLO_TIMEOUT, read_hello(&mut stream)).await {
        Ok(Ok(hello)) => hello,
        _ => return Ok(None),
    };
    stream.send(&Envelope::req(1, Request::Status)).await.ok();
    let snapshot = match tokio::time::timeout(HELLO_TIMEOUT, stream.recv()).await {
        Ok(Ok(Some(envelope))) => match envelope.body {
            EnvelopeBody::Res { body, .. } => Snapshot {
                pid: body.pid,
                opened_at_unix_ms: body.opened_at_unix_ms,
                elapsed_ms: body.elapsed_ms,
                clients: body.clients,
                worker_version: body.worker_version,
                generation: body.generation,
            },
            _ => Snapshot {
                pid: hello.pid,
                opened_at_unix_ms: hello.opened_at_unix_ms,
                elapsed_ms: 0,
                clients: 0,
                worker_version: hello.worker_version,
                generation: hello.generation,
            },
        },
        _ => Snapshot {
            pid: hello.pid,
            opened_at_unix_ms: hello.opened_at_unix_ms,
            elapsed_ms: 0,
            clients: 0,
            worker_version: hello.worker_version,
            generation: hello.generation,
        },
    };
    Ok(Some(snapshot))
}

async fn connect_stream(socket: &Path) -> Result<ProtoStream> {
    let stream = UnixStream::connect(socket)
        .await
        .with_context(|| format!("connecting to {}", socket.display()))?;
    Ok(ProtoStream::new(stream))
}

async fn read_hello(stream: &mut ProtoStream) -> Result<Hello> {
    let envelope = stream
        .recv()
        .await?
        .context("daemon closed before sending hello")?;
    if envelope.v != PROTOCOL_VERSION {
        bail!(
            "incompatible daemon protocol {} (this CLI speaks {PROTOCOL_VERSION})",
            envelope.v
        );
    }
    envelope.as_hello()
}
