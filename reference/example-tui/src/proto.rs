//! NDJSON envelopes over a Unix socket.
//!
//! Same shape as `crates/cockpit-proto`: one JSON object per newline, with a
//! schema version `v` on every line so a mismatch is visible without buffering
//! the rest of the stream. Live connections require an exact version match.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, ReadHalf, WriteHalf};
use tokio::net::UnixStream;

pub const PROTOCOL_VERSION: u32 = 1;
pub const MAX_FRAME_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    pub v: u32,
    #[serde(flatten)]
    pub body: EnvelopeBody,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EnvelopeBody {
    Hello {
        protocol_version: u32,
        pid: u32,
        opened_at_unix_ms: u64,
        /// Version of the *worker* answering this connection. Under the
        /// supervised design this rolls forward on `excoc upgrade` while the
        /// supervisor and its socket stay put; the classic `daemon` reports 0.
        worker_version: u32,
        /// Which worker generation this is. Incremented by the supervisor on
        /// every roll or crash-respawn; the classic `daemon` reports 0.
        generation: u32,
    },
    Req {
        id: u64,
        body: Request,
    },
    Res {
        id: u64,
        body: Response,
    },
    Evt {
        body: Event,
    },
    /// Control frame: the daemon has handed off to `successor_pid` on the same
    /// canonical socket. A lifetime client should drop this connection and
    /// re-attach; it will land on the successor with the clock unbroken. This
    /// is the redirect half of "redirect-then-reconnect" — the successor
    /// re-negotiates hello, so a hot upgrade may change the protocol.
    Reconnect {
        successor_pid: u32,
    },
    Err {
        id: Option<u64>,
        message: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Request {
    /// Become a lifetime client and start receiving [`Event::Tick`].
    Subscribe,
    /// Snapshot the clock without participating in last-client teardown.
    Status,
    /// Hand the shared endpoint to a fresh daemon without losing uptime.
    ///
    /// The receiving daemon spawns a successor, hands it the open time, waits
    /// for it to bind a staging endpoint and health-check, then atomically
    /// promotes it onto the canonical socket. The response snapshots the
    /// **successor** so the caller can see the new pid and the continuous
    /// clock. Analog of a `cockpit-core` hot reload / self-upgrade.
    Reset,
    /// Sent by a resetting daemon to its freshly spawned successor: rename the
    /// staging socket + pid file onto the canonical paths, then adopt them.
    /// Only valid once, on an unpromoted successor. Never sent by an end user.
    Promote,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Response {
    pub pid: u32,
    pub opened_at_unix_ms: u64,
    pub elapsed_ms: u64,
    pub clients: usize,
    /// See [`EnvelopeBody::Hello::worker_version`]. 0 for the classic daemon.
    pub worker_version: u32,
    /// See [`EnvelopeBody::Hello::generation`]. 0 for the classic daemon.
    pub generation: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    pub elapsed_ms: u64,
    pub clients: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hello {
    pub protocol_version: u32,
    pub pid: u32,
    pub opened_at_unix_ms: u64,
    pub worker_version: u32,
    pub generation: u32,
}

impl Envelope {
    pub fn hello(pid: u32, opened_at_unix_ms: u64, worker_version: u32, generation: u32) -> Self {
        Self {
            v: PROTOCOL_VERSION,
            body: EnvelopeBody::Hello {
                protocol_version: PROTOCOL_VERSION,
                pid,
                opened_at_unix_ms,
                worker_version,
                generation,
            },
        }
    }

    pub fn req(id: u64, body: Request) -> Self {
        Self {
            v: PROTOCOL_VERSION,
            body: EnvelopeBody::Req { id, body },
        }
    }

    pub fn res(id: u64, body: Response) -> Self {
        Self {
            v: PROTOCOL_VERSION,
            body: EnvelopeBody::Res { id, body },
        }
    }

    pub fn evt(body: Event) -> Self {
        Self {
            v: PROTOCOL_VERSION,
            body: EnvelopeBody::Evt { body },
        }
    }

    pub fn reconnect(successor_pid: u32) -> Self {
        Self {
            v: PROTOCOL_VERSION,
            body: EnvelopeBody::Reconnect { successor_pid },
        }
    }

    pub fn error(id: Option<u64>, message: impl Into<String>) -> Self {
        Self {
            v: PROTOCOL_VERSION,
            body: EnvelopeBody::Err {
                id,
                message: message.into(),
            },
        }
    }

    pub fn as_hello(&self) -> Result<Hello> {
        self.check_version()?;
        match self.body {
            EnvelopeBody::Hello {
                protocol_version,
                pid,
                opened_at_unix_ms,
                worker_version,
                generation,
            } => {
                if protocol_version != PROTOCOL_VERSION {
                    bail!(
                        "incompatible daemon protocol {protocol_version} (this CLI speaks {PROTOCOL_VERSION})"
                    );
                }
                Ok(Hello {
                    protocol_version,
                    pid,
                    opened_at_unix_ms,
                    worker_version,
                    generation,
                })
            }
            _ => bail!("expected daemon hello, got {:?}", self.body),
        }
    }

    fn check_version(&self) -> Result<()> {
        if self.v != PROTOCOL_VERSION {
            bail!(
                "incompatible envelope version {} (this CLI speaks {PROTOCOL_VERSION})",
                self.v
            );
        }
        Ok(())
    }
}

pub struct ProtoStream {
    reader: BufReader<ReadHalf<UnixStream>>,
    writer: WriteHalf<UnixStream>,
}

impl ProtoStream {
    pub fn new(stream: UnixStream) -> Self {
        let (reader, writer) = tokio::io::split(stream);
        Self {
            reader: BufReader::new(reader),
            writer,
        }
    }

    pub async fn send(&mut self, envelope: &Envelope) -> Result<()> {
        let mut line = serde_json::to_string(envelope).context("serializing frame")?;
        line.push('\n');
        if line.len() > MAX_FRAME_BYTES {
            bail!("outgoing frame exceeded {MAX_FRAME_BYTES} bytes");
        }
        self.writer.write_all(line.as_bytes()).await?;
        self.writer.flush().await?;
        Ok(())
    }

    pub async fn recv(&mut self) -> Result<Option<Envelope>> {
        let mut line = String::new();
        let n = self.reader.read_line(&mut line).await?;
        if n == 0 {
            return Ok(None);
        }
        if line.len() > MAX_FRAME_BYTES {
            bail!("incoming frame exceeded {MAX_FRAME_BYTES} bytes");
        }
        let envelope: Envelope =
            serde_json::from_str(line.trim_end()).context("decoding NDJSON frame")?;
        envelope.check_version()?;
        Ok(Some(envelope))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hello_round_trip_is_tagged_ndjson() {
        let encoded = serde_json::to_string(&Envelope::hello(7, 42, 3, 5)).unwrap();
        assert!(encoded.contains("\"kind\":\"hello\""));
        let decoded: Envelope = serde_json::from_str(&encoded).unwrap();
        let hello = decoded.as_hello().unwrap();
        assert_eq!(hello.pid, 7);
        assert_eq!(hello.opened_at_unix_ms, 42);
        assert_eq!(hello.worker_version, 3);
        assert_eq!(hello.generation, 5);
    }

    #[test]
    fn refuses_other_schema_versions() {
        let encoded = r#"{"v":99,"kind":"hello","protocol_version":99,"pid":1,"opened_at_unix_ms":0,"worker_version":0,"generation":0}"#;
        let decoded: Envelope = serde_json::from_str(encoded).unwrap();
        let error = decoded.as_hello().unwrap_err().to_string();
        assert!(
            error.contains("incompatible envelope version 99"),
            "{error}"
        );
    }
}
