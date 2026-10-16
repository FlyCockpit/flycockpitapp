//! Bounded transport for complete configuration publications. Logical snapshots
//! can grow when independently valid layers compose. Physical NDJSON frames
//! always stay below the decoder ceiling; readers adopt only a complete digest.
use super::*;
use base64::Engine as _;
use sha2::{Digest, Sha256};

pub const MAX_CONFIG_TRANSFER_BYTES: usize = 32 * 1024 * 1024;
const CHUNK_BYTES: usize = 64 * 1024;
const TRANSFER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
const KIND: &str = "config_chunk";

#[derive(Serialize, Deserialize)]
struct Chunk {
    v: u32,
    kind: String,
    digest: String,
    offset: usize,
    total: usize,
    data: String,
}

pub(super) fn eligible(env: &Envelope) -> bool {
    match &env.body {
        Body::Event {
            event: Event::ConfigSnapshot { .. },
        } => true,
        Body::Response { response, .. } => matches!(
            response.as_ref(),
            Response::ProviderMutationCommitted { .. }
        ),
        _ => false,
    }
}

pub(super) async fn send<T>(framed: &mut T, env: &Envelope, line: String) -> Result<()>
where
    T: futures::Sink<String, Error = LinesCodecError> + Unpin,
{
    if line.len() <= MAX_NDJSON_FRAME_BYTES {
        return framed
            .send(line)
            .await
            .map_err(codec_error)
            .context("writing envelope");
    }
    anyhow::ensure!(eligible(env), "envelope exceeds NDJSON frame limit");
    anyhow::ensure!(
        line.len() <= MAX_CONFIG_TRANSFER_BYTES,
        "configuration publication exceeds complete transfer limit"
    );
    let digest = hex(&Sha256::digest(line.as_bytes()));
    let transfer = async {
        for (index, bytes) in line.as_bytes().chunks(CHUNK_BYTES).enumerate() {
            let chunk = Chunk {
                v: PROTOCOL_VERSION,
                kind: KIND.into(),
                digest: digest.clone(),
                offset: index * CHUNK_BYTES,
                total: line.len(),
                data: base64::engine::general_purpose::STANDARD.encode(bytes),
            };
            let json = serde_json::to_string(&chunk)?;
            anyhow::ensure!(
                json.len() <= MAX_NDJSON_FRAME_BYTES,
                "configuration chunk exceeds frame limit"
            );
            framed
                .send(json)
                .await
                .map_err(codec_error)
                .context("writing configuration chunk")?;
        }
        Ok(())
    };
    tokio::time::timeout(TRANSFER_TIMEOUT, transfer)
        .await
        .context("configuration publication deadline exceeded")?
}

/// Assembly belongs to the read side of the connection, never to a recv future.
/// Every consumed physical frame is recorded before the next await. Cancelling
/// recv (for example to send an outbound request) retains bytes and the original
/// deadline; resuming cannot extend the transfer's lifetime.
#[derive(Default)]
pub(super) struct Receiver {
    assembly: Option<Assembly>,
}

struct Assembly {
    total: usize,
    digest: String,
    bytes: Vec<u8>,
    deadline: tokio::time::Instant,
}

impl Receiver {
    pub(super) async fn receive<T>(
        &mut self,
        framed: &mut T,
    ) -> Result<Option<(serde_json::Value, bool)>>
    where
        T: futures::Stream<Item = std::result::Result<String, LinesCodecError>> + Unpin,
    {
        loop {
            let line = if let Some(assembly) = &self.assembly {
                tokio::time::timeout_at(assembly.deadline, recv_raw_line(framed))
                    .await
                    .context("configuration transfer deadline exceeded")??
                    .context("incomplete configuration transfer")?
            } else {
                let Some(line) = recv_raw_line(framed).await? else {
                    return Ok(None);
                };
                line
            };
            let value: serde_json::Value = serde_json::from_str(&line)
                .context("deserializing envelope/configuration chunk")?;
            if self.assembly.is_none()
                && value.get("kind").and_then(serde_json::Value::as_str) != Some(KIND)
            {
                return Ok(Some((value, false)));
            }
            let chunk: Chunk =
                serde_json::from_value(value).context("deserializing configuration chunk")?;
            if self.assembly.is_none() {
                anyhow::ensure!(
                    chunk.total > MAX_NDJSON_FRAME_BYTES
                        && chunk.total <= MAX_CONFIG_TRANSFER_BYTES
                        && chunk.digest.len() == 64,
                    "invalid configuration transfer size or digest"
                );
                self.assembly = Some(Assembly {
                    total: chunk.total,
                    digest: chunk.digest.clone(),
                    bytes: Vec::new(),
                    deadline: tokio::time::Instant::now() + TRANSFER_TIMEOUT,
                });
            }
            let assembly = self.assembly.as_mut().expect("assembly initialized");
            anyhow::ensure!(
                chunk.v == PROTOCOL_VERSION
                    && chunk.kind == KIND
                    && chunk.total == assembly.total
                    && chunk.digest == assembly.digest
                    && chunk.offset == assembly.bytes.len(),
                "configuration transfer identity or offset mismatch"
            );
            anyhow::ensure!(
                chunk.data.len() <= CHUNK_BYTES.div_ceil(3) * 4,
                "configuration chunk exceeds byte limit"
            );
            let decoded = base64::engine::general_purpose::STANDARD.decode(&chunk.data)?;
            anyhow::ensure!(
                !decoded.is_empty()
                    && decoded.len() <= CHUNK_BYTES
                    && assembly.bytes.len().saturating_add(decoded.len()) <= assembly.total,
                "invalid configuration chunk length"
            );
            assembly.bytes.extend_from_slice(&decoded);
            if assembly.bytes.len() == assembly.total {
                let assembly = self.assembly.take().expect("complete assembly");
                anyhow::ensure!(
                    hex(&Sha256::digest(&assembly.bytes)) == assembly.digest,
                    "configuration transfer digest mismatch"
                );
                return Ok(Some((serde_json::from_slice(&assembly.bytes)?, true)));
            }
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_transport_chunk_fields_are_forward_open_and_known_fields_stay_typed() {
        let mut value = serde_json::json!({
            "v": PROTOCOL_VERSION, "kind": KIND, "digest": "digest",
            "offset": 0, "total": 1, "data": "eA==", "future_metadata": {"hint": true}
        });
        let chunk: Chunk = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(chunk.v, PROTOCOL_VERSION);
        assert_eq!(chunk.kind, KIND);
        assert_eq!(chunk.offset, 0);
        assert_eq!(chunk.total, 1);
        assert_eq!(chunk.data, "eA==");
        value["offset"] = serde_json::json!("invalid");
        assert!(serde_json::from_value::<Chunk>(value).is_err());
    }

    fn large_event() -> Envelope {
        Envelope::event(Event::ConfigSnapshot {
            snapshot: Box::new(ConfigSnapshot {
                session_id: Uuid::nil(),
                generation: 42,
                extended: Default::default(),
                providers: ProviderConfigView {
                    configuration_warnings: vec!["quota 模型\"\\ ".repeat(110_000)],
                    ..Default::default()
                },
            }),
        })
    }

    #[tokio::test]
    async fn config_transport_chunks_preserve_complete_publications_in_both_writers() {
        for (split, receipt) in [(false, false), (true, false), (false, true), (true, true)] {
            let env = large_event();
            let env = if receipt {
                let Body::Event {
                    event: Event::ConfigSnapshot { snapshot },
                } = env.body
                else {
                    unreachable!()
                };
                Envelope::response(
                    Uuid::new_v4(),
                    Response::ProviderMutationCommitted {
                        catalog_readback: Default::default(),
                        client_operation_id: "operation".into(),
                        snapshot_session_id: "snapshot".into(),
                        layer_id: "layer".into(),
                        owner_root: "/project".into(),
                        mutation_intent_hash: "digest".into(),
                        upserted_provider_ids: vec!["p".into()],
                        consumed_revision: "before".into(),
                        result_revision: "after".into(),
                        config_generation: 42,
                        config: snapshot.providers,
                        status: ConfigCommitStatus::Committed,
                        publication: ConfigPublicationStatus::Published,
                    },
                )
            } else {
                env
            };
            let expected = serde_json::to_value(&env).unwrap();
            assert!(serde_json::to_vec(&env).unwrap().len() > MAX_NDJSON_FRAME_BYTES);
            let (left, right) = tokio::io::duplex(4096);
            let sender = tokio::spawn(async move {
                let mut stream = ProtoStream::new(left);
                if split {
                    let (_, mut writer) = stream.into_split();
                    writer.send(&env).await.unwrap();
                } else {
                    stream.send(&env).await.unwrap();
                }
            });
            let mut reader = ProtoStream::new(right);
            let RecvFrame::Envelope(received) = reader.recv().await.unwrap().unwrap() else {
                panic!("complete envelope")
            };
            assert_eq!(serde_json::to_value(received).unwrap(), expected);
            sender.await.unwrap();
        }
    }

    #[tokio::test]
    async fn config_transport_rejects_size_identity_corruption_and_interleaving() {
        let env = large_event();
        let bytes = serde_json::to_vec(&env).unwrap();
        let digest = hex(&Sha256::digest(&bytes));
        for fault in ["size", "offset", "digest", "corrupt", "interleave", "eof"] {
            let mut lines = Vec::new();
            for (index, source) in bytes.chunks(CHUNK_BYTES).enumerate() {
                let mut source = source.to_vec();
                if fault == "corrupt" && index == 1 {
                    source[0] ^= 1;
                }
                let chunk = Chunk {
                    v: PROTOCOL_VERSION,
                    kind: KIND.into(),
                    digest: if fault == "digest" {
                        "f".repeat(64)
                    } else {
                        digest.clone()
                    },
                    offset: index * CHUNK_BYTES + usize::from(fault == "offset" && index == 1),
                    total: if fault == "size" {
                        MAX_CONFIG_TRANSFER_BYTES + 1
                    } else {
                        bytes.len()
                    },
                    data: base64::engine::general_purpose::STANDARD.encode(&source),
                };
                let line = if fault == "interleave" && index == 1 {
                    serde_json::to_string(&Envelope::response(Uuid::nil(), Response::Ack)).unwrap()
                } else {
                    serde_json::to_string(&chunk).unwrap()
                };
                assert!(line.len() <= MAX_NDJSON_FRAME_BYTES);
                lines.push(Ok(line));
                if fault == "eof" {
                    break;
                }
            }
            let mut stream = futures::stream::iter(lines);
            let error = format!(
                "{:#}",
                Receiver::default().receive(&mut stream).await.unwrap_err()
            );
            let expected = match fault {
                "size" => "size or digest",
                "offset" => "identity or offset",
                "digest" | "corrupt" => "digest mismatch",
                "interleave" => "deserializing configuration chunk",
                "eof" => "incomplete configuration transfer",
                _ => unreachable!(),
            };
            assert!(error.contains(expected), "{fault}: {error}");
        }
    }

    #[tokio::test]
    async fn config_transport_cancellation_preserves_deadline_and_buffered_bytes_when_split() {
        use tokio::io::AsyncWriteExt;
        let env = large_event();
        let expected = serde_json::to_value(&env).unwrap();
        let bytes = serde_json::to_vec(&env).unwrap();
        let digest = hex(&Sha256::digest(&bytes));
        let lines = bytes
            .chunks(CHUNK_BYTES)
            .enumerate()
            .map(|(index, data)| {
                let mut line = serde_json::to_vec(&Chunk {
                    v: PROTOCOL_VERSION,
                    kind: KIND.into(),
                    digest: digest.clone(),
                    offset: index * CHUNK_BYTES,
                    total: bytes.len(),
                    data: base64::engine::general_purpose::STANDARD.encode(data),
                })
                .unwrap();
                line.push(b'\n');
                line
            })
            .collect::<Vec<_>>();
        let (left, mut right) = tokio::io::duplex(256 * 1024);
        right.write_all(&lines[0]).await.unwrap();
        right.write_all(&lines[1][..100]).await.unwrap();
        let mut reader = ProtoStream::new(left);
        {
            let receive = reader.recv();
            tokio::pin!(receive);
            assert!(
                futures::poll!(receive).is_pending(),
                "first chunk and partial next physical frame consumed"
            );
        }
        assert_eq!(
            reader
                .config_receiver
                .assembly
                .as_ref()
                .unwrap()
                .bytes
                .len(),
            CHUNK_BYTES
        );
        assert!(
            !reader.framed.read_buffer().is_empty(),
            "partial next frame is in codec buffer"
        );
        let deadline = reader.config_receiver.assembly.as_ref().unwrap().deadline;
        let (mut reader, _writer) = reader.into_split();
        assert_eq!(
            reader.config_receiver.assembly.as_ref().unwrap().deadline,
            deadline
        );
        let sender = tokio::spawn(async move {
            right.write_all(&lines[1][100..]).await.unwrap();
            for line in lines.iter().skip(2) {
                right.write_all(line).await.unwrap();
            }
        });
        let RecvFrame::Envelope(actual) = reader.recv().await.unwrap().unwrap() else {
            panic!("complete config")
        };
        assert_eq!(serde_json::to_value(actual).unwrap(), expected);
        sender.await.unwrap();
        assert!(reader.config_receiver.assembly.is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn config_transport_cancelled_receives_cannot_extend_transfer_deadline() {
        let env = large_event();
        let bytes = serde_json::to_vec(&env).unwrap();
        let chunk = Chunk {
            v: PROTOCOL_VERSION,
            kind: KIND.into(),
            digest: hex(&Sha256::digest(&bytes)),
            offset: 0,
            total: bytes.len(),
            data: base64::engine::general_purpose::STANDARD.encode(&bytes[..CHUNK_BYTES]),
        };
        let mut stream = futures::stream::iter([Ok(serde_json::to_string(&chunk).unwrap())]).chain(
            futures::stream::pending::<std::result::Result<String, LinesCodecError>>(),
        );
        let mut receiver = Receiver::default();
        for _ in 0..3 {
            {
                let receive = receiver.receive(&mut stream);
                tokio::pin!(receive);
                assert!(futures::poll!(receive).is_pending());
            }
            tokio::time::advance(std::time::Duration::from_secs(10)).await;
        }
        assert!(
            format!("{:#}", receiver.receive(&mut stream).await.unwrap_err())
                .contains("configuration transfer deadline exceeded")
        );
    }

    #[tokio::test]
    async fn config_transport_partial_publication_has_owned_deadline() {
        let env = large_event();
        let bytes = serde_json::to_vec(&env).unwrap();
        let chunk = Chunk {
            v: PROTOCOL_VERSION,
            kind: KIND.into(),
            digest: hex(&Sha256::digest(&bytes)),
            offset: 0,
            total: bytes.len(),
            data: base64::engine::general_purpose::STANDARD.encode(&bytes[..CHUNK_BYTES]),
        };
        let line = serde_json::to_string(&chunk).unwrap();
        let task = tokio::spawn(async move {
            let mut stream = futures::stream::once(async move { Ok(line) })
                .chain(futures::stream::pending::<
                    std::result::Result<String, LinesCodecError>,
                >())
                .boxed();
            Receiver::default().receive(&mut stream).await
        });
        tokio::task::yield_now().await;
        assert!(!task.is_finished());
        tokio::time::pause();
        tokio::time::advance(TRANSFER_TIMEOUT + std::time::Duration::from_secs(1)).await;
        assert!(
            format!("{:#}", task.await.unwrap().unwrap_err())
                .contains("configuration transfer deadline exceeded")
        );
    }
}
