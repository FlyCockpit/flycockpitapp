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
#[serde(deny_unknown_fields)]
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

pub(super) async fn receive<T>(framed: &mut T, line: String) -> Result<(serde_json::Value, bool)>
where
    T: futures::Stream<Item = std::result::Result<String, LinesCodecError>> + Unpin,
{
    let value: serde_json::Value = serde_json::from_str(&line).context("deserializing envelope")?;
    if value.get("kind").and_then(serde_json::Value::as_str) != Some(KIND) {
        return Ok((value, false));
    }
    let transfer = async {
        let mut chunk: Chunk = serde_json::from_value(value)?;
        let total = chunk.total;
        let digest = chunk.digest.clone();
        anyhow::ensure!(
            total > MAX_NDJSON_FRAME_BYTES
                && total <= MAX_CONFIG_TRANSFER_BYTES
                && digest.len() == 64,
            "invalid configuration transfer size or digest"
        );
        let mut bytes = Vec::new();
        loop {
            anyhow::ensure!(
                chunk.v == PROTOCOL_VERSION
                    && chunk.kind == KIND
                    && chunk.total == total
                    && chunk.digest == digest
                    && chunk.offset == bytes.len(),
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
                    && bytes.len().saturating_add(decoded.len()) <= total,
                "invalid configuration chunk length"
            );
            bytes.extend_from_slice(&decoded);
            if bytes.len() == total {
                break;
            }
            let line = recv_raw_line(framed)
                .await?
                .context("incomplete configuration transfer")?;
            chunk = serde_json::from_str(&line).context("deserializing configuration chunk")?;
        }
        anyhow::ensure!(
            hex(&Sha256::digest(&bytes)) == digest,
            "configuration transfer digest mismatch"
        );
        Ok((serde_json::from_slice(&bytes)?, true))
    };
    tokio::time::timeout(TRANSFER_TIMEOUT, transfer)
        .await
        .context("configuration transfer deadline exceeded")?
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

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
            let first = stream.next().await.unwrap().unwrap();
            let error = format!("{:#}", receive(&mut stream, first).await.unwrap_err());
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
            receive(
                &mut futures::stream::pending::<std::result::Result<String, LinesCodecError>>(),
                line,
            )
            .await
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
