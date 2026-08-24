//! Client-side staging for text that cannot safely ride the NDJSON request
//! lane.  The daemon consumes the returned references atomically through
//! `SendUserMessageBulk`; callers retain the exact submission id and can stage
//! a fresh, digest-bound reference on an idempotent retry if a reply is lost.

use base64::Engine as _;
use rand::RngExt as _;
use sha2::{Digest as _, Sha256};

use crate::daemon::client::DaemonClient;
use crate::daemon::proto::{ErrorCode, Request, Response};
use crate::proto_crate::remote_protocol_id::{kind, tag_protocol_id_bytes};
use crate::proto_crate::remote_transport::bulk::{RemoteBulkMimeClass, RemoteBulkTransferRef};

/// Text above this boundary must use the FCM2 source-artifact path rather than
/// an inline user-message request.  It is intentionally shared by the native
/// run and TUI clients so neither can accidentally put a multi-megabyte string
/// back into an NDJSON line.
pub const INLINE_USER_MESSAGE_TEXT_BYTES: usize = 64 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum BulkUserMessageUploadError {
    #[error("{0}")]
    Usage(String),
    #[error("{0}")]
    Daemon(String),
    #[error("{0}")]
    Transport(String),
}

/// Whether either authored text representation requires the bounded bulk
/// ingress.  When only display text crosses the boundary, callers must still
/// stage the source through [`stage_opaque_user_text`] because the bulk
/// protocol consumes source/display references as one atomic pair.
pub fn user_message_needs_bulk(text: &str, display_text: Option<&str>) -> bool {
    text.len() > INLINE_USER_MESSAGE_TEXT_BYTES
        || display_text.is_some_and(|display| display.len() > INLINE_USER_MESSAGE_TEXT_BYTES)
}

/// Stage one non-empty UTF-8 user-message body as an opaque, digest-bound
/// transfer. The daemon derives the transfer owner from this already-attached
/// authenticated client/session; ownership is deliberately not a caller-wired
/// field that a native or remote client could forge. Each request body is
/// chunked below the existing NDJSON cap and every acknowledgement is checked,
/// including the final digest-complete acknowledgement, before the reference
/// is returned to the caller.
pub async fn stage_opaque_user_text(
    client: &DaemonClient,
    text: &str,
) -> std::result::Result<RemoteBulkTransferRef, BulkUserMessageUploadError> {
    let bytes = text.as_bytes();
    if bytes.is_empty() {
        return Err(BulkUserMessageUploadError::Usage(
            "bulk user-message source text must not be empty".to_owned(),
        ));
    }
    if bytes.len() > crate::proto_crate::send_user_message_v2::MAX_MESSAGE_TEXT_BYTES {
        return Err(BulkUserMessageUploadError::Usage(format!(
            "bulk user-message text exceeds the {} byte FCM2 limit",
            crate::proto_crate::send_user_message_v2::MAX_MESSAGE_TEXT_BYTES
        )));
    }

    let mut digest = [0u8; 32];
    digest.copy_from_slice(&Sha256::digest(bytes));
    let mut transfer_id_bytes = [0u8; 16];
    rand::rng().fill(&mut transfer_id_bytes[..]);
    if transfer_id_bytes.iter().all(|byte| *byte == 0) {
        transfer_id_bytes[0] = 1;
    }
    let transfer_id =
        tag_protocol_id_bytes::<kind::Transfer>(transfer_id_bytes).map_err(|error| {
            BulkUserMessageUploadError::Daemon(format!("building bulk transfer id: {error}"))
        })?;
    let transfer = RemoteBulkTransferRef::new(
        transfer_id,
        bytes.len() as u64,
        digest,
        RemoteBulkMimeClass::Opaque,
    )
    .map_err(|error| {
        BulkUserMessageUploadError::Usage(format!("bulk user-message transfer rejected: {error}"))
    })?;

    let chunk_size = crate::daemon::bulk_staging::STAGED_CHUNK_BYTES;
    for (index, chunk) in bytes.chunks(chunk_size).enumerate() {
        let chunk_index = u32::try_from(index).map_err(|_| {
            BulkUserMessageUploadError::Usage("bulk user-message has too many chunks".to_owned())
        })?;
        let expected_next = chunk_index.checked_add(1).ok_or_else(|| {
            BulkUserMessageUploadError::Usage("bulk user-message chunk index overflow".to_owned())
        })?;
        let expected_received = (index + 1)
            .checked_mul(chunk_size)
            .map(|end| end.min(bytes.len()))
            .and_then(|end| u64::try_from(end).ok())
            .ok_or_else(|| {
                BulkUserMessageUploadError::Usage(
                    "bulk user-message byte accounting overflow".to_owned(),
                )
            })?;
        let expected_complete = expected_received == bytes.len() as u64;
        let response = client
            .request(Request::WriteBulkTransferChunk {
                transfer: transfer.clone(),
                chunk_index,
                data_base64: base64::engine::general_purpose::STANDARD.encode(chunk),
            })
            .await
            .map_err(|error| BulkUserMessageUploadError::Transport(error.to_string()))?;
        match response {
            Ok(Response::BulkTransferChunkAccepted {
                next_chunk_index,
                received_bytes,
                complete,
                ..
            }) if next_chunk_index == expected_next
                && received_bytes.value() == expected_received
                && complete == expected_complete => {}
            Ok(Response::BulkTransferChunkAccepted {
                next_chunk_index,
                received_bytes,
                complete,
                ..
            }) => {
                return Err(BulkUserMessageUploadError::Daemon(format!(
                    "bulk user-message acknowledgement mismatch for chunk {chunk_index}: \
                     next={next_chunk_index} received={} complete={complete}",
                    received_bytes.value()
                )));
            }
            Ok(other) => {
                return Err(BulkUserMessageUploadError::Daemon(format!(
                    "daemon returned unexpected response to bulk user-message chunk: {other:?}"
                )));
            }
            Err(error) if error.code == ErrorCode::BadRequest => {
                return Err(BulkUserMessageUploadError::Usage(error.message));
            }
            Err(error) => return Err(BulkUserMessageUploadError::Daemon(error.to_string())),
        }
    }
    Ok(transfer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bulk_user_message_threshold_routes_only_oversized_text() {
        assert!(!user_message_needs_bulk(
            &"x".repeat(INLINE_USER_MESSAGE_TEXT_BYTES),
            None,
        ));
        assert!(user_message_needs_bulk(
            &"x".repeat(INLINE_USER_MESSAGE_TEXT_BYTES + 1),
            None,
        ));
        assert!(user_message_needs_bulk(
            "source",
            Some(&"x".repeat(INLINE_USER_MESSAGE_TEXT_BYTES + 1)),
        ));
        assert!(user_message_needs_bulk(&"x".repeat(1024 * 1024 + 1), None));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn bulk_user_message_staging_uses_bounded_write_requests_and_exact_digest() {
        use crate::daemon::client::DaemonClient;
        use crate::daemon::proto::{Body, Envelope, ProtoStream, RecvFrame, Request, Response};
        use crate::proto_crate::remote_transport::bulk::RemoteBulkMimeClass;
        use base64::Engine as _;
        use sha2::{Digest as _, Sha256};
        use tokio::net::UnixListener;
        use uuid::Uuid;

        let directory = tempfile::tempdir().expect("temporary bulk-upload socket directory");
        let socket = directory.path().join("bulk-upload.sock");
        let listener = UnixListener::bind(&socket).expect("bind bulk-upload test socket");
        let source = "bounded native upload\n".repeat(50_001);
        assert!(source.len() > 1024 * 1024);
        let expected_bytes = source.as_bytes().to_vec();
        let expected_chunk_count = expected_bytes
            .len()
            .div_ceil(crate::daemon::bulk_staging::STAGED_CHUNK_BYTES);

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept bulk-upload client");
            let mut daemon = ProtoStream::new(stream);
            daemon
                .send(&Envelope::response(
                    Uuid::nil(),
                    Response::DaemonStatus {
                        pid: 1,
                        uptime_secs: 0,
                        active_sessions: 0,
                        socket_path: "bulk-upload-test.sock".to_owned(),
                        daemon_version: "bulk-upload-test".to_owned(),
                        protocol_version: crate::daemon::proto::PROTOCOL_VERSION,
                        paused_sessions: 0,
                        database_path: ":memory:".to_owned(),
                        schema_version: 0,
                    },
                ))
                .await
                .expect("send daemon hello");

            let mut uploaded = Vec::new();
            let mut reference = None;
            for expected_index in 0..expected_chunk_count {
                let envelope = match daemon
                    .recv()
                    .await
                    .expect("read bulk-upload request")
                    .expect("bulk-upload client stays connected")
                {
                    RecvFrame::Envelope(envelope) => envelope,
                    other => panic!("expected bulk-upload request envelope, got {other:?}"),
                };
                let Body::Request { id, request, .. } = envelope.body else {
                    panic!("expected bulk-upload request body");
                };
                let Request::WriteBulkTransferChunk {
                    transfer,
                    chunk_index,
                    data_base64,
                } = request
                else {
                    panic!("oversized native source must use WriteBulkTransferChunk");
                };
                assert_eq!(chunk_index, expected_index as u32);
                if let Some(expected) = &reference {
                    assert_eq!(&transfer, expected, "all chunks retain one exact reference");
                } else {
                    reference = Some(transfer.clone());
                }
                assert!(
                    data_base64.len() <= crate::daemon::proto::MAX_ATTACHMENT_CHUNK_BASE64_BYTES,
                    "each chunk stays below the NDJSON body limit"
                );
                let chunk = base64::engine::general_purpose::STANDARD
                    .decode(data_base64)
                    .expect("chunk is base64");
                assert!(
                    chunk.len() <= crate::daemon::bulk_staging::STAGED_CHUNK_BYTES,
                    "raw chunk stays within the staged transfer limit"
                );
                uploaded.extend_from_slice(&chunk);
                let received_bytes = uploaded.len() as u64;
                daemon
                    .send(&Envelope::response(
                        id,
                        Response::BulkTransferChunkAccepted {
                            next_chunk_index: expected_index as u32 + 1,
                            received_bytes:
                                crate::daemon::proto::CanonicalU64DecimalStringV1::from_u64(
                                    received_bytes,
                                ),
                            complete: expected_index + 1 == expected_chunk_count,
                            idle_timeout_ms: crate::daemon::bulk_staging::STAGED_TRANSFER_TTL_MS
                                as u32,
                        },
                    ))
                    .await
                    .expect("acknowledge bounded bulk chunk");
            }
            assert_eq!(
                uploaded, expected_bytes,
                "wire chunks reconstruct byte-exact source"
            );
            reference.expect("at least one chunk for a nonempty source")
        });

        let client = DaemonClient::connect(&socket)
            .await
            .expect("connect native bulk-upload client");
        let transfer = stage_opaque_user_text(&client, &source)
            .await
            .expect("stage oversized source through bounded write requests");
        let server_transfer = server.await.expect("bulk-upload server task");
        let mut expected_digest = [0u8; 32];
        expected_digest.copy_from_slice(&Sha256::digest(source.as_bytes()));
        assert_eq!(
            transfer, server_transfer,
            "returned reference is the uploaded reference"
        );
        assert_eq!(transfer.sha256, expected_digest);
        assert_eq!(transfer.total_length.value(), source.len() as u64);
        assert_eq!(transfer.mime_class, RemoteBulkMimeClass::Opaque);
    }
}
