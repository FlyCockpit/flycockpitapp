//! Client-side staging for text too large for the NDJSON request lane.

use base64::Engine as _;
use cockpit_proto::bulk_transfer::{BulkMimeClass, BulkTransferRef, transfer_id_from_bytes};
use cockpit_proto::{self as proto, ErrorCode, Request, Response};
use rand::RngExt as _;
use sha2::{Digest as _, Sha256};

use crate::DaemonRequestClient;

pub const INLINE_USER_MESSAGE_TEXT_BYTES: usize = 64 * 1024;
const STAGED_CHUNK_BYTES: usize = 3 * (proto::MAX_ATTACHMENT_CHUNK_BASE64_BYTES / 4);

#[derive(Debug, thiserror::Error)]
pub enum BulkUserMessageUploadError {
    #[error("{0}")]
    Usage(String),
    #[error("{0}")]
    Daemon(String),
    #[error("{0}")]
    Transport(String),
}

pub fn user_message_needs_bulk(text: &str, display_text: Option<&str>) -> bool {
    text.len() > INLINE_USER_MESSAGE_TEXT_BYTES
        || display_text.is_some_and(|display| display.len() > INLINE_USER_MESSAGE_TEXT_BYTES)
}

pub async fn stage_opaque_user_text<C: DaemonRequestClient>(
    client: &C,
    text: &str,
) -> Result<BulkTransferRef, BulkUserMessageUploadError> {
    let bytes = text.as_bytes();
    if bytes.is_empty() {
        return Err(BulkUserMessageUploadError::Usage(
            "bulk user-message source text must not be empty".to_owned(),
        ));
    }
    if bytes.len() > proto::send_user_message_v2::MAX_MESSAGE_TEXT_BYTES {
        return Err(BulkUserMessageUploadError::Usage(format!(
            "bulk user-message text exceeds the {} byte FCM2 limit",
            proto::send_user_message_v2::MAX_MESSAGE_TEXT_BYTES
        )));
    }

    let mut digest = [0u8; 32];
    digest.copy_from_slice(&Sha256::digest(bytes));
    let mut transfer_id_bytes = [0u8; 16];
    rand::rng().fill(&mut transfer_id_bytes[..]);
    if transfer_id_bytes.iter().all(|byte| *byte == 0) {
        transfer_id_bytes[0] = 1;
    }
    let transfer_id = transfer_id_from_bytes(transfer_id_bytes).map_err(|error| {
        BulkUserMessageUploadError::Daemon(format!("building bulk transfer id: {error}"))
    })?;
    let transfer = BulkTransferRef::new(
        transfer_id,
        bytes.len() as u64,
        digest,
        BulkMimeClass::Opaque,
    )
    .map_err(|error| {
        BulkUserMessageUploadError::Usage(format!("bulk user-message transfer rejected: {error}"))
    })?;

    for (index, chunk) in bytes.chunks(STAGED_CHUNK_BYTES).enumerate() {
        let chunk_index = u32::try_from(index).map_err(|_| {
            BulkUserMessageUploadError::Usage("bulk user-message has too many chunks".to_owned())
        })?;
        let expected_next = chunk_index.checked_add(1).ok_or_else(|| {
            BulkUserMessageUploadError::Usage("bulk user-message chunk index overflow".to_owned())
        })?;
        let expected_received = (index + 1)
            .checked_mul(STAGED_CHUNK_BYTES)
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
            Err(error) => {
                return Err(BulkUserMessageUploadError::Daemon(error.to_string()));
            }
        }
    }
    Ok(transfer)
}
