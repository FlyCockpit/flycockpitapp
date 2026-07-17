//! User-message image upload helper shared by the TUI and headless run client.

use anyhow::Result;
use base64::Engine as _;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::daemon::client::DaemonClient;
use crate::daemon::proto::{self, ErrorCode, Request, Response};

#[derive(Debug, thiserror::Error)]
pub(crate) enum ImageUploadError {
    #[error("{0}")]
    Usage(String),
    #[error("{0}")]
    Daemon(String),
    #[error("{0}")]
    Transport(String),
}

pub(crate) async fn upload_submission_images(
    client: &DaemonClient,
    images: &[Vec<u8>],
) -> Result<Vec<proto::ImageAttachmentRef>, ImageUploadError> {
    if images.is_empty() {
        return Ok(Vec::new());
    }
    if images.len() > proto::MAX_IMAGES_PER_USER_MESSAGE {
        return Err(ImageUploadError::Usage(format!(
            "too many images: {} exceeds {} image limit",
            images.len(),
            proto::MAX_IMAGES_PER_USER_MESSAGE
        )));
    }
    let total: usize = images.iter().map(Vec::len).sum();
    if total > proto::MAX_TOTAL_IMAGE_BYTES {
        return Err(ImageUploadError::Usage(format!(
            "total image data is too large: {} bytes exceeds {} byte limit",
            total,
            proto::MAX_TOTAL_IMAGE_BYTES
        )));
    }

    let mut refs = Vec::with_capacity(images.len());
    for png in images {
        refs.push(upload_one_image(client, png).await?);
    }
    Ok(refs)
}

async fn upload_one_image(
    client: &DaemonClient,
    png: &[u8],
) -> Result<proto::ImageAttachmentRef, ImageUploadError> {
    if png.is_empty() {
        return Err(ImageUploadError::Usage(
            "image attachment is empty".to_string(),
        ));
    }
    if png.len() > proto::MAX_SINGLE_IMAGE_BYTES {
        return Err(ImageUploadError::Usage(format!(
            "image is too large: {} bytes exceeds {} byte limit",
            png.len(),
            proto::MAX_SINGLE_IMAGE_BYTES
        )));
    }
    let sha256 = crate::intel::hex_lower(&Sha256::digest(png));
    let upload_id = match request_or_error(
        client,
        Request::BeginAttachmentUpload {
            mime: proto::IMAGE_ATTACHMENT_MIME_PNG.to_string(),
            byte_len: png.len(),
            sha256,
            purpose: proto::AttachmentPurpose::UserMessageImage,
        },
    )
    .await?
    {
        Response::AttachmentUploadStarted { upload_id, .. } => upload_id,
        other => {
            return Err(ImageUploadError::Daemon(format!(
                "unexpected attachment upload response: {other:?}"
            )));
        }
    };

    let result = upload_one_image_chunks(client, upload_id, png).await;
    match result {
        Ok(image_ref) => Ok(image_ref),
        Err(error) => {
            let _ = client
                .request(Request::CancelAttachmentUpload { upload_id })
                .await;
            Err(error)
        }
    }
}

async fn upload_one_image_chunks(
    client: &DaemonClient,
    upload_id: Uuid,
    png: &[u8],
) -> Result<proto::ImageAttachmentRef, ImageUploadError> {
    let max_raw = (proto::MAX_ATTACHMENT_CHUNK_BASE64_BYTES / 4) * 3;
    let chunk_len = max_raw.max(1);
    let mut offset = 0usize;
    while offset < png.len() {
        let end = (offset + chunk_len).min(png.len());
        let data_base64 = base64::engine::general_purpose::STANDARD.encode(&png[offset..end]);
        if data_base64.len() > proto::MAX_ATTACHMENT_CHUNK_BASE64_BYTES {
            return Err(ImageUploadError::Usage(
                "encoded attachment chunk exceeded configured frame budget".to_string(),
            ));
        }
        match request_or_error(
            client,
            Request::UploadAttachmentChunk {
                upload_id,
                offset,
                data_base64,
            },
        )
        .await?
        {
            Response::AttachmentChunkAccepted { next_offset, .. } => {
                if next_offset != end {
                    return Err(ImageUploadError::Daemon(format!(
                        "attachment upload ack offset mismatch: got {next_offset}, expected {end}"
                    )));
                }
                offset = next_offset;
            }
            other => {
                return Err(ImageUploadError::Daemon(format!(
                    "unexpected attachment chunk response: {other:?}"
                )));
            }
        }
    }
    match request_or_error(client, Request::FinishAttachmentUpload { upload_id }).await? {
        Response::AttachmentUploaded { image_ref } => Ok(image_ref),
        other => Err(ImageUploadError::Daemon(format!(
            "unexpected attachment finish response: {other:?}"
        ))),
    }
}

async fn request_or_error(
    client: &DaemonClient,
    request: Request,
) -> Result<Response, ImageUploadError> {
    match client.request(request).await {
        Ok(Ok(response)) => Ok(response),
        Ok(Err(error)) if error.code == ErrorCode::BadRequest => {
            Err(ImageUploadError::Usage(error.message))
        }
        Ok(Err(error)) => Err(ImageUploadError::Daemon(error.to_string())),
        Err(error) => Err(ImageUploadError::Transport(error.to_string())),
    }
}
