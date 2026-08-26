//! Typed image ingress over the local daemon protocol.

use base64::Engine as _;
use cockpit_proto::{self as proto, ErrorCode, Request, Response};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::DaemonClient;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SubmissionImage {
    Png {
        bytes: Vec<u8>,
    },
    Retained {
        image_ref: proto::ImageAttachmentRef,
    },
}

impl SubmissionImage {
    pub fn png(bytes: Vec<u8>) -> Self {
        Self::Png { bytes }
    }

    pub fn retained(image_ref: proto::ImageAttachmentRef) -> Self {
        Self::Retained { image_ref }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ImageUploadError {
    #[error("{0}")]
    Usage(String),
    #[error("{0}")]
    Daemon(String),
    #[error("{0}")]
    Transport(String),
}

pub async fn upload_submission_images(
    client: &DaemonClient,
    images: &[SubmissionImage],
) -> Result<Vec<proto::ImageAttachmentRef>, ImageUploadError> {
    if images.len() > proto::MAX_IMAGES_PER_USER_MESSAGE {
        return Err(ImageUploadError::Usage(format!(
            "too many images: {} exceeds {} image limit",
            images.len(),
            proto::MAX_IMAGES_PER_USER_MESSAGE
        )));
    }
    let total = images
        .iter()
        .filter_map(|image| match image {
            SubmissionImage::Png { bytes } => Some(bytes.len()),
            SubmissionImage::Retained { .. } => None,
        })
        .sum::<usize>();
    if total > proto::MAX_TOTAL_IMAGE_BYTES {
        return Err(ImageUploadError::Usage(format!(
            "total image data is too large: {total} bytes exceeds {} byte limit",
            proto::MAX_TOTAL_IMAGE_BYTES
        )));
    }

    let mut refs = Vec::with_capacity(images.len());
    for image in images {
        match image {
            SubmissionImage::Png { bytes } => refs.push(upload_one(client, bytes).await?),
            SubmissionImage::Retained { image_ref } => refs.push(image_ref.clone()),
        }
    }
    Ok(refs)
}

async fn upload_one(
    client: &DaemonClient,
    png: &[u8],
) -> Result<proto::ImageAttachmentRef, ImageUploadError> {
    if png.is_empty() {
        return Err(ImageUploadError::Usage("image attachment is empty".into()));
    }
    if png.len() > proto::MAX_SINGLE_IMAGE_BYTES {
        return Err(ImageUploadError::Usage(format!(
            "image is too large: {} bytes exceeds {} byte limit",
            png.len(),
            proto::MAX_SINGLE_IMAGE_BYTES
        )));
    }
    let sha256 = Sha256::digest(png)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let upload_id = match request(
        client,
        Request::BeginAttachmentUpload {
            mime: proto::IMAGE_ATTACHMENT_MIME_PNG.to_owned(),
            byte_len: png.len() as u64,
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

    match upload_chunks(client, upload_id, png).await {
        Ok(image_ref) => Ok(image_ref),
        Err(error) => {
            let _ = client
                .request(Request::CancelAttachmentUpload { upload_id })
                .await;
            Err(error)
        }
    }
}

async fn upload_chunks(
    client: &DaemonClient,
    upload_id: Uuid,
    png: &[u8],
) -> Result<proto::ImageAttachmentRef, ImageUploadError> {
    let chunk_len = ((proto::MAX_ATTACHMENT_CHUNK_BASE64_BYTES / 4) * 3).max(1);
    let mut offset = 0usize;
    while offset < png.len() {
        let end = (offset + chunk_len).min(png.len());
        let data_base64 = base64::engine::general_purpose::STANDARD.encode(&png[offset..end]);
        if data_base64.len() > proto::MAX_ATTACHMENT_CHUNK_BASE64_BYTES {
            return Err(ImageUploadError::Usage(
                "encoded attachment chunk exceeded configured frame budget".into(),
            ));
        }
        match request(
            client,
            Request::UploadAttachmentChunk {
                upload_id,
                offset: offset as u64,
                data_base64,
            },
        )
        .await?
        {
            Response::AttachmentChunkAccepted { next_offset, .. } if next_offset == end => {
                offset = next_offset;
            }
            Response::AttachmentChunkAccepted { next_offset, .. } => {
                return Err(ImageUploadError::Daemon(format!(
                    "attachment upload ack offset mismatch: got {next_offset}, expected {end}"
                )));
            }
            other => {
                return Err(ImageUploadError::Daemon(format!(
                    "unexpected attachment chunk response: {other:?}"
                )));
            }
        }
    }
    match request(client, Request::FinishAttachmentUpload { upload_id }).await? {
        Response::AttachmentUploaded { image_ref } => Ok(image_ref),
        other => Err(ImageUploadError::Daemon(format!(
            "unexpected attachment finish response: {other:?}"
        ))),
    }
}

async fn request(client: &DaemonClient, value: Request) -> Result<Response, ImageUploadError> {
    match client.request(value).await {
        Ok(Ok(response)) => Ok(response),
        Ok(Err(error)) if error.code == ErrorCode::BadRequest => {
            Err(ImageUploadError::Usage(error.message))
        }
        Ok(Err(error)) => Err(ImageUploadError::Daemon(error.to_string())),
        Err(error) => Err(ImageUploadError::Transport(error.to_string())),
    }
}
