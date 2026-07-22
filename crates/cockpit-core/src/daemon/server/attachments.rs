use super::sessions::*;
use super::*;

pub(super) fn prune_expired_attachments(state: &mut ClientState) {
    let ttl = Duration::from_secs(proto::PENDING_ATTACHMENT_TTL_SECS);
    let now = Instant::now();
    let expired: Vec<_> = state
        .pending_uploads
        .iter()
        .filter_map(|(upload_id, upload)| {
            (now.duration_since(upload.created_at) > ttl).then_some(*upload_id)
        })
        .collect();
    for upload_id in &expired {
        state.pending_uploads.remove(upload_id);
    }
    release_uploads(&state.upload_accounting, expired);
    state
        .ready_attachments
        .retain(|_, attachment| now.duration_since(attachment.created_at) <= ttl);
}

pub(super) fn validate_sha256_hex(sha256: &str) -> bool {
    sha256.len() == 64
        && sha256
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub(super) fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    crate::intel::hex_lower(&digest)
}

pub(super) async fn validate_png_attachment(
    bytes: Vec<u8>,
) -> std::result::Result<Vec<u8>, ErrorPayload> {
    tokio::task::spawn_blocking(move || validate_png_attachment_blocking(bytes))
        .await
        .map_err(internal)?
}

pub fn validate_png_attachment_blocking(
    bytes: Vec<u8>,
) -> std::result::Result<Vec<u8>, ErrorPayload> {
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(proto::MAX_IMAGE_DIMENSION_PIXELS);
    limits.max_image_height = Some(proto::MAX_IMAGE_DIMENSION_PIXELS);
    limits.max_alloc = Some(proto::MAX_SINGLE_IMAGE_BYTES as u64);
    let mut reader = image::ImageReader::with_format(
        std::io::Cursor::new(bytes.as_slice()),
        image::ImageFormat::Png,
    );
    reader.limits(limits);
    reader.decode().map_err(|err| match err {
        image::ImageError::Limits(_) => bad_request(format!(
            "attachment PNG exceeds the {} pixel or {} byte decode limit",
            proto::MAX_IMAGE_DIMENSION_PIXELS,
            proto::MAX_SINGLE_IMAGE_BYTES
        )),
        _ => bad_request("attachment is not a valid PNG"),
    })?;
    Ok(bytes)
}

pub(super) fn begin_attachment_upload(
    state: &mut ClientState,
    mime: String,
    byte_len: usize,
    sha256: String,
    purpose: proto::AttachmentPurpose,
) -> std::result::Result<Response, ErrorPayload> {
    begin_attachment_upload_with_limits(state, mime, byte_len, sha256, purpose, state.upload_limits)
}

pub(super) fn begin_attachment_upload_with_limits(
    state: &mut ClientState,
    mime: String,
    byte_len: usize,
    sha256: String,
    purpose: proto::AttachmentPurpose,
    limits: AttachmentUploadLimits,
) -> std::result::Result<Response, ErrorPayload> {
    let session_id = match purpose {
        proto::AttachmentPurpose::UserMessageImage => {
            Some(require_attached(state)?.handle.session_id)
        }
        proto::AttachmentPurpose::TerminalPasteImage { terminal_id } => {
            if !state.terminal_host.contains(terminal_id) {
                return Err(bad_request(format!("unknown terminal {terminal_id}")));
            }
            None
        }
    };
    if mime != proto::IMAGE_ATTACHMENT_MIME_PNG {
        return Err(bad_request(format!("unsupported attachment MIME `{mime}`")));
    }
    if byte_len == 0 {
        return Err(bad_request("attachment is empty"));
    }
    if state.pending_uploads.len() >= limits.per_client_uploads {
        return Err(bad_request(format!(
            "too many pending attachment uploads for this client: {} pending, limit {}",
            state.pending_uploads.len(),
            limits.per_client_uploads
        )));
    }
    if byte_len > limits.per_upload_bytes {
        return Err(bad_request(format!(
            "attachment upload is too large: {} bytes exceeds {} byte pending-upload limit",
            byte_len, limits.per_upload_bytes
        )));
    }
    if byte_len > proto::MAX_SINGLE_IMAGE_BYTES {
        return Err(bad_request(format!(
            "image is too large: {} bytes exceeds {} byte limit",
            byte_len,
            proto::MAX_SINGLE_IMAGE_BYTES
        )));
    }
    if !validate_sha256_hex(&sha256) {
        return Err(bad_request(
            "attachment sha256 must be 64 lowercase hex characters",
        ));
    }
    let upload_id = Uuid::new_v4();
    {
        let mut accounting = crate::sync::lock_or_recover(&state.upload_accounting);
        accounting.reserve(upload_id, byte_len, limits)?;
    }
    state.pending_uploads.insert(
        upload_id,
        PendingAttachmentUpload {
            session_id,
            mime,
            byte_len,
            sha256,
            purpose,
            bytes: Vec::with_capacity(byte_len),
            created_at: Instant::now(),
        },
    );
    Ok(Response::AttachmentUploadStarted {
        upload_id,
        max_chunk_base64_bytes: proto::MAX_ATTACHMENT_CHUNK_BASE64_BYTES,
    })
}

pub(super) fn upload_attachment_chunk(
    state: &mut ClientState,
    upload_id: Uuid,
    offset: usize,
    data_base64: String,
) -> std::result::Result<Response, ErrorPayload> {
    let Some(upload) = state.pending_uploads.get_mut(&upload_id) else {
        return Err(bad_request("unknown or expired attachment upload id"));
    };
    if data_base64.len() > proto::MAX_ATTACHMENT_CHUNK_BASE64_BYTES {
        return Err(bad_request(format!(
            "attachment chunk is too large: {} base64 bytes exceeds {} byte limit",
            data_base64.len(),
            proto::MAX_ATTACHMENT_CHUNK_BASE64_BYTES
        )));
    }
    if offset != upload.bytes.len() {
        return Err(bad_request(format!(
            "attachment chunk offset mismatch: got {offset}, expected {}",
            upload.bytes.len()
        )));
    }
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(data_base64.as_bytes())
        .map_err(|_| bad_request("attachment chunk is not valid base64"))?;
    if upload.bytes.len() + decoded.len() > upload.byte_len {
        return Err(bad_request("attachment chunk exceeds declared byte length"));
    }
    upload.bytes.extend(decoded);
    Ok(Response::AttachmentChunkAccepted {
        upload_id,
        next_offset: upload.bytes.len(),
    })
}

pub(super) async fn finish_attachment_upload(
    state: &mut ClientState,
    upload_id: Uuid,
) -> std::result::Result<Response, ErrorPayload> {
    let Some(upload) = state.pending_uploads.remove(&upload_id) else {
        return Err(bad_request("unknown or expired attachment upload id"));
    };
    release_uploads(&state.upload_accounting, [upload_id]);
    if upload.bytes.len() != upload.byte_len {
        return Err(bad_request(format!(
            "attachment length mismatch: got {} bytes, expected {}",
            upload.bytes.len(),
            upload.byte_len
        )));
    }
    let actual = sha256_hex(&upload.bytes);
    if actual != upload.sha256 {
        return Err(bad_request("attachment SHA-256 mismatch"));
    }
    let bytes = validate_png_attachment(upload.bytes).await?;
    match upload.purpose {
        proto::AttachmentPurpose::UserMessageImage => {
            let Some(session_id) = upload.session_id else {
                return Err(bad_request(
                    "user-message image upload is missing its session",
                ));
            };
            let image_ref = proto::ImageAttachmentRef { id: Uuid::new_v4() };
            state.ready_attachments.insert(
                image_ref.id,
                ReadyAttachment {
                    session_id,
                    mime: upload.mime,
                    bytes,
                    purpose: upload.purpose,
                    created_at: Instant::now(),
                },
            );
            Ok(Response::AttachmentUploaded { image_ref })
        }
        proto::AttachmentPurpose::TerminalPasteImage { terminal_id } => {
            state.terminal_host.paste_image(terminal_id, &bytes)
        }
    }
}

pub(super) fn consume_image_refs(
    state: &mut ClientState,
    session_id: Uuid,
    refs: &[proto::ImageAttachmentRef],
) -> std::result::Result<Vec<Vec<u8>>, ErrorPayload> {
    if refs.len() > proto::MAX_IMAGES_PER_USER_MESSAGE {
        return Err(bad_request(format!(
            "too many images: {} exceeds {} image limit",
            refs.len(),
            proto::MAX_IMAGES_PER_USER_MESSAGE
        )));
    }
    let mut seen = HashSet::new();
    for image_ref in refs {
        if !seen.insert(image_ref.id) {
            return Err(bad_request("duplicate image ref in user message"));
        }
    }
    let mut total = 0usize;
    for image_ref in refs {
        let Some(attachment) = state.ready_attachments.get(&image_ref.id) else {
            return Err(bad_request(
                "unknown, expired, or already consumed image ref",
            ));
        };
        if attachment.session_id != session_id {
            return Err(bad_request("image ref belongs to a different session"));
        }
        if attachment.mime != proto::IMAGE_ATTACHMENT_MIME_PNG {
            return Err(bad_request("image ref has unsupported MIME"));
        }
        if attachment.purpose != proto::AttachmentPurpose::UserMessageImage {
            return Err(bad_request("image ref has unsupported purpose"));
        }
        total += attachment.bytes.len();
        if total > proto::MAX_TOTAL_IMAGE_BYTES {
            return Err(bad_request(format!(
                "total image data is too large: {} bytes exceeds {} byte limit",
                total,
                proto::MAX_TOTAL_IMAGE_BYTES
            )));
        }
    }
    let images = refs
        .iter()
        .map(|image_ref| {
            state
                .ready_attachments
                .remove(&image_ref.id)
                .expect("image ref was validated before removal")
                .bytes
        })
        .collect();
    Ok(images)
}
