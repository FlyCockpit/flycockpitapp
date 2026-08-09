use super::sessions::*;
use super::*;

#[derive(Default)]
pub(super) struct PrunedMediaReservations {
    pub cancelled: Vec<crate::media_reservation::ReservationReceipt>,
    pub destroyed: Vec<crate::media_reservation::ReservationReceipt>,
}

pub(super) fn prune_expired_attachments(state: &mut MutableClientState) -> PrunedMediaReservations {
    let ttl = Duration::from_secs(proto::PENDING_ATTACHMENT_TTL_SECS);
    let now = Instant::now();
    let expired: Vec<_> = state
        .pending_uploads
        .iter()
        .filter_map(|(upload_id, upload)| {
            (now.duration_since(upload.created_at) > ttl).then_some(*upload_id)
        })
        .collect();
    let cancelled = expired
        .iter()
        .filter_map(|upload_id| state.pending_uploads.remove(upload_id))
        .filter_map(|upload| upload.media_reservation)
        .collect();
    release_uploads(&state.upload_accounting, expired);
    let expired_ready: Vec<_> = state
        .ready_attachments
        .iter()
        .filter_map(|(id, attachment)| {
            (now.duration_since(attachment.created_at) > ttl).then_some(*id)
        })
        .collect();
    let destroyed: Vec<_> = expired_ready
        .into_iter()
        .filter_map(|id| state.ready_attachments.remove(&id))
        .filter_map(|attachment| attachment.media_reservation)
        .collect();
    // This cache is not authoritative ownership: the session actor already
    // received an image clone. Cache TTL must not release that actor-owned
    // durable reservation.
    crate::sync::lock_or_recover(&state.upload_accounting)
        .consumed_message_attachments
        .retain(|_, consumed| now.duration_since(consumed.consumed_at) <= ttl);
    PrunedMediaReservations {
        cancelled,
        destroyed,
    }
}

pub(super) async fn drain_client_attachment_ownership(
    state: &mut MutableClientState,
    ctx: &DaemonContext,
    reason: &str,
) -> std::result::Result<(), ErrorPayload> {
    let pending: Vec<_> = state
        .pending_uploads
        .iter()
        .filter_map(|(id, upload)| {
            upload
                .media_reservation
                .clone()
                .map(|receipt| (*id, receipt))
        })
        .collect();
    let ready: Vec<_> = state
        .ready_attachments
        .iter()
        .filter_map(|(id, attachment)| {
            attachment
                .media_reservation
                .clone()
                .map(|receipt| (*id, receipt))
        })
        .collect();
    let untracked_pending: Vec<_> = state
        .pending_uploads
        .iter()
        .filter_map(|(id, upload)| upload.media_reservation.is_none().then_some(*id))
        .collect();
    let untracked_ready: Vec<_> = state
        .ready_attachments
        .iter()
        .filter_map(|(id, attachment)| attachment.media_reservation.is_none().then_some(*id))
        .collect();
    let wall_ms = chrono::Utc::now()
        .timestamp_millis()
        .try_into()
        .unwrap_or(0);
    for (id, receipt) in pending {
        ctx.media_ledger
            .request_cancellation(&receipt.reservation_id, receipt.version, wall_ms)
            .await
            .map_err(internal)?;
        state.pending_uploads.remove(&id);
        release_uploads(&state.upload_accounting, [id]);
    }
    for (id, receipt) in ready {
        ctx.media_ledger
            .destroy_local_artifacts(
                &receipt.reservation_id,
                receipt.version,
                &format!("attachment-{reason}-destroyed:{}", receipt.reservation_id),
                wall_ms,
            )
            .await
            .map_err(internal)?;
        state.ready_attachments.remove(&id);
    }
    for id in untracked_pending {
        state.pending_uploads.remove(&id);
        release_uploads(&state.upload_accounting, [id]);
    }
    for id in untracked_ready {
        state.ready_attachments.remove(&id);
    }
    Ok(())
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

pub(super) fn user_message_wire_fingerprint(
    text: &str,
    display_text: Option<&str>,
    tag_expansions: &[proto::TagExpansionMeta],
    image_refs: &[proto::ImageAttachmentRef],
    forced_skill: Option<&str>,
) -> String {
    fn part(hasher: &mut Sha256, bytes: &[u8]) {
        hasher.update((bytes.len() as u64).to_be_bytes());
        hasher.update(bytes);
    }
    fn optional_part(hasher: &mut Sha256, value: Option<&str>) {
        match value {
            None => part(hasher, b"none"),
            Some(value) => {
                part(hasher, b"some");
                part(hasher, value.as_bytes());
            }
        }
    }

    let mut hasher = Sha256::new();
    part(&mut hasher, b"user");
    part(&mut hasher, text.as_bytes());
    optional_part(&mut hasher, display_text);
    part(
        &mut hasher,
        &serde_json::to_vec(tag_expansions).unwrap_or_default(),
    );
    for image_ref in image_refs {
        part(&mut hasher, image_ref.id.as_bytes());
    }
    optional_part(&mut hasher, forced_skill);
    crate::intel::hex_lower(&hasher.finalize())
}

pub(super) async fn validate_png_attachment(
    bytes: Vec<u8>,
) -> std::result::Result<ValidatedPngAttachment, ErrorPayload> {
    tokio::task::spawn_blocking(move || validate_png_attachment_blocking(bytes))
        .await
        .map_err(internal)?
}

pub fn validate_png_attachment_blocking(
    bytes: Vec<u8>,
) -> std::result::Result<ValidatedPngAttachment, ErrorPayload> {
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(proto::MAX_IMAGE_DIMENSION_PIXELS);
    limits.max_image_height = Some(proto::MAX_IMAGE_DIMENSION_PIXELS);
    limits.max_alloc = Some(proto::MAX_SINGLE_IMAGE_BYTES as u64);
    let mut reader = image::ImageReader::with_format(
        std::io::Cursor::new(bytes.as_slice()),
        image::ImageFormat::Png,
    );
    reader.limits(limits);
    let decoded = reader.decode().map_err(|err| match err {
        image::ImageError::Limits(_) => bad_request(format!(
            "attachment PNG exceeds the {} pixel or {} byte decode limit",
            proto::MAX_IMAGE_DIMENSION_PIXELS,
            proto::MAX_SINGLE_IMAGE_BYTES
        )),
        _ => bad_request("attachment is not a valid PNG"),
    })?;
    Ok(ValidatedPngAttachment {
        bytes,
        width: u64::from(decoded.width()),
        height: u64::from(decoded.height()),
    })
}

#[derive(Debug)]
pub struct ValidatedPngAttachment {
    pub bytes: Vec<u8>,
    pub width: u64,
    pub height: u64,
}

pub(super) fn begin_attachment_upload(
    state: &mut MutableClientState,
    mime: String,
    byte_len: usize,
    sha256: String,
    purpose: proto::AttachmentPurpose,
) -> std::result::Result<Response, ErrorPayload> {
    begin_attachment_upload_with_limits(state, mime, byte_len, sha256, purpose, state.upload_limits)
}

pub(super) fn begin_attachment_upload_with_limits(
    state: &mut MutableClientState,
    mime: String,
    byte_len: usize,
    sha256: String,
    purpose: proto::AttachmentPurpose,
    _limits: AttachmentUploadLimits,
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
        accounting.track_pending(upload_id, byte_len);
    }
    state.pending_uploads.insert(
        upload_id,
        PendingAttachmentUpload {
            media_reservation: None,
            session_id,
            mime,
            byte_len,
            sha256,
            purpose,
            // Capacity allocation is intentionally deferred until the first
            // chunk. Production has durably admitted the reservation before
            // that request can arrive.
            bytes: Vec::new(),
            created_at: Instant::now(),
        },
    );
    Ok(Response::AttachmentUploadStarted {
        upload_id,
        max_chunk_base64_bytes: proto::MAX_ATTACHMENT_CHUNK_BASE64_BYTES,
    })
}

pub(super) async fn begin_attachment_upload_admitted(
    ctx: &DaemonContext,
    state: &mut MutableClientState,
    mime: String,
    byte_len: usize,
    sha256: String,
    purpose: proto::AttachmentPurpose,
) -> std::result::Result<Response, ErrorPayload> {
    if !ctx
        .media_admission_open
        .load(std::sync::atomic::Ordering::Acquire)
    {
        return Err(internal(
            "media admission is unavailable while durable accounting recovery is incomplete",
        ));
    }
    let response = begin_attachment_upload(state, mime, byte_len, sha256, purpose)?;
    let Response::AttachmentUploadStarted { upload_id, .. } = response else {
        unreachable!()
    };
    use cockpit_config::config::media_budget::{
        MediaDimension, MediaEvaluationRequest, PASTE_IMAGE_PROFILE,
    };
    let config_root = state
        .attached
        .as_ref()
        .map(|attached| attached.handle.project_root.as_path())
        .unwrap_or_else(|| std::path::Path::new("."));
    let (_, extended) = ctx.config_source.load(config_root).map_err(internal)?;
    let policy = extended.media_resources;
    let plans = [
        (MediaDimension::QueuedOperationsGlobal, 1),
        (MediaDimension::QueuedOperationsPerSession, 1),
        (MediaDimension::EncodedBytesPerObject, byte_len as u64),
        (MediaDimension::RetainedBytesPerSession, byte_len as u64),
        (
            MediaDimension::DecodedEdgePixels,
            policy.limits().get(MediaDimension::DecodedEdgePixels),
        ),
        (
            MediaDimension::DecodedImagePixels,
            policy.limits().get(MediaDimension::DecodedImagePixels),
        ),
        (
            MediaDimension::AggregateDecodedPixelsPerRequest,
            policy
                .limits()
                .get(MediaDimension::AggregateDecodedPixelsPerRequest),
        ),
        (MediaDimension::LocalCpuJobsGlobal, 1),
        (
            MediaDimension::OperationDeadlineSeconds,
            policy
                .limits()
                .get(MediaDimension::OperationDeadlineSeconds),
        ),
    ]
    .into_iter()
    .map(|(dimension, requested)| {
        policy.evaluate(MediaEvaluationRequest {
            dimension,
            requested: Some(requested),
            current_scope: 0,
            profile: Some(PASTE_IMAGE_PROFILE),
            adapter_limit: None,
            request_limit: None,
        })
    })
    .collect::<Result<Vec<_>, _>>();
    let plans = match plans {
        Ok(plans) => plans,
        Err(_) => {
            state.pending_uploads.remove(&upload_id);
            release_uploads(&state.upload_accounting, [upload_id]);
            return Err(bad_request("attachment exceeds media resource policy"));
        }
    };
    let (project_id, session) = state.attached.as_ref().map_or_else(
        || {
            let principal = format!(
                "principal:{}",
                state.principal.tag().unwrap_or_else(|| "local".into())
            );
            (principal.clone(), principal)
        },
        |attached| {
            (
                attached.handle.project_id(),
                attached.handle.session_id.to_string(),
            )
        },
    );
    let reservation_id = format!("attachment:{upload_id}");
    let admission = ctx
        .media_ledger
        .reserve(crate::media_reservation::ReserveRequest {
            reservation_id: reservation_id.clone(),
            recovery_id: reservation_id,
            owner: crate::media_reservation::MediaOwner {
                project_id,
                session_id: session,
            },
            operation: "attachment_upload".into(),
            purpose: "paste_image".into(),
            plans,
            wall_ms: chrono::Utc::now()
                .timestamp_millis()
                .try_into()
                .unwrap_or(0),
        })
        .await;
    let receipt = match admission {
        Ok(receipt) => receipt,
        Err(error) => {
            state.pending_uploads.remove(&upload_id);
            release_uploads(&state.upload_accounting, [upload_id]);
            return Err(internal(format!("media admission denied: {error}")));
        }
    };
    state
        .pending_uploads
        .get_mut(&upload_id)
        .expect("upload inserted before durable admission")
        .media_reservation = Some(receipt);
    Ok(response)
}

pub(super) fn upload_attachment_chunk(
    state: &mut MutableClientState,
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

#[cfg(test)]
pub(super) async fn finish_attachment_upload(
    state: &mut MutableClientState,
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
    let bytes = validate_png_attachment(upload.bytes).await?.bytes;
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
                    media_reservation: upload.media_reservation,
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

pub(super) async fn finish_attachment_upload_admitted(
    ctx: &DaemonContext,
    state: &mut MutableClientState,
    upload_id: Uuid,
) -> std::result::Result<Response, ErrorPayload> {
    let Some(mut upload) = state.pending_uploads.remove(&upload_id) else {
        return Err(bad_request("unknown or expired attachment upload id"));
    };
    release_uploads(&state.upload_accounting, [upload_id]);
    let receipt = upload
        .media_reservation
        .take()
        .ok_or_else(|| internal("attachment upload is missing its durable media reservation"))?;
    let wall_ms = chrono::Utc::now()
        .timestamp_millis()
        .try_into()
        .unwrap_or(0);
    let config_root = state
        .attached
        .as_ref()
        .map(|attached| attached.handle.project_root.as_path())
        .unwrap_or_else(|| std::path::Path::new("."));
    let (_, extended) = ctx.config_source.load(config_root).map_err(internal)?;
    let execution_plan = extended
        .media_resources
        .evaluate(
            cockpit_config::config::media_budget::MediaEvaluationRequest {
                dimension: cockpit_config::config::media_budget::MediaDimension::LocalCpuJobsGlobal,
                requested: Some(1),
                current_scope: 0,
                profile: Some(cockpit_config::config::media_budget::PASTE_IMAGE_PROFILE),
                adapter_limit: None,
                request_limit: None,
            },
        )
        .map_err(|_| bad_request("attachment exceeds media execution policy"))?;
    if let Err(error) = ctx
        .media_ledger
        .mark_execution_ready(&receipt.reservation_id, wall_ms)
        .await
    {
        ctx.media_ledger
            .request_cancellation(&receipt.reservation_id, receipt.version, wall_ms)
            .await
            .map_err(internal)?;
        return Err(internal(error));
    }
    let executing = loop {
        match ctx
            .media_ledger
            .claim_ready_fair(&receipt.reservation_id, execution_plan.clone(), wall_ms)
            .await
        {
            Ok(Some(value)) => break value,
            Ok(None) | Err(crate::media_reservation::LedgerError::Denied(_)) => {
                tokio::task::yield_now().await;
            }
            Err(error) => {
                ctx.media_ledger
                    .request_cancellation(&receipt.reservation_id, receipt.version, wall_ms)
                    .await
                    .map_err(internal)?;
                return Err(internal(error));
            }
        }
    };
    let validation = async {
        if upload.bytes.len() != upload.byte_len {
            return Err(bad_request(format!(
                "attachment length mismatch: got {} bytes, expected {}",
                upload.bytes.len(),
                upload.byte_len
            )));
        }
        if sha256_hex(&upload.bytes) != upload.sha256 {
            return Err(bad_request("attachment SHA-256 mismatch"));
        }
        validate_png_attachment(upload.bytes).await
    }
    .await;
    let validated = match validation {
        Ok(validated) => validated,
        Err(error) => {
            let cancelled = ctx
                .media_ledger
                .request_cancellation(&executing.reservation_id, executing.version, wall_ms)
                .await
                .map_err(internal)?;
            ctx.media_ledger
                .destroy_local_artifacts(
                    &cancelled.reservation_id,
                    cancelled.version,
                    &format!("invalid-attachment-destroyed:{upload_id}"),
                    wall_ms,
                )
                .await
                .map_err(internal)?;
            return Err(error);
        }
    };
    let pixels = validated
        .width
        .checked_mul(validated.height)
        .ok_or_else(|| bad_request("attachment decoded pixel count overflows"))?;
    let mut reconciled = executing;
    for (dimension, actual) in [
        (
            cockpit_config::config::media_budget::MediaDimension::DecodedEdgePixels,
            validated.width.max(validated.height),
        ),
        (
            cockpit_config::config::media_budget::MediaDimension::DecodedImagePixels,
            pixels,
        ),
        (
            cockpit_config::config::media_budget::MediaDimension::AggregateDecodedPixelsPerRequest,
            pixels,
        ),
    ] {
        reconciled = ctx
            .media_ledger
            .reconcile_actual(
                &reconciled.reservation_id,
                reconciled.version,
                dimension,
                actual,
                false,
                wall_ms,
            )
            .await
            .map_err(internal)?;
        if reconciled.state == crate::media_reservation::ReservationState::OverageQuarantined {
            ctx.media_ledger
                .destroy_local_artifacts(
                    &reconciled.reservation_id,
                    reconciled.version,
                    &format!("attachment-overage-destroyed:{upload_id}"),
                    wall_ms,
                )
                .await
                .map_err(internal)?;
            return Err(bad_request(
                "attachment exceeds decoded media resource policy",
            ));
        }
    }
    let bytes = validated.bytes;
    // This commit releases queue permits and makes retained byte charges
    // authoritative before the bytes become visible to another subsystem.
    let completed = ctx
        .media_ledger
        .complete_local_allocation(&reconciled.reservation_id, reconciled.version, wall_ms)
        .await
        .map_err(internal)?;
    match upload.purpose {
        proto::AttachmentPurpose::UserMessageImage => {
            let session_id = upload
                .session_id
                .ok_or_else(|| bad_request("user-message image upload is missing its session"))?;
            let image_ref = proto::ImageAttachmentRef { id: Uuid::new_v4() };
            if let Err(error) = ctx
                .media_ledger
                .authorize_publication(&completed.reservation_id)
                .await
            {
                ctx.media_ledger
                    .destroy_local_artifacts(
                        &completed.reservation_id,
                        completed.version,
                        &format!("attachment-unpublished-destroyed:{upload_id}"),
                        wall_ms,
                    )
                    .await
                    .map_err(internal)?;
                return Err(internal(error));
            }
            state.ready_attachments.insert(
                image_ref.id,
                ReadyAttachment {
                    media_reservation: Some(completed),
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
            let response = state.terminal_host.paste_image(terminal_id, &bytes);
            let checksum = format!("terminal-paste-buffer-destroyed:{upload_id}");
            ctx.media_ledger
                .destroy_local_artifacts(
                    &completed.reservation_id,
                    completed.version,
                    &checksum,
                    wall_ms,
                )
                .await
                .map_err(internal)?;
            response
        }
    }
}

#[cfg(test)]
pub(super) fn consume_image_refs(
    state: &mut MutableClientState,
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

/// Atomically bind a message's single-use image refs to its client UUID and
/// return their bytes.
///
/// Moving ready refs into the consumed map before the first await prevents a
/// competing UUID from racing worker acceptance or reusing a ref after an
/// ambiguous/lost worker response. The bytes remain TTL-scoped and resolvable
/// only by this exact UUID, so the worker can still perform its authoritative
/// durable/in-memory fingerprint check on every retry.
pub(super) fn claim_message_image_refs(
    state: &mut MutableClientState,
    session_id: Uuid,
    client_submission_id: Uuid,
    refs: &[proto::ImageAttachmentRef],
) -> std::result::Result<Vec<Vec<u8>>, ErrorPayload> {
    validate_image_ref_shape(refs)?;

    let origin_principal = state.principal.tag();
    let mut accounting = crate::sync::lock_or_recover(&state.upload_accounting);
    let mut total = 0usize;
    let mut images = Vec::with_capacity(refs.len());
    for image_ref in refs {
        let attachment = if let Some(attachment) = state.ready_attachments.get(&image_ref.id) {
            attachment
        } else if let Some(consumed) = accounting.consumed_message_attachments.get(&image_ref.id) {
            if consumed.client_submission_id != client_submission_id
                || consumed.origin_principal != origin_principal
            {
                return Err(bad_request(
                    "unknown, expired, or already consumed image ref",
                ));
            }
            &consumed.attachment
        } else {
            return Err(bad_request(
                "unknown, expired, or already consumed image ref",
            ));
        };
        validate_message_attachment(attachment, session_id, &mut total)?;
        images.push(attachment.bytes.clone());
    }

    // Validation above is all-or-nothing. Move only after every ref and the
    // aggregate size have passed, with no await between validation and bind.
    for image_ref in refs {
        if let Some(attachment) = state.ready_attachments.remove(&image_ref.id) {
            accounting.consumed_message_attachments.insert(
                image_ref.id,
                ConsumedMessageAttachment {
                    client_submission_id,
                    origin_principal: origin_principal.clone(),
                    consumed_at: Instant::now(),
                    attachment,
                },
            );
        }
    }
    Ok(images)
}

pub(super) async fn claim_message_image_refs_admitted(
    ctx: &DaemonContext,
    state: &mut MutableClientState,
    session_id: Uuid,
    client_submission_id: Uuid,
    refs: &[proto::ImageAttachmentRef],
) -> std::result::Result<Vec<Vec<u8>>, ErrorPayload> {
    let images = claim_message_image_refs(state, session_id, client_submission_id, refs)?;
    let reservation_ids = {
        let accounting = crate::sync::lock_or_recover(&state.upload_accounting);
        refs.iter()
            .filter_map(|image_ref| {
                accounting
                    .consumed_message_attachments
                    .get(&image_ref.id)
                    .and_then(|consumed| consumed.attachment.media_reservation.as_ref())
                    .map(|receipt| receipt.reservation_id.clone())
            })
            .collect::<Vec<_>>()
    };
    if let Err(error) = ctx
        .media_ledger
        .bind_downstream_ownership(
            reservation_ids,
            &client_submission_id.to_string(),
            chrono::Utc::now()
                .timestamp_millis()
                .try_into()
                .unwrap_or(0),
        )
        .await
    {
        release_message_image_refs(state, client_submission_id, refs);
        return Err(internal(error));
    }
    Ok(images)
}

/// Roll back only this submission's freshly claimed refs when the session
/// actor proves the model fence stale before queue insertion.
pub(super) fn release_message_image_refs(
    state: &mut MutableClientState,
    client_submission_id: Uuid,
    refs: &[proto::ImageAttachmentRef],
) {
    let origin_principal = state.principal.tag();
    let mut accounting = crate::sync::lock_or_recover(&state.upload_accounting);
    for image_ref in refs {
        let matches = accounting
            .consumed_message_attachments
            .get(&image_ref.id)
            .is_some_and(|consumed| {
                consumed.client_submission_id == client_submission_id
                    && consumed.origin_principal == origin_principal
            });
        if matches
            && let Some(consumed) = accounting
                .consumed_message_attachments
                .remove(&image_ref.id)
        {
            state
                .ready_attachments
                .insert(image_ref.id, consumed.attachment);
        }
    }
}

fn validate_image_ref_shape(
    refs: &[proto::ImageAttachmentRef],
) -> std::result::Result<(), ErrorPayload> {
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
    Ok(())
}

fn validate_message_attachment(
    attachment: &ReadyAttachment,
    session_id: Uuid,
    total: &mut usize,
) -> std::result::Result<(), ErrorPayload> {
    if attachment.session_id != session_id {
        return Err(bad_request("image ref belongs to a different session"));
    }
    if attachment.mime != proto::IMAGE_ATTACHMENT_MIME_PNG {
        return Err(bad_request("image ref has unsupported MIME"));
    }
    if attachment.purpose != proto::AttachmentPurpose::UserMessageImage {
        return Err(bad_request("image ref has unsupported purpose"));
    }
    *total += attachment.bytes.len();
    if *total > proto::MAX_TOTAL_IMAGE_BYTES {
        return Err(bad_request(format!(
            "total image data is too large: {} bytes exceeds {} byte limit",
            *total,
            proto::MAX_TOTAL_IMAGE_BYTES
        )));
    }
    Ok(())
}
