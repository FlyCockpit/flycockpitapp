use super::sessions::*;
use super::*;

const LOCAL_IMAGE_PATH_MAX_INPUT_BYTES: u64 = 10 * 1024 * 1024;

pub(super) async fn admit_local_image_path(
    ctx: &DaemonContext,
    project_root: String,
    path: proto::SensitiveWirePayload,
    admission_id: Uuid,
) -> std::result::Result<Response, ErrorPayload> {
    if project_root.trim().is_empty() || path.trim().is_empty() || path.len() > 4096 {
        return Err(bad_request("local image path is unavailable"));
    }
    let root = std::fs::canonicalize(&project_root)
        .map_err(|_| bad_request("local image path is unavailable"))?;
    let trust = crate::config::trust::resolve_workspace_trust_policy_from_db(&ctx.db, &root)
        .await
        .map_err(|_| bad_request("local image path is unavailable"))?;
    if trust.root.root != root && !root.starts_with(&trust.root.root) {
        return Err(bad_request("local image path is unavailable"));
    }
    let (_, extended) = ctx
        .config_source
        .load_effective_for_daemon(&root, &trust)
        .map_err(|_| bad_request("local image path is unavailable"))?;
    let requested = std::path::PathBuf::from(path.as_str());
    let root_for_worker = root.clone();
    let admitted = tokio::task::spawn_blocking(move || {
        normalize_project_image_path(&root_for_worker, &requested, admission_id)
    })
    .await
    .map_err(internal)?
    .map_err(|_| bad_request("local image path is unavailable"))?;
    evaluate_local_image_admission_policy(&extended.media_resources, &admitted)
        .map_err(|_| bad_request("local image path is unavailable"))?;
    Ok(Response::LocalImagePathAdmitted(admitted))
}

fn evaluate_local_image_admission_policy(
    policy: &cockpit_config::config::media_budget::MediaResourcePolicy,
    admitted: &proto::LocalImagePathAdmissionV1,
) -> anyhow::Result<()> {
    use cockpit_config::config::media_budget::{
        MediaDimension, MediaEvaluationRequest, PASTE_IMAGE_PROFILE,
    };
    let pixels = u64::from(admitted.width)
        .checked_mul(u64::from(admitted.height))
        .ok_or_else(|| anyhow::anyhow!("pixel count overflow"))?;
    for (dimension, requested) in [
        (MediaDimension::QueuedOperationsGlobal, 1),
        (MediaDimension::QueuedOperationsPerSession, 1),
        (
            MediaDimension::EncodedBytesPerObject,
            admitted.normalized_byte_length,
        ),
        (
            MediaDimension::RetainedBytesPerSession,
            admitted.normalized_byte_length,
        ),
        (
            MediaDimension::DecodedEdgePixels,
            u64::from(admitted.width.max(admitted.height)),
        ),
        (MediaDimension::DecodedImagePixels, pixels),
        (MediaDimension::AggregateDecodedPixelsPerRequest, pixels),
        (MediaDimension::LocalCpuJobsGlobal, 1),
        (
            MediaDimension::OperationDeadlineSeconds,
            policy
                .limits()
                .get(MediaDimension::OperationDeadlineSeconds),
        ),
    ] {
        policy.evaluate(MediaEvaluationRequest {
            dimension,
            requested: Some(requested),
            current_scope: 0,
            profile: Some(PASTE_IMAGE_PROFILE),
            adapter_limit: None,
            request_limit: None,
        })?;
    }
    Ok(())
}

fn normalize_project_image_path(
    project_root: &std::path::Path,
    requested: &std::path::Path,
    admission_id: Uuid,
) -> anyhow::Result<proto::LocalImagePathAdmissionV1> {
    use base64::Engine as _;
    use image::{DynamicImage, GenericImageView as _, ImageDecoder as _, ImageFormat, Limits};
    use std::io::{Cursor, Read as _};

    let joined = if requested.is_absolute() {
        requested.to_path_buf()
    } else {
        project_root.join(requested)
    };
    let canonical = std::fs::canonicalize(&joined)?;
    anyhow::ensure!(
        canonical.starts_with(project_root),
        "path escaped workspace"
    );
    let mut file = open_local_image_no_follow(&canonical)?;
    let before = file.metadata()?;
    anyhow::ensure!(
        before.is_file() && before.len() > 0 && before.len() <= LOCAL_IMAGE_PATH_MAX_INPUT_BYTES,
        "invalid source"
    );
    let identity_before = local_image_identity(&before);
    let mut bytes = Vec::with_capacity(usize::try_from(before.len())?);
    file.by_ref()
        .take(LOCAL_IMAGE_PATH_MAX_INPUT_BYTES + 1)
        .read_to_end(&mut bytes)?;
    anyhow::ensure!(
        bytes.len() as u64 <= LOCAL_IMAGE_PATH_MAX_INPUT_BYTES,
        "source too large"
    );
    let after = file.metadata()?;
    anyhow::ensure!(
        before.len() == after.len()
            && before.len() == bytes.len() as u64
            && identity_before == local_image_identity(&after),
        "source changed"
    );

    let format = image::guess_format(&bytes)?;
    anyhow::ensure!(
        matches!(
            format,
            ImageFormat::Png | ImageFormat::Jpeg | ImageFormat::Gif | ImageFormat::WebP
        ),
        "unsupported image"
    );
    let extension = canonical
        .extension()
        .and_then(|value| value.to_str())
        .map(str::to_ascii_lowercase)
        .ok_or_else(|| anyhow::anyhow!("missing image extension"))?;
    anyhow::ensure!(
        matches!(
            (format, extension.as_str()),
            (ImageFormat::Png, "png")
                | (ImageFormat::Jpeg, "jpg" | "jpeg")
                | (ImageFormat::Gif, "gif")
                | (ImageFormat::WebP, "webp")
        ),
        "image extension does not match content"
    );
    reject_local_image_animation(format, &bytes)?;
    let mut reader = image::ImageReader::with_format(Cursor::new(bytes), format);
    let mut limits = Limits::default();
    limits.max_image_width = Some(proto::MAX_IMAGE_DIMENSION_PIXELS);
    limits.max_image_height = Some(proto::MAX_IMAGE_DIMENSION_PIXELS);
    limits.max_alloc = Some(proto::MAX_SINGLE_IMAGE_BYTES as u64);
    reader.limits(limits);
    let mut decoder = reader.into_decoder()?;
    let orientation = decoder.orientation()?;
    let mut image = DynamicImage::from_decoder(decoder)?;
    image.apply_orientation(orientation);
    let (width, height) = image.dimensions();
    anyhow::ensure!(
        width <= proto::MAX_IMAGE_DIMENSION_PIXELS && height <= proto::MAX_IMAGE_DIMENSION_PIXELS,
        "image dimensions exceed policy"
    );
    let mut normalized = Cursor::new(Vec::new());
    DynamicImage::ImageRgba8(image.into_rgba8()).write_to(&mut normalized, ImageFormat::Png)?;
    let png = normalized.into_inner();
    anyhow::ensure!(
        !png.is_empty() && png.len() <= proto::MAX_SINGLE_IMAGE_BYTES,
        "normalized image exceeds policy"
    );
    let digest = sha256_hex(&png);
    Ok(proto::LocalImagePathAdmissionV1 {
        schema_version: 1,
        kind: "localImagePathAdmission".into(),
        admission_id,
        normalized_png_base64: proto::LocalImagePngPayload::new(
            base64::engine::general_purpose::STANDARD.encode(&png),
        ),
        normalized_sha256: digest,
        normalized_byte_length: png.len() as u64,
        width,
        height,
    })
}

#[cfg(unix)]
fn open_local_image_no_follow(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt as _;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
}

#[cfg(windows)]
fn open_local_image_no_follow(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    use std::os::windows::fs::OpenOptionsExt as _;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

#[cfg(not(any(unix, windows)))]
fn open_local_image_no_follow(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    std::fs::File::open(path)
}

#[cfg(unix)]
fn local_image_identity(metadata: &std::fs::Metadata) -> (u64, u64, u64, i128) {
    use std::os::unix::fs::MetadataExt as _;
    (
        metadata.dev(),
        metadata.ino(),
        metadata.len(),
        i128::from(metadata.mtime()) * 1_000_000_000 + i128::from(metadata.mtime_nsec()),
    )
}

#[cfg(not(unix))]
fn local_image_identity(metadata: &std::fs::Metadata) -> (u64, Option<std::time::SystemTime>) {
    (metadata.len(), metadata.modified().ok())
}

fn reject_local_image_animation(format: image::ImageFormat, bytes: &[u8]) -> anyhow::Result<()> {
    match format {
        image::ImageFormat::Gif => anyhow::ensure!(
            !local_gif_has_multiple_frames(bytes),
            "animated image unsupported"
        ),
        image::ImageFormat::Png => anyhow::ensure!(
            !bytes.windows(4).any(|window| window == b"acTL"),
            "animated image unsupported"
        ),
        image::ImageFormat::WebP => anyhow::ensure!(
            !bytes
                .windows(4)
                .any(|window| window == b"ANIM" || window == b"ANMF"),
            "animated image unsupported"
        ),
        _ => {}
    }
    Ok(())
}

fn local_gif_has_multiple_frames(bytes: &[u8]) -> bool {
    let Some(packed) = bytes.get(10).copied() else {
        return true;
    };
    let global_table = if packed & 0x80 != 0 {
        3usize << (usize::from(packed & 0x07) + 1)
    } else {
        0
    };
    let Some(mut cursor) = 13usize.checked_add(global_table) else {
        return true;
    };
    let mut frames = 0;
    while let Some(marker) = bytes.get(cursor).copied() {
        cursor += 1;
        match marker {
            0x3b => return frames > 1,
            0x2c => {
                frames += 1;
                let Some(descriptor) = bytes.get(cursor..cursor + 9) else {
                    return true;
                };
                cursor += 9;
                if descriptor[8] & 0x80 != 0 {
                    let Some(next) =
                        cursor.checked_add(3usize << (usize::from(descriptor[8] & 7) + 1))
                    else {
                        return true;
                    };
                    cursor = next;
                }
                if bytes.get(cursor).is_none() {
                    return true;
                }
                cursor += 1;
                if !skip_local_gif_sub_blocks(bytes, &mut cursor) {
                    return true;
                }
            }
            0x21 => {
                if bytes.get(cursor).is_none() {
                    return true;
                }
                cursor += 1;
                if !skip_local_gif_sub_blocks(bytes, &mut cursor) {
                    return true;
                }
            }
            _ => return true,
        }
    }
    true
}

fn skip_local_gif_sub_blocks(bytes: &[u8], cursor: &mut usize) -> bool {
    loop {
        let Some(size) = bytes.get(*cursor).copied().map(usize::from) else {
            return false;
        };
        *cursor += 1;
        if size == 0 {
            return true;
        }
        let Some(next) = (*cursor).checked_add(size) else {
            return false;
        };
        if next > bytes.len() {
            return false;
        }
        *cursor = next;
    }
}

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
    // Published attachments are not pending uploads and never inherit the
    // legacy 600-second transport TTL. Durable draft/session retention owns
    // their cleanup after publication.
    let destroyed = Vec::new();
    PrunedMediaReservations {
        cancelled,
        destroyed,
    }
}

pub(super) async fn drain_client_attachment_ownership(
    state: &mut MutableClientState,
    ctx: &DaemonContext,
    _reason: &str,
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
    let untracked_pending: Vec<_> = state
        .pending_uploads
        .iter()
        .filter_map(|(id, upload)| upload.media_reservation.is_none().then_some(*id))
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
    for id in untracked_pending {
        state.pending_uploads.remove(&id);
        release_uploads(&state.upload_accounting, [id]);
    }
    // Published media is session-owned. Disconnect releases only this
    // client's ephemeral view when `state` drops; retention/explicit discard
    // remains the sole authority for bytes, reservations, and durable rows.
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

#[cfg(test)]
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

struct AbandonAttachmentOnDrop {
    ledger: crate::media_reservation::MediaReservationLedger,
    reservation_id: Option<String>,
    wall_ms: u64,
    decode_worker:
        Option<tokio::task::JoinHandle<std::result::Result<ValidatedPngAttachment, ErrorPayload>>>,
}

impl Drop for AbandonAttachmentOnDrop {
    fn drop(&mut self) {
        let Some(id) = self.reservation_id.take() else {
            return;
        };
        let worker = self.decode_worker.take();
        let ledger = self.ledger.clone();
        let wall_ms = self.wall_ms;
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                // Dropping a spawn_blocking JoinHandle detaches the closure. It
                // still owns decoded buffers and CPU capacity, so accounting
                // cannot attest cleanup until the actual closure has returned.
                if let Some(worker) = worker {
                    let _ = worker.await;
                }
                let _ = ledger
                    .abandon_local_operation(
                        &id,
                        &format!("abandoned-upload-destroyed:{id}"),
                        wall_ms,
                    )
                    .await;
            });
        }
    }
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
            media_resources_policy: None,
            session_id,
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
    use cockpit_config::config::media_budget::{
        MediaDimension, MediaEvaluationRequest, PASTE_IMAGE_PROFILE,
    };
    let (_, extended) = if let Some(attached) = state.attached.as_ref() {
        ctx.config_source
            .load_effective_for_daemon(&attached.handle.project_root, &attached.handle.trust_policy)
            .map_err(internal)?
    } else {
        // Terminal uploads can exist before session attachment. They have no
        // workspace trust decision, so resolve only trusted/global layers and
        // explicitly ignore any project config beneath the daemon cwd.
        let root = std::env::current_dir().map_err(internal)?;
        let policy = crate::config::trust::WorkspaceTrustPolicy {
            root: crate::config::trust::TrustRoot {
                opened_path: root.clone(),
                root: root.clone(),
                kind: crate::config::trust::TrustRootKind::Directory,
            },
            mode: crate::db::workspace_trust::WorkspaceTrustMode::IgnoreConfig,
        };
        ctx.config_source
            .load_effective_for_daemon(&root, &policy)
            .map_err(internal)?
    };
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
        Err(_) => return Err(bad_request("attachment exceeds media resource policy")),
    };
    // All policy resolution and evaluation is complete before this call
    // creates process-local pending state. Subsequent durable-admission errors
    // have an exact upload id to roll back below.
    let response = begin_attachment_upload(state, mime, byte_len, sha256, purpose)?;
    let Response::AttachmentUploadStarted { upload_id, .. } = response else {
        unreachable!()
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
    state
        .pending_uploads
        .get_mut(&upload_id)
        .expect("upload inserted before durable admission")
        .media_resources_policy = Some(policy);
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
                    session_id,
                    bytes,
                    purpose: upload.purpose,
                },
            );
            Ok(Response::AttachmentUploaded { image_ref })
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
    let mut abandon = AbandonAttachmentOnDrop {
        ledger: ctx.media_ledger.clone(),
        reservation_id: Some(receipt.reservation_id.clone()),
        wall_ms,
        decode_worker: None,
    };
    let execution_plan = ctx
        .media_ledger
        .evaluated_plan(
            &receipt.reservation_id,
            cockpit_config::config::media_budget::MediaDimension::LocalCpuJobsGlobal,
        )
        .await
        .map_err(internal)?;
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
        if ctx.media_ledger.clock_now_ms() >= receipt.deadline_monotonic_ms {
            return Err(bad_request("attachment media execution deadline expired"));
        }
        match ctx
            .media_ledger
            .claim_ready_fair(&receipt.reservation_id, execution_plan.clone(), wall_ms)
            .await
        {
            Ok(Some(value)) => break value,
            Ok(None) | Err(crate::media_reservation::LedgerError::Denied(_)) => {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
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
    let validation = if upload.bytes.len() != upload.byte_len {
        Err(bad_request(format!(
            "attachment length mismatch: got {} bytes, expected {}",
            upload.bytes.len(),
            upload.byte_len
        )))
    } else if sha256_hex(&upload.bytes) != upload.sha256 {
        Err(bad_request("attachment SHA-256 mismatch"))
    } else {
        abandon.decode_worker = Some(tokio::task::spawn_blocking(move || {
            validate_png_attachment_blocking(upload.bytes)
        }));
        let result = abandon
            .decode_worker
            .as_mut()
            .expect("decode worker was installed")
            .await;
        abandon.decode_worker.take();
        result.map_err(internal)?
    };
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
            let project_text = {
                let attached = require_attached(state)?;
                attached
                    .handle
                    .project_root
                    .to_str()
                    .ok_or_else(|| internal("project path is not UTF-8"))?
                    .to_owned()
            };
            let project_digest = crate::intel::hex_lower(&Sha256::digest(project_text.as_bytes()));
            let policy = upload.media_resources_policy.take().ok_or_else(|| {
                internal("attachment upload is missing its evaluated media policy")
            })?;
            let storage = ctx
                .media_storage_recovery
                .as_ref()
                .ok_or_else(|| internal("durable media storage unavailable"))?;
            ctx.media_ledger
                .destroy_local_artifacts(
                    &completed.reservation_id,
                    completed.version,
                    &format!("legacy-paste-promoted:{upload_id}"),
                    wall_ms,
                )
                .await
                .map_err(internal)?;
            abandon.reservation_id = None;
            let attachment_id = storage
                .ingest_message_image(crate::media_storage::IngestMessageImageInput {
                    actor_principal_digest: super::run_invocation::principal_digest(
                        &state.principal,
                    ),
                    session_id,
                    project_digest,
                    bytes,
                    policy: &policy,
                    now_unix_ms: wall_ms.try_into().unwrap_or(i64::MAX),
                    now_monotonic_ms: ctx.media_ledger.clock_now_ms(),
                })
                .await
                .map_err(internal)?;
            let image_ref = proto::ImageAttachmentRef { id: attachment_id };
            Ok(Response::AttachmentUploaded { image_ref })
        }
    }
}

#[cfg(test)]
pub(super) fn consume_image_refs(
    state: &mut MutableClientState,
    session_id: Uuid,
    refs: &[proto::ImageAttachmentRef],
) -> std::result::Result<Vec<Vec<u8>>, ErrorPayload> {
    claim_message_image_refs(state, session_id, Uuid::nil(), refs)
}

/// Acquire reusable immutable attachment bytes for one submission.
///
/// Attachment ownership remains with the session. Submission UUID
/// idempotency belongs to the worker receipt, while the durable media layer
/// records a distinct reference per committed consumer.
#[cfg(test)]
pub(super) fn claim_message_image_refs(
    state: &mut MutableClientState,
    session_id: Uuid,
    client_submission_id: Uuid,
    refs: &[proto::ImageAttachmentRef],
) -> std::result::Result<Vec<Vec<u8>>, ErrorPayload> {
    validate_image_ref_shape(refs)?;

    let mut total = 0usize;
    let mut images = Vec::with_capacity(refs.len());
    for image_ref in refs {
        let Some(attachment) = state.ready_attachments.get(&image_ref.id) else {
            return Err(bad_request("media attachment unavailable"));
        };
        validate_message_attachment(attachment, session_id, &mut total)?;
        images.push(attachment.bytes.clone());
    }
    let _ = client_submission_id;
    Ok(images)
}

pub(super) async fn claim_message_image_refs_admitted(
    ctx: &DaemonContext,
    state: &mut MutableClientState,
    session_id: Uuid,
    client_submission_id: Uuid,
    refs: &[proto::ImageAttachmentRef],
) -> std::result::Result<Vec<Vec<u8>>, ErrorPayload> {
    validate_image_ref_shape(refs)?;
    // A text-only message has no attachments to claim, so it must not depend on
    // the media subsystem being provisioned. Short-circuit before touching the
    // attachment state or media storage recovery, mirroring the empty-refs guard
    // on the probe path in `handle_send_user_message`.
    if refs.is_empty() {
        return Ok(Vec::new());
    }
    let attached =
        require_attached(state).map_err(|_| bad_request("media attachment unavailable"))?;
    if attached.handle.session_id != session_id {
        return Err(bad_request("media attachment unavailable"));
    }
    let project = attached
        .handle
        .project_root
        .to_str()
        .ok_or_else(|| bad_request("media attachment unavailable"))?;
    let project_digest = crate::intel::hex_lower(&Sha256::digest(project.as_bytes()));
    let storage = ctx
        .media_storage_recovery
        .as_ref()
        .ok_or_else(|| bad_request("media attachment unavailable"))?;
    let now = chrono::Utc::now().timestamp_millis();
    let images = storage
        .acquire_message_images_bound(crate::media_storage::AcquireMessageImagesInput {
            attachment_ids: refs.iter().map(|image_ref| image_ref.id).collect(),
            session_id,
            project_digest,
            consumer_id: client_submission_id.to_string(),
            ledger: &ctx.media_ledger,
            max_total_bytes: proto::MAX_TOTAL_IMAGE_BYTES as u64,
            now_unix_ms: now,
        })
        .await
        .map_err(|_| bad_request("media attachment unavailable"))?;
    Ok(images)
}

/// Reusable attachments do not transfer ownership during acquisition, so a
/// rejected submission has no in-memory attachment mutation to roll back.
pub(super) fn release_message_image_refs(
    state: &mut MutableClientState,
    client_submission_id: Uuid,
    refs: &[proto::ImageAttachmentRef],
) {
    let _ = (state, client_submission_id, refs);
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

#[cfg(test)]
fn validate_message_attachment(
    attachment: &ReadyAttachment,
    session_id: Uuid,
    total: &mut usize,
) -> std::result::Result<(), ErrorPayload> {
    if attachment.session_id != session_id {
        return Err(bad_request("image ref belongs to a different session"));
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

#[cfg(test)]
mod decode_cleanup_tests {
    use super::*;
    use std::sync::Arc;

    struct TestClock;
    impl crate::media_reservation::MonotonicClock for TestClock {
        fn now_ms(&self) -> u64 {
            0
        }
    }

    #[test]
    fn local_image_path_admission_normalizes_without_disclosing_the_path() {
        use base64::Engine as _;

        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("source.png");
        let image = image::DynamicImage::ImageRgba8(image::RgbaImage::from_pixel(
            2,
            3,
            image::Rgba([1, 2, 3, 255]),
        ));
        image.save(&path).unwrap();
        let admission_id = Uuid::now_v7();
        let admitted = normalize_project_image_path(root.path(), &path, admission_id).unwrap();

        assert_eq!(admitted.admission_id, admission_id);
        assert_eq!((admitted.width, admitted.height), (2, 3));
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(admitted.normalized_png_base64.as_str())
            .unwrap();
        assert!(bytes.starts_with(b"\x89PNG\r\n\x1a\n"));
        assert_eq!(admitted.normalized_byte_length, bytes.len() as u64);
        assert_eq!(admitted.normalized_sha256, sha256_hex(&bytes));
        assert!(!format!("{admitted:?}").contains(path.to_str().unwrap()));
    }

    #[test]
    fn local_image_path_admission_rejects_workspace_escape() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        assert!(normalize_project_image_path(root.path(), outside.path(), Uuid::now_v7()).is_err());
    }

    #[test]
    fn attachment_policy_resolution_is_trust_scoped_and_promotion_is_snapshot_bound() {
        let source = include_str!("attachments.rs");
        let begin = source
            .split("pub(super) async fn begin_attachment_upload_admitted")
            .nth(1)
            .and_then(|tail| tail.split("pub(super) fn upload_attachment_chunk").next())
            .expect("attachment admission function");
        assert!(begin.contains("load_effective_for_daemon"));
        assert!(begin.contains("handle.trust_policy"));
        assert!(begin.contains("WorkspaceTrustMode::IgnoreConfig"));

        let finish = source
            .split("pub(super) async fn finish_attachment_upload_admitted")
            .nth(1)
            .and_then(|tail| {
                tail.split("#[cfg(test)]\npub(super) fn consume_image_refs")
                    .next()
            })
            .expect("attachment finish function");
        assert!(finish.contains("evaluated_plan"));
        assert!(!finish.contains("config_source"));
    }

    #[tokio::test]
    async fn dropped_decode_retains_cpu_charge_until_blocking_worker_terminates() {
        let db = cockpit_db::Db::open_in_memory().unwrap();
        db.transaction(|conn| {
            conn.execute("INSERT INTO media_reservations(reservation_id,policy_version,project_id,owner_session_key,operation,purpose,recovery_id,state,version,queue_sequence,deadline_monotonic_ms,created_wall_ms) VALUES('decode-drop',1,'p','s','upload','image','decode-drop-recovery','executing_local',1,1,100,0)",[])?;
            conn.execute("INSERT INTO media_resource_counters(scope_kind,scope_id,dimension,charged,generation) VALUES('global','global','local_cpu_jobs_global',1,1)",[])?;
            conn.execute("INSERT INTO media_reservation_deltas(reservation_id,reservation_version,dimension,scope_kind,scope_id,estimated,delta,charged_after,fact_kind,created_wall_ms) VALUES('decode-drop',1,'local_cpu_jobs_global','global','global',1,1,1,'reserve',0)",[])?;
            Ok(())
        }).await.unwrap();
        let ledger =
            crate::media_reservation::MediaReservationLedger::new(db.clone(), Arc::new(TestClock));
        let (release_worker, wait_for_release) = std::sync::mpsc::channel();
        let worker = tokio::task::spawn_blocking(move || {
            wait_for_release.recv().unwrap();
            Err(bad_request("cancelled test decode"))
        });
        drop(AbandonAttachmentOnDrop {
            ledger,
            reservation_id: Some("decode-drop".into()),
            wall_ms: 1,
            decode_worker: Some(worker),
        });
        tokio::task::yield_now().await;
        let before=db.read(|conn|Ok((
            conn.query_row("SELECT charged FROM media_resource_counters WHERE scope_kind='global' AND scope_id='global' AND dimension='local_cpu_jobs_global'",[],|row|row.get::<_,i64>(0))?,
            conn.query_row("SELECT COUNT(*) FROM media_cleanup_attestations WHERE reservation_id='decode-drop'",[],|row|row.get::<_,i64>(0))?,
        ))).await.unwrap();
        assert_eq!(
            before,
            (1, 0),
            "cleanup proof and CPU release must wait for worker termination"
        );
        release_worker.send(()).unwrap();
        for _ in 0..100 {
            let state = db
                .read(|conn| {
                    Ok(conn.query_row(
                        "SELECT state FROM media_reservations WHERE reservation_id='decode-drop'",
                        [],
                        |row| row.get::<_, String>(0),
                    )?)
                })
                .await
                .unwrap();
            if state == "released" {
                break;
            }
            tokio::task::yield_now().await;
        }
        let after=db.read(|conn|Ok((
            conn.query_row("SELECT charged FROM media_resource_counters WHERE scope_kind='global' AND scope_id='global' AND dimension='local_cpu_jobs_global'",[],|row|row.get::<_,i64>(0))?,
            conn.query_row("SELECT state FROM media_reservations WHERE reservation_id='decode-drop'",[],|row|row.get::<_,String>(0))?,
        ))).await.unwrap();
        assert_eq!(after, (0, "released".into()));
    }
}
