//! Durable, session-owned typed media attachment records.
//!
//! Mutating `_conn` entry points deliberately accept the caller's SQLite
//! connection. Callers compose them inside [`Db::transaction`](super::Db::transaction)
//! with reservations, receipts, audit rows, or message commits; this module
//! never opens or commits an independent transaction.

use anyhow::{Context, Result, bail, ensure};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaKind {
    Image,
    Audio,
    Video,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaSourceKind {
    LocalPath,
    RetainedHttps,
    AuthenticatedSessionUpload,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestedLocalPathMediaKind {
    Image,
    Audio,
    Video,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalMediaActorRoleV1 {
    Owner,
    Writer,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "action",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum LocalMediaMutationPayloadV1 {
    Begin {
        #[serde(with = "strict_uuid_v7")]
        session_id: Uuid,
        canonical_project_digest: String,
        #[serde(with = "strict_uuid_v7")]
        client_draft_id: Uuid,
        media_kind: RequestedLocalPathMediaKind,
        declared_total_bytes: u64,
        reservation_digest: String,
    },
    Append {
        #[serde(with = "strict_uuid_v7")]
        session_id: Uuid,
        canonical_project_digest: String,
        #[serde(with = "strict_uuid_v7")]
        client_draft_id: Uuid,
        #[serde(with = "strict_uuid_v7")]
        upload_id: Uuid,
        upload_generation: u64,
        chunk_index: u32,
        chunk_length: u32,
        chunk_sha256: String,
    },
    Finalize {
        #[serde(with = "strict_uuid_v7")]
        session_id: Uuid,
        canonical_project_digest: String,
        #[serde(with = "strict_uuid_v7")]
        client_draft_id: Uuid,
        #[serde(with = "strict_uuid_v7")]
        upload_id: Uuid,
        upload_generation: u64,
        chunk_count: u32,
        total_bytes: u64,
        object_sha256: String,
    },
    Cancel {
        #[serde(with = "strict_uuid_v7")]
        session_id: Uuid,
        canonical_project_digest: String,
        #[serde(with = "strict_uuid_v7")]
        client_draft_id: Uuid,
        #[serde(with = "strict_uuid_v7")]
        upload_id: Uuid,
        upload_generation: u64,
    },
    Discard {
        #[serde(with = "strict_uuid_v7")]
        session_id: Uuid,
        canonical_project_digest: String,
        #[serde(with = "strict_uuid_v7")]
        attachment_id: Uuid,
        attachment_version: u64,
        availability_generation: u64,
        reference_generation: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        origin_upload: Option<MediaOriginUploadV1>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MediaOriginUploadV1 {
    #[serde(with = "strict_uuid_v7")]
    pub client_draft_id: Uuid,
    #[serde(with = "strict_uuid_v7")]
    pub upload_id: Uuid,
    pub upload_generation: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LocalMediaMutationV1 {
    pub schema_version: u8,
    pub kind: String,
    #[serde(with = "strict_uuid_v7")]
    pub local_operation_id: Uuid,
    pub actor_principal_digest: String,
    pub actor_role: LocalMediaActorRoleV1,
    pub payload: LocalMediaMutationPayloadV1,
}

pub type BeginMediaUploadV1 = LocalMediaMutationV1;
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AppendMediaUploadChunkV1 {
    pub mutation: LocalMediaMutationV1,
    pub data_base64: String,
}
pub type FinalizeMediaUploadV1 = LocalMediaMutationV1;
pub type CancelMediaUploadV1 = LocalMediaMutationV1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DiscardUnreferencedMediaAttachmentV1 {
    pub schema_version: u8,
    pub kind: String,
    #[serde(with = "strict_uuid_v7")]
    pub attachment_id: Uuid,
    pub attachment_version: u64,
    pub availability_generation: u64,
    pub reference_generation: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin_upload: Option<MediaOriginUploadV1>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MediaDiscardOutcomeV1 {
    Applied,
    Rejected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MediaDiscardReasonV1 {
    DiscardStarted,
    MediaAttachmentInUse,
    StaleAttachmentVersion,
    StaleAvailabilityGeneration,
    StaleReferenceGeneration,
    AvailabilityStateIneligible,
    SecurityRecoveryRequired,
    AvailabilityGenerationOverflow,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "actor",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum MediaDiscardResultV1 {
    Remote {
        schema_version: u8,
        kind: String,
        #[serde(with = "strict_uuid_v7")]
        result_id: Uuid,
        #[serde(with = "strict_uuid_v7")]
        operation_id: Uuid,
        request_digest: String,
        #[serde(with = "strict_uuid_v7")]
        attachment_id: Uuid,
        requested_attachment_version: u64,
        attachment_version_before: u64,
        requested_availability_generation: u64,
        availability_generation_before: u64,
        availability_generation_after: u64,
        requested_reference_generation: u64,
        reference_generation_before: u64,
        reference_generation_after: u64,
        outcome: MediaDiscardOutcomeV1,
        reason: MediaDiscardReasonV1,
    },
    Local {
        schema_version: u8,
        kind: String,
        #[serde(with = "strict_uuid_v7")]
        result_id: Uuid,
        #[serde(with = "strict_uuid_v7")]
        local_operation_id: Uuid,
        operation_request_digest: String,
        semantic_command_digest: String,
        #[serde(with = "strict_uuid_v7")]
        attachment_id: Uuid,
        requested_attachment_version: u64,
        attachment_version_before: u64,
        requested_availability_generation: u64,
        availability_generation_before: u64,
        availability_generation_after: u64,
        requested_reference_generation: u64,
        reference_generation_before: u64,
        reference_generation_after: u64,
        outcome: MediaDiscardOutcomeV1,
        reason: MediaDiscardReasonV1,
    },
}

impl MediaDiscardResultV1 {
    pub fn encode_fcdr(&self) -> Result<Vec<u8>> {
        let (
            actor,
            result_id,
            operation_id,
            request_digest,
            semantic,
            attachment_id,
            requested_version,
            before_version,
            requested_availability,
            before_availability,
            after_availability,
            requested_reference,
            before_reference,
            after_reference,
            outcome,
            reason,
        ) = match self {
            Self::Remote {
                schema_version,
                kind,
                result_id,
                operation_id,
                request_digest,
                attachment_id,
                requested_attachment_version,
                attachment_version_before,
                requested_availability_generation,
                availability_generation_before,
                availability_generation_after,
                requested_reference_generation,
                reference_generation_before,
                reference_generation_after,
                outcome,
                reason,
            } => {
                ensure!(
                    *schema_version == 1 && kind == "mediaDiscardResult",
                    "invalid media discard result"
                );
                (
                    1u8,
                    *result_id,
                    *operation_id,
                    request_digest,
                    None,
                    *attachment_id,
                    *requested_attachment_version,
                    *attachment_version_before,
                    *requested_availability_generation,
                    *availability_generation_before,
                    *availability_generation_after,
                    *requested_reference_generation,
                    *reference_generation_before,
                    *reference_generation_after,
                    *outcome,
                    *reason,
                )
            }
            Self::Local {
                schema_version,
                kind,
                result_id,
                local_operation_id,
                operation_request_digest,
                semantic_command_digest,
                attachment_id,
                requested_attachment_version,
                attachment_version_before,
                requested_availability_generation,
                availability_generation_before,
                availability_generation_after,
                requested_reference_generation,
                reference_generation_before,
                reference_generation_after,
                outcome,
                reason,
            } => {
                ensure!(
                    *schema_version == 1 && kind == "mediaDiscardResult",
                    "invalid media discard result"
                );
                (
                    2u8,
                    *result_id,
                    *local_operation_id,
                    operation_request_digest,
                    Some(semantic_command_digest),
                    *attachment_id,
                    *requested_attachment_version,
                    *attachment_version_before,
                    *requested_availability_generation,
                    *availability_generation_before,
                    *availability_generation_after,
                    *requested_reference_generation,
                    *reference_generation_before,
                    *reference_generation_after,
                    *outcome,
                    *reason,
                )
            }
        };
        ensure!(
            is_strict_uuid_v7(result_id)
                && is_strict_uuid_v7(operation_id)
                && is_strict_uuid_v7(attachment_id),
            "discard ids must be UUIDv7"
        );
        validate_digest(request_digest, "discard request digest")?;
        if let Some(value) = semantic {
            validate_digest(value, "discard semantic digest")?;
        }
        ensure!(
            [
                requested_version,
                before_version,
                requested_availability,
                before_availability,
                after_availability,
                requested_reference,
                before_reference,
                after_reference
            ]
            .into_iter()
            .all(|value| value > 0),
            "discard generations must be positive"
        );
        let applied = outcome == MediaDiscardOutcomeV1::Applied;
        ensure!(
            applied == (reason == MediaDiscardReasonV1::DiscardStarted),
            "discard outcome/reason mismatch"
        );
        ensure!(
            if applied {
                requested_version == before_version
                    && requested_availability == before_availability
                    && requested_reference == before_reference
                    && after_availability
                        == before_availability
                            .checked_add(1)
                            .context("availability generation overflow")?
                    && after_reference == before_reference
            } else {
                after_availability == before_availability && after_reference == before_reference
            },
            "invalid discard generation transition"
        );
        let digest_bytes = |value: &str| -> Result<[u8; 32]> {
            validate_digest(value, "discard digest")?;
            let mut decoded = [0u8; 32];
            for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
                let nibble = |byte: u8| {
                    if byte.is_ascii_digit() {
                        Some(byte - b'0')
                    } else if (b'a'..=b'f').contains(&byte) {
                        Some(byte - b'a' + 10)
                    } else {
                        None
                    }
                };
                decoded[index] = (nibble(pair[0]).context("invalid digest")? << 4)
                    | nibble(pair[1]).context("invalid digest")?;
            }
            Ok(decoded)
        };
        let mut bytes = Vec::with_capacity(if actor == 1 { 153 } else { 185 });
        bytes.extend_from_slice(b"FCDR");
        bytes.push(1);
        bytes.push(actor);
        bytes.extend_from_slice(result_id.as_bytes());
        bytes.extend_from_slice(operation_id.as_bytes());
        bytes.extend_from_slice(&digest_bytes(request_digest)?);
        bytes.push(u8::from(semantic.is_some()));
        if let Some(value) = semantic {
            bytes.extend_from_slice(&digest_bytes(value)?);
        }
        bytes.extend_from_slice(attachment_id.as_bytes());
        for value in [
            requested_version,
            before_version,
            requested_availability,
            before_availability,
            after_availability,
            requested_reference,
            before_reference,
            after_reference,
        ] {
            bytes.extend_from_slice(&value.to_be_bytes());
        }
        bytes.push(if applied { 1 } else { 2 });
        bytes.push(match reason {
            MediaDiscardReasonV1::DiscardStarted => 1,
            MediaDiscardReasonV1::MediaAttachmentInUse => 2,
            MediaDiscardReasonV1::StaleAttachmentVersion => 3,
            MediaDiscardReasonV1::StaleAvailabilityGeneration => 4,
            MediaDiscardReasonV1::StaleReferenceGeneration => 5,
            MediaDiscardReasonV1::AvailabilityStateIneligible => 6,
            MediaDiscardReasonV1::SecurityRecoveryRequired => 7,
            MediaDiscardReasonV1::AvailabilityGenerationOverflow => 8,
        });
        ensure!(
            bytes.len() == if actor == 1 { 153 } else { 185 },
            "invalid FCDR length"
        );
        Ok(bytes)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoteMediaOperationOutcomeV1 {
    Applied,
    Rejected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MediaUploadTerminalReasonV1 {
    ClientCancelled,
    DraftExpired,
    ChunkOutOfOrder,
    ChunkConflict,
    DeclaredLengthMismatch,
    DeclaredDigestMismatch,
    ReservationExhausted,
    StorageFailure,
    StorageSecurityViolation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "actor",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum MediaUploadLastTransitionV1 {
    Remote {
        action: MediaUploadActionV1,
        #[serde(with = "strict_uuid_v7")]
        operation_id: Uuid,
        outcome: RemoteMediaOperationOutcomeV1,
    },
    Local {
        action: MediaUploadActionV1,
        #[serde(with = "strict_uuid_v7")]
        local_operation_id: Uuid,
        outcome: RemoteMediaOperationOutcomeV1,
    },
    System {
        action: MediaUploadSystemActionV1,
        outcome: RemoteMediaOperationOutcomeV1,
    },
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MediaUploadActionV1 {
    Begin,
    Append,
    Finalize,
    Cancel,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MediaUploadSystemActionV1 {
    Expire,
    StartupReconcile,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "state",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum MediaUploadStateDetailV1 {
    Open {
        next_chunk_index: u32,
    },
    Finalizing {
        next_chunk_index: u32,
    },
    Materialized {
        #[serde(with = "strict_uuid_v7")]
        attachment_id: Uuid,
        attachment_version: u64,
    },
    Cancelled {
        reason: MediaUploadTerminalReasonV1,
    },
    Expired {
        reason: MediaUploadTerminalReasonV1,
    },
    Failed {
        reason: MediaUploadTerminalReasonV1,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MediaUploadStatusV1 {
    pub schema_version: u8,
    pub kind: String,
    #[serde(with = "strict_uuid_v7")]
    pub upload_id: Uuid,
    pub upload_generation: u64,
    #[serde(with = "strict_uuid_v7")]
    pub client_draft_id: Uuid,
    pub media_kind: RequestedLocalPathMediaKind,
    pub expires_at_unix_ms: i64,
    pub acknowledged_chunks: u32,
    pub acknowledged_bytes: u64,
    pub last_transition: MediaUploadLastTransitionV1,
    #[serde(flatten)]
    pub detail: MediaUploadStateDetailV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GetMediaUploadStatusV1 {
    pub schema_version: u8,
    pub kind: String,
    #[serde(with = "strict_uuid_v7")]
    pub session_id: Uuid,
    pub canonical_project_digest: String,
    #[serde(with = "strict_uuid_v7")]
    pub client_draft_id: Uuid,
    #[serde(with = "strict_uuid_v7")]
    pub upload_id: Uuid,
    pub upload_generation: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum LocalMediaMutationTransitionV1 {
    Upload {
        generation_before: u64,
        generation_after: u64,
    },
    UploadToAttachment {
        upload_generation_before: u64,
        upload_generation_after: u64,
        attachment_version: u64,
        availability_generation: u64,
        reference_generation: u64,
    },
    Attachment {
        generation_before: u64,
        generation_after: u64,
        reference_generation_before: u64,
        reference_generation_after: u64,
    },
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalMediaMutationOutcomeV1 {
    Applied,
    Rejected,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalMediaSubjectKindV1 {
    Upload,
    Attachment,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LocalMediaMutationReceiptV1 {
    pub schema_version: u8,
    pub kind: String,
    #[serde(with = "strict_uuid_v7")]
    pub receipt_id: Uuid,
    #[serde(with = "strict_uuid_v7")]
    pub local_operation_id: Uuid,
    pub actor_principal_digest: String,
    pub action: String,
    pub subject_kind: LocalMediaSubjectKindV1,
    #[serde(with = "strict_uuid_v7")]
    pub subject_id: Uuid,
    pub operation_request_digest: String,
    pub semantic_command_digest: String,
    pub outcome: LocalMediaMutationOutcomeV1,
    pub transition: LocalMediaMutationTransitionV1,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub discard_result: Option<MediaDiscardResultV1>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub discard_result_digest: Option<String>,
    pub committed_at_unix_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegisterLocalPathMediaV1 {
    pub schema_version: u8,
    pub kind: String,
    #[serde(with = "strict_uuid_v7")]
    pub local_operation_id: Uuid,
    pub owner_principal_digest: String,
    #[serde(with = "strict_uuid_v7")]
    pub session_id: Uuid,
    pub canonical_project_digest: String,
    #[serde(with = "strict_uuid_v7")]
    pub client_draft_id: Uuid,
    pub requested_media_kind: RequestedLocalPathMediaKind,
    pub path: String,
}

/// Owner-authorized daemon request to retain a remote HTTPS object. The URL
/// exists only at this ingress boundary; no receipt or attachment row stores
/// it verbatim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RetainHttpsMediaV1 {
    pub schema_version: u8,
    pub kind: String,
    #[serde(with = "strict_uuid_v7")]
    pub local_operation_id: Uuid,
    pub owner_principal_digest: String,
    #[serde(with = "strict_uuid_v7")]
    pub session_id: Uuid,
    pub canonical_project_digest: String,
    #[serde(with = "strict_uuid_v7")]
    pub client_draft_id: Uuid,
    pub requested_media_kind: RequestedLocalPathMediaKind,
    pub url: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HttpsRedirectLocationClassV1 {
    SameOrigin,
    CrossOrigin,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HttpsRetentionRejectionReasonV1 {
    SourceUnavailable,
    ResourceLimit,
    InvalidHttpsSource,
    StorageFailure,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case", deny_unknown_fields)]
pub enum HttpsRetentionResultV1 {
    Retained {
        #[serde(with = "strict_uuid_v7")]
        attachment_id: Uuid,
        attachment_version: u64,
        availability_state: String,
        availability_generation: u64,
        reference_generation: u64,
        reservation_id: String,
        reservation_digest: String,
        source_evidence_digest: String,
    },
    Rejected {
        reason: HttpsRetentionRejectionReasonV1,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RetainedHttpsMediaReceiptV1 {
    pub schema_version: u8,
    pub kind: String,
    #[serde(with = "strict_uuid_v7")]
    pub receipt_id: Uuid,
    #[serde(with = "strict_uuid_v7")]
    pub local_operation_id: Uuid,
    pub owner_principal_digest: String,
    #[serde(with = "strict_uuid_v7")]
    pub session_id: Uuid,
    pub canonical_project_digest: String,
    #[serde(with = "strict_uuid_v7")]
    pub client_draft_id: Uuid,
    pub operation_request_digest: String,
    pub semantic_command_digest: String,
    pub origin_scheme: String,
    pub redirect_location_classes: Vec<HttpsRedirectLocationClassV1>,
    pub path_segment_count: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub safe_basename: Option<String>,
    pub fetched_at_unix_ms: i64,
    pub result: HttpsRetentionResultV1,
    pub committed_at_unix_ms: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalPathRegistrationRejectionReason {
    SourceUnavailable,
    StableIdentityUnavailable,
    ResourceLimit,
    SourceChangedDuringRegistration,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case", deny_unknown_fields)]
pub enum LocalPathRegistrationResultV1 {
    Registered {
        #[serde(with = "strict_uuid_v7")]
        attachment_id: Uuid,
        attachment_version: u64,
        availability_state: String,
        availability_generation: u64,
        reference_generation: u64,
        reservation_id: String,
        reservation_digest: String,
        source_evidence_digest: String,
    },
    Rejected {
        reason: LocalPathRegistrationRejectionReason,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LocalPathRegistrationReceiptV1 {
    pub schema_version: u8,
    pub kind: String,
    #[serde(with = "strict_uuid_v7")]
    pub receipt_id: Uuid,
    #[serde(with = "strict_uuid_v7")]
    pub local_operation_id: Uuid,
    pub owner_principal_digest: String,
    #[serde(with = "strict_uuid_v7")]
    pub session_id: Uuid,
    pub canonical_project_digest: String,
    #[serde(with = "strict_uuid_v7")]
    pub client_draft_id: Uuid,
    pub operation_request_digest: String,
    pub semantic_command_digest: String,
    pub result: LocalPathRegistrationResultV1,
    pub committed_at_unix_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GetMediaAttachmentStatusV1 {
    pub schema_version: u8,
    pub kind: String,
    #[serde(with = "strict_uuid_v7")]
    pub session_id: Uuid,
    pub canonical_project_digest: String,
    #[serde(with = "strict_uuid_v7")]
    pub attachment_id: Uuid,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GetMediaAttachmentPreviewV1 {
    pub schema_version: u8,
    pub kind: String,
    #[serde(with = "strict_uuid_v7")]
    pub session_id: Uuid,
    pub canonical_project_digest: String,
    #[serde(with = "strict_uuid_v7")]
    pub attachment_id: Uuid,
    pub attachment_version: u64,
    pub availability_generation: u64,
    pub preview_generation: u64,
    pub preview_checksum: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MediaAttachmentPreviewV1 {
    pub schema_version: u8,
    pub kind: String,
    pub content_type: String,
    pub cache_control: String,
    pub x_content_type_options: String,
    pub content_length: u64,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MediaAttachmentReasonV1 {
    AmbiguousOrUnsupportedContainer,
    UnsupportedCodec,
    UnsupportedColorProfile,
    InvalidMedia,
    ResourceLimit,
    DecodeFailed,
    NormalizationFailed,
    ModelRuntimeUnavailable,
    SourceChanged,
    StorageFailure,
    StorageSecurityViolation,
    CleanupPending,
    RetainedCopyDeleted,
    BorrowedDerivativesDeleted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MediaAttachmentPreviewSummaryV1 {
    pub generation: u64,
    pub checksum: String,
    pub width: u32,
    pub height: u32,
    pub byte_length: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "availabilityState",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum MediaAttachmentStatusDetailV1 {
    Quarantined,
    Registered,
    Probing,
    Decoding,
    Normalizing,
    Ready {
        #[serde(rename = "readyChecksum")]
        ready_checksum: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        preview: Option<MediaAttachmentPreviewSummaryV1>,
    },
    ModelDerivativeUnavailable {
        reason: MediaAttachmentReasonV1,
    },
    Failed {
        reason: MediaAttachmentReasonV1,
    },
    SourceChanged {
        reason: MediaAttachmentReasonV1,
    },
    SecurityBlocked {
        reason: MediaAttachmentReasonV1,
    },
    OwnedCleanupPending {
        reason: MediaAttachmentReasonV1,
    },
    BorrowedCleanupPending {
        reason: MediaAttachmentReasonV1,
    },
    RetainedCopyDeleted {
        reason: MediaAttachmentReasonV1,
    },
    BorrowedDerivativesDeleted {
        reason: MediaAttachmentReasonV1,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MediaAttachmentStatusV1 {
    pub schema_version: u8,
    pub kind: String,
    #[serde(with = "strict_uuid_v7")]
    pub attachment_id: Uuid,
    pub attachment_version: u64,
    pub media_kind: RequestedLocalPathMediaKind,
    pub availability_generation: u64,
    pub reference_generation: u64,
    pub can_discard: bool,
    pub preview_available: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub draft_expires_at_unix_ms: Option<i64>,
    #[serde(flatten)]
    pub detail: MediaAttachmentStatusDetailV1,
}

impl MediaSourceKind {
    fn is_borrowed(self) -> bool {
        self == Self::LocalPath
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaAvailability {
    Registered,
    Quarantined,
    Probing,
    Decoding,
    Normalizing,
    Ready,
    ModelDerivativeUnavailable,
    SourceChanged,
    Failed,
    SecurityBlocked,
    OwnedCleanupPending,
    RetainedCopyDeleted,
    BorrowedCleanupPending,
    BorrowedDerivativesDeleted,
    MetadataDeleted,
}

impl MediaAvailability {
    pub fn is_ready(self) -> bool {
        self == Self::Ready
    }

    pub fn permits_transition(self, source: MediaSourceKind, next: Self) -> bool {
        use MediaAvailability as A;
        let common_processing = matches!(
            (self, next),
            (A::Probing, A::Decoding)
                | (A::Decoding, A::Normalizing)
                | (A::Normalizing, A::Ready | A::ModelDerivativeUnavailable)
                | (A::ModelDerivativeUnavailable, A::Normalizing)
        );
        if common_processing {
            return true;
        }
        if self == A::SecurityBlocked {
            return false;
        }
        if source.is_borrowed() {
            matches!(
                (self, next),
                (A::Registered, A::Probing) | (A::BorrowedDerivativesDeleted, A::MetadataDeleted)
            ) || matches!(next, A::SourceChanged)
                && matches!(
                    self,
                    A::Registered
                        | A::Probing
                        | A::Decoding
                        | A::Normalizing
                        | A::Ready
                        | A::ModelDerivativeUnavailable
                )
                || matches!(next, A::Failed)
                    && matches!(
                        self,
                        A::Registered | A::Probing | A::Decoding | A::Normalizing
                    )
                || next == A::SecurityBlocked
                    && !matches!(self, A::BorrowedDerivativesDeleted | A::MetadataDeleted)
                || next == A::BorrowedCleanupPending
                    && matches!(
                        self,
                        A::Registered
                            | A::Probing
                            | A::Decoding
                            | A::Normalizing
                            | A::Ready
                            | A::ModelDerivativeUnavailable
                            | A::SourceChanged
                            | A::Failed
                    )
                || self == A::BorrowedCleanupPending && next == A::BorrowedDerivativesDeleted
        } else {
            matches!((self, next), (A::Quarantined, A::Probing))
                || next == A::Failed
                    && matches!(
                        self,
                        A::Quarantined | A::Probing | A::Decoding | A::Normalizing
                    )
                || next == A::SecurityBlocked
                    && !matches!(self, A::OwnedCleanupPending | A::RetainedCopyDeleted)
                || next == A::OwnedCleanupPending
                    && matches!(
                        self,
                        A::Quarantined
                            | A::Probing
                            | A::Decoding
                            | A::Normalizing
                            | A::Ready
                            | A::ModelDerivativeUnavailable
                            | A::Failed
                    )
                || self == A::OwnedCleanupPending && next == A::RetainedCopyDeleted
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectedMediaStream {
    pub index: u32,
    pub codec: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaAttachmentRecord {
    pub attachment_id: Uuid,
    pub session_id: Uuid,
    pub canonical_project_digest: String,
    pub media_kind: MediaKind,
    pub source_kind: MediaSourceKind,
    pub canonical_container: String,
    pub canonical_mime: String,
    pub availability: MediaAvailability,
    pub attachment_version: u64,
    pub availability_generation: u64,
    pub reference_generation: u64,
    pub captured_capability_generation: u64,
    pub source_identity_digest: String,
    pub source_byte_length: u64,
    pub source_sha256: String,
    pub selected_video_stream: Option<SelectedMediaStream>,
    pub selected_audio_stream: Option<SelectedMediaStream>,
    pub created_at_unix_ms: i64,
    pub updated_at_unix_ms: i64,
    pub draft_expires_at_unix_ms: Option<i64>,
    pub first_referenced_at_unix_ms: Option<i64>,
}

impl MediaAttachmentRecord {
    pub fn ready_for(&self, session_id: Uuid, project_digest: &str) -> bool {
        self.session_id == session_id
            && self.canonical_project_digest == project_digest
            && self.availability.is_ready()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaReferenceConsumerKind {
    Message,
    Tool,
    Job,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcquiredMediaReference {
    pub reference_id: Uuid,
    pub attachment_id: Uuid,
    pub attachment_version: u64,
    pub reference_generation: u64,
    pub inserted: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaComponentLeaseKind {
    Preview,
    Model,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcquiredMediaComponentLease {
    pub lease_id: Uuid,
    pub attachment_id: Uuid,
    pub attachment_version: u64,
    pub availability_generation: u64,
    pub captured_capability_generation: u64,
    pub component: MediaAttachmentComponent,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaCleanupIntent {
    pub intent_id: Uuid,
    pub attachment_id: Uuid,
    pub attachment_version: u64,
    pub expected_availability_generation: u64,
    pub expected_reference_generation: u64,
    pub component_set_digest: String,
    pub reason: String,
    pub created_at_unix_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaDiscardDecision {
    pub attachment_id: Uuid,
    pub attachment_version_before: u64,
    pub availability_generation_before: u64,
    pub availability_generation_after: u64,
    pub reference_generation_before: u64,
    pub reference_generation_after: u64,
    pub outcome: MediaDiscardOutcomeV1,
    pub reason: MediaDiscardReasonV1,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaAttachmentComponent {
    pub component_id: Uuid,
    pub attachment_id: Uuid,
    pub attachment_version: u64,
    pub component_kind: String,
    /// Opaque relative UUID storage name; never an absolute/caller path.
    pub storage_id: Uuid,
    pub lifecycle_state: String,
    pub component_generation: u64,
    pub stable_identity_digest: String,
    pub byte_length: u64,
    pub sha256: String,
    pub reservation_id: String,
    pub created_at_unix_ms: i64,
    pub updated_at_unix_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedBlockedComponent {
    pub component_id: Uuid,
    pub component_kind: String,
    pub component_generation: u64,
    pub stable_identity_digest: String,
    pub byte_length: u64,
    pub sha256: String,
    pub reservation_id: String,
    pub deletion_evidence_digest: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecoverSecurityBlockedComponentV1 {
    #[serde(with = "strict_uuid_v7")]
    pub component_id: Uuid,
    pub component_kind: String,
    pub component_generation: u64,
    pub recorded_evidence_digest: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MediaSecurityRecoveryDisposition {
    RetainBlocked,
    ResumeVerifiedCleanup,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecoverSecurityBlockedMediaV1 {
    pub schema_version: u8,
    pub kind: String,
    #[serde(with = "strict_uuid_v7")]
    pub local_request_id: Uuid,
    pub owner_principal_digest: String,
    #[serde(with = "strict_uuid_v7")]
    pub attachment_id: Uuid,
    pub attachment_version: u64,
    pub expected_availability_generation: u64,
    pub affected_components: Vec<RecoverSecurityBlockedComponentV1>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub borrowed_source_evidence_digest: Option<String>,
    pub disposition: MediaSecurityRecoveryDisposition,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MediaSecurityRecoveryOutcome {
    RetainedBlocked,
    CleanupResumed,
    RejectedStale,
    RejectedUnverifiable,
    RejectedInUse,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MediaSecurityRecoveryComponentTransitionV1 {
    #[serde(with = "strict_uuid_v7")]
    pub component_id: Uuid,
    pub component_kind: String,
    pub generation_before: u64,
    pub generation_after: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LocalMediaOwnerReceiptV1 {
    pub schema_version: u8,
    pub kind: String,
    #[serde(with = "strict_uuid_v7")]
    pub receipt_id: Uuid,
    #[serde(with = "strict_uuid_v7")]
    pub local_request_id: Uuid,
    pub owner_principal_digest: String,
    #[serde(with = "strict_uuid_v7")]
    pub attachment_id: Uuid,
    pub attachment_version: u64,
    pub disposition: MediaSecurityRecoveryDisposition,
    pub request_digest: String,
    pub affected_set_digest: String,
    pub outcome: MediaSecurityRecoveryOutcome,
    pub availability_generation_before: u64,
    pub availability_generation_after: u64,
    pub components: Vec<MediaSecurityRecoveryComponentTransitionV1>,
    pub committed_at_unix_ms: i64,
}

mod strict_uuid_v7 {
    use serde::{Deserialize, Deserializer, Serializer, de::Error as _};
    use uuid::Uuid;

    pub fn serialize<S>(value: &Uuid, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&value.to_string())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Uuid, D::Error>
    where
        D: Deserializer<'de>,
    {
        let text = String::deserialize(deserializer)?;
        let value = Uuid::parse_str(&text).map_err(D::Error::custom)?;
        if value.is_nil()
            || value.get_version_num() != 7
            || value.get_variant() != uuid::Variant::RFC4122
            || value.to_string() != text
        {
            return Err(D::Error::custom(
                "UUID must be nonnil RFC 9562 UUIDv7 in canonical lowercase hyphenated form",
            ));
        }
        Ok(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityRecoveryComponentSnapshot {
    pub component: VerifiedBlockedComponent,
    pub storage_id: Uuid,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityRecoverySnapshot {
    pub attachment: MediaAttachmentRecord,
    pub components: Vec<SecurityRecoveryComponentSnapshot>,
    pub live_reference_count: u64,
    pub request_digest: String,
    pub affected_set_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecurityRecoverySnapshotResult {
    Replay(LocalMediaOwnerReceiptV1),
    Current(SecurityRecoverySnapshot),
}

impl super::Db {
    pub fn media_upload_status_for_owner_conn(
        conn: &Connection,
        request: &GetMediaUploadStatusV1,
    ) -> Result<Option<MediaUploadStatusV1>> {
        ensure!(
            request.schema_version == 1
                && request.kind == "getMediaUploadStatus"
                && is_strict_uuid_v7(request.session_id)
                && is_strict_uuid_v7(request.client_draft_id)
                && is_strict_uuid_v7(request.upload_id)
                && request.upload_generation > 0,
            "invalid upload status request"
        );
        validate_digest(&request.canonical_project_digest, "project digest")?;
        let row:Option<(String,String,String,u32,String,i64,String,String,Option<String>,Option<String>)>=conn.query_row("SELECT state,upload_generation,media_kind,acknowledged_chunks,acknowledged_bytes,expires_at_unix_ms,last_transition_json,client_draft_id,attachment_id,attachment_version FROM media_uploads WHERE upload_id=?1 AND session_id=?2 AND canonical_project_digest=?3 AND client_draft_id=?4",params![request.upload_id.to_string(),request.session_id.to_string(),request.canonical_project_digest,request.client_draft_id.to_string()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?,r.get(8)?,r.get(9)?))).optional()?;
        let Some((
            state,
            generation,
            kind,
            chunks,
            bytes,
            expires,
            transition,
            draft,
            attachment,
            attachment_version,
        )) = row
        else {
            return Ok(None);
        };
        let generation = generation.parse::<u64>()?;
        ensure!(
            generation == request.upload_generation,
            "media_attachment_unavailable"
        );
        let media_kind = serde_json::from_value(serde_json::Value::String(kind))?;
        let reason = match state.as_str() {
            "cancelled" => Some(MediaUploadTerminalReasonV1::ClientCancelled),
            "expired" => Some(MediaUploadTerminalReasonV1::DraftExpired),
            _ => None,
        };
        let detail = match state.as_str() {
            "open" => MediaUploadStateDetailV1::Open {
                next_chunk_index: chunks,
            },
            "finalizing" => MediaUploadStateDetailV1::Finalizing {
                next_chunk_index: chunks,
            },
            "materialized" => MediaUploadStateDetailV1::Materialized {
                attachment_id: Uuid::parse_str(
                    &attachment.context("materialized attachment missing")?,
                )?,
                attachment_version: attachment_version
                    .context("materialized version missing")?
                    .parse()?,
            },
            "cancelled" => MediaUploadStateDetailV1::Cancelled {
                reason: reason.unwrap(),
            },
            "expired" => MediaUploadStateDetailV1::Expired {
                reason: reason.unwrap(),
            },
            "failed" => MediaUploadStateDetailV1::Failed {
                reason: MediaUploadTerminalReasonV1::StorageFailure,
            },
            _ => bail!("invalid upload state"),
        };
        Ok(Some(MediaUploadStatusV1 {
            schema_version: 1,
            kind: "mediaUploadStatus".into(),
            upload_id: request.upload_id,
            upload_generation: generation,
            client_draft_id: Uuid::parse_str(&draft)?,
            media_kind,
            expires_at_unix_ms: expires,
            acknowledged_chunks: chunks,
            acknowledged_bytes: bytes.parse()?,
            last_transition: serde_json::from_str(&transition)?,
            detail,
        }))
    }
    pub fn validate_local_media_mutation_v1(request: &LocalMediaMutationV1) -> Result<()> {
        ensure!(
            request.schema_version == 1 && request.kind == "localMediaMutation",
            "invalid local media mutation schema or kind"
        );
        ensure!(
            is_strict_uuid_v7(request.local_operation_id),
            "local operation id must be UUIDv7"
        );
        validate_digest(&request.actor_principal_digest, "actor principal digest")?;
        let (session, project) = match &request.payload {
            LocalMediaMutationPayloadV1::Begin {
                session_id,
                canonical_project_digest,
                client_draft_id,
                declared_total_bytes,
                reservation_digest,
                ..
            } => {
                ensure!(
                    is_strict_uuid_v7(*client_draft_id) && *declared_total_bytes > 0,
                    "invalid begin bounds"
                );
                validate_digest(reservation_digest, "reservation digest")?;
                (*session_id, canonical_project_digest)
            }
            LocalMediaMutationPayloadV1::Append {
                session_id,
                canonical_project_digest,
                client_draft_id,
                upload_id,
                upload_generation,
                chunk_length,
                chunk_sha256,
                ..
            } => {
                ensure!(
                    is_strict_uuid_v7(*client_draft_id)
                        && is_strict_uuid_v7(*upload_id)
                        && *upload_generation > 0
                        && *chunk_length > 0
                        && *chunk_length <= 262_144,
                    "invalid append bounds"
                );
                validate_digest(chunk_sha256, "chunk checksum")?;
                (*session_id, canonical_project_digest)
            }
            LocalMediaMutationPayloadV1::Finalize {
                session_id,
                canonical_project_digest,
                client_draft_id,
                upload_id,
                upload_generation,
                chunk_count,
                total_bytes,
                object_sha256,
            } => {
                ensure!(
                    is_strict_uuid_v7(*client_draft_id)
                        && is_strict_uuid_v7(*upload_id)
                        && *upload_generation > 0
                        && *chunk_count > 0
                        && *chunk_count <= 65_536
                        && *total_bytes > 0,
                    "invalid finalize bounds"
                );
                validate_digest(object_sha256, "object checksum")?;
                (*session_id, canonical_project_digest)
            }
            LocalMediaMutationPayloadV1::Cancel {
                session_id,
                canonical_project_digest,
                client_draft_id,
                upload_id,
                upload_generation,
            } => {
                ensure!(
                    is_strict_uuid_v7(*client_draft_id)
                        && is_strict_uuid_v7(*upload_id)
                        && *upload_generation > 0,
                    "invalid cancel binding"
                );
                (*session_id, canonical_project_digest)
            }
            LocalMediaMutationPayloadV1::Discard {
                session_id,
                canonical_project_digest,
                attachment_id,
                attachment_version,
                availability_generation,
                reference_generation,
                origin_upload,
            } => {
                ensure!(
                    is_strict_uuid_v7(*attachment_id)
                        && *attachment_version > 0
                        && *availability_generation > 0
                        && *reference_generation > 0,
                    "invalid discard binding"
                );
                if let Some(origin) = origin_upload {
                    ensure!(
                        is_strict_uuid_v7(origin.client_draft_id)
                            && is_strict_uuid_v7(origin.upload_id)
                            && origin.upload_generation > 0,
                        "invalid upload origin"
                    )
                };
                (*session_id, canonical_project_digest)
            }
        };
        ensure!(is_strict_uuid_v7(session), "session id must be UUIDv7");
        validate_digest(project, "project digest")?;
        Ok(())
    }

    pub fn local_media_mutation_digests(
        request: &LocalMediaMutationV1,
    ) -> Result<(String, String)> {
        Self::validate_local_media_mutation_v1(request)?;
        let request_bytes = serde_json::to_vec(request)?;
        let mut semantic = serde_json::to_value(request)?;
        semantic
            .as_object_mut()
            .context("local mutation object")?
            .remove("localOperationId");
        Ok((
            hex_lower(&Sha256::digest(request_bytes)),
            hex_lower(&Sha256::digest(serde_json::to_vec(&semantic)?)),
        ))
    }

    pub fn media_attachment_status_for_owner_conn(
        conn: &Connection,
        request: &GetMediaAttachmentStatusV1,
    ) -> Result<Option<MediaAttachmentStatusV1>> {
        ensure!(
            request.schema_version == 1 && request.kind == "getMediaAttachmentStatus",
            "invalid media attachment status request"
        );
        ensure!(
            is_strict_uuid_v7(request.session_id) && is_strict_uuid_v7(request.attachment_id),
            "status ids must be UUIDv7"
        );
        validate_digest(&request.canonical_project_digest, "project digest")?;
        let Some(record) = Self::media_attachment_for_owner_conn(
            conn,
            request.attachment_id,
            request.session_id,
            &request.canonical_project_digest,
        )?
        else {
            return Ok(None);
        };
        let live:i64=conn.query_row("SELECT (SELECT COUNT(*) FROM media_attachment_references WHERE attachment_id=?1 AND attachment_version=?2 AND released_at_unix_ms IS NULL) + (SELECT COUNT(*) FROM media_attachment_component_leases WHERE attachment_id=?1 AND attachment_version=?2 AND released_at_unix_ms IS NULL)",params![record.attachment_id.to_string(),decimal(record.attachment_version)?],|row|row.get(0))?;
        let eligible = matches!(
            record.availability,
            MediaAvailability::Registered
                | MediaAvailability::Quarantined
                | MediaAvailability::Probing
                | MediaAvailability::Decoding
                | MediaAvailability::Normalizing
                | MediaAvailability::Ready
                | MediaAvailability::ModelDerivativeUnavailable
                | MediaAvailability::SourceChanged
                | MediaAvailability::Failed
        );
        let detail = match record.availability {
            MediaAvailability::Quarantined => MediaAttachmentStatusDetailV1::Quarantined,
            MediaAvailability::Registered => MediaAttachmentStatusDetailV1::Registered,
            MediaAvailability::Probing => MediaAttachmentStatusDetailV1::Probing,
            MediaAvailability::Decoding => MediaAttachmentStatusDetailV1::Decoding,
            MediaAvailability::Normalizing => MediaAttachmentStatusDetailV1::Normalizing,
            MediaAvailability::Ready => {
                let checksum:Option<String>=conn.query_row("SELECT sha256 FROM media_attachment_components WHERE attachment_id=?1 AND attachment_version=?2 AND component_kind IN ('image_model','audio_model','video_model') AND lifecycle_state='ready' ORDER BY component_kind LIMIT 1",params![record.attachment_id.to_string(),decimal(record.attachment_version)?],|row|row.get(0)).optional()?;
                let preview = if record.media_kind == MediaKind::Image {
                    conn.query_row("SELECT c.component_generation,c.sha256,d.width,d.height,c.byte_length FROM media_attachment_components c JOIN media_image_component_dimensions d ON d.component_id=c.component_id WHERE c.attachment_id=?1 AND c.attachment_version=?2 AND c.component_kind='browser_thumbnail' AND c.lifecycle_state='ready'",params![record.attachment_id.to_string(),decimal(record.attachment_version)?],|row|Ok(MediaAttachmentPreviewSummaryV1{generation:row.get::<_,String>(0)?.parse().map_err(|_|rusqlite::Error::InvalidQuery)?,checksum:row.get(1)?,width:row.get(2)?,height:row.get(3)?,byte_length:row.get::<_,String>(4)?.parse().map_err(|_|rusqlite::Error::InvalidQuery)?})).optional()?.map(Some).context("ready image preview missing")?
                } else {
                    None
                };
                MediaAttachmentStatusDetailV1::Ready {
                    ready_checksum: checksum.context("ready media component missing")?,
                    preview,
                }
            }
            MediaAvailability::ModelDerivativeUnavailable => {
                MediaAttachmentStatusDetailV1::ModelDerivativeUnavailable {
                    reason: MediaAttachmentReasonV1::ModelRuntimeUnavailable,
                }
            }
            MediaAvailability::Failed => MediaAttachmentStatusDetailV1::Failed {
                reason: MediaAttachmentReasonV1::StorageFailure,
            },
            MediaAvailability::SourceChanged => MediaAttachmentStatusDetailV1::SourceChanged {
                reason: MediaAttachmentReasonV1::SourceChanged,
            },
            MediaAvailability::SecurityBlocked => MediaAttachmentStatusDetailV1::SecurityBlocked {
                reason: MediaAttachmentReasonV1::StorageSecurityViolation,
            },
            MediaAvailability::OwnedCleanupPending => {
                MediaAttachmentStatusDetailV1::OwnedCleanupPending {
                    reason: MediaAttachmentReasonV1::CleanupPending,
                }
            }
            MediaAvailability::BorrowedCleanupPending => {
                MediaAttachmentStatusDetailV1::BorrowedCleanupPending {
                    reason: MediaAttachmentReasonV1::CleanupPending,
                }
            }
            MediaAvailability::RetainedCopyDeleted => {
                MediaAttachmentStatusDetailV1::RetainedCopyDeleted {
                    reason: MediaAttachmentReasonV1::RetainedCopyDeleted,
                }
            }
            MediaAvailability::BorrowedDerivativesDeleted => {
                MediaAttachmentStatusDetailV1::BorrowedDerivativesDeleted {
                    reason: MediaAttachmentReasonV1::BorrowedDerivativesDeleted,
                }
            }
            MediaAvailability::MetadataDeleted => return Ok(None),
        };
        let media_kind = match record.media_kind {
            MediaKind::Image => RequestedLocalPathMediaKind::Image,
            MediaKind::Audio => RequestedLocalPathMediaKind::Audio,
            MediaKind::Video => RequestedLocalPathMediaKind::Video,
        };
        let terminal = matches!(
            record.availability,
            MediaAvailability::RetainedCopyDeleted | MediaAvailability::BorrowedDerivativesDeleted
        );
        Ok(Some(MediaAttachmentStatusV1 {
            schema_version: 1,
            kind: "mediaAttachmentStatus".into(),
            attachment_id: record.attachment_id,
            attachment_version: record.attachment_version,
            media_kind,
            availability_generation: record.availability_generation,
            reference_generation: record.reference_generation,
            can_discard: eligible && live == 0,
            preview_available: matches!(
                &detail,
                MediaAttachmentStatusDetailV1::Ready {
                    preview: Some(_),
                    ..
                }
            ),
            draft_expires_at_unix_ms: if terminal {
                None
            } else {
                record.draft_expires_at_unix_ms
            },
            detail,
        }))
    }

    pub fn validate_recover_security_blocked_media_v1(
        request: &RecoverSecurityBlockedMediaV1,
        source_kind: MediaSourceKind,
    ) -> Result<()> {
        ensure!(
            request.schema_version == 1 && request.kind == "recoverSecurityBlockedMedia",
            "invalid recovery request schema or kind"
        );
        ensure!(
            is_strict_uuid_v7(request.local_request_id),
            "local recovery request id must be canonical RFC UUIDv7"
        );
        ensure!(
            is_strict_uuid_v7(request.attachment_id),
            "attachment id must be UUIDv7"
        );
        validate_digest(&request.owner_principal_digest, "owner principal digest")?;
        ensure!(
            request.attachment_version > 0 && request.expected_availability_generation > 0,
            "recovery versions and generations must be positive"
        );
        ensure!(
            !request.affected_components.is_empty() && request.affected_components.len() <= 256,
            "security recovery requires 1..=256 components"
        );
        ensure!(
            request
                .affected_components
                .windows(2)
                .all(|pair| pair[0].component_id < pair[1].component_id),
            "security recovery components must be sorted and unique"
        );
        for component in &request.affected_components {
            ensure!(
                is_strict_uuid_v7(component.component_id),
                "component id must be UUIDv7"
            );
            ensure!(
                component.component_generation > 0,
                "component generation must be positive"
            );
            validate_digest(
                &component.recorded_evidence_digest,
                "recorded evidence digest",
            )?;
        }
        match (
            source_kind.is_borrowed(),
            &request.borrowed_source_evidence_digest,
        ) {
            (true, Some(digest)) => validate_digest(digest, "borrowed source evidence digest")?,
            (false, None) => {}
            _ => bail!("borrowed source evidence presence does not match source ownership"),
        }
        Ok(())
    }

    /// Capture all database authority needed by the private storage verifier.
    /// The private core verifier invokes this on its writer transaction before
    /// holding every storage handle. This helper is read-only and grants no
    /// authority to leave `security_blocked`.
    pub fn security_recovery_snapshot_conn(
        conn: &Connection,
        request: &RecoverSecurityBlockedMediaV1,
        owner_session_id: Uuid,
        canonical_project_digest: &str,
    ) -> Result<SecurityRecoverySnapshotResult> {
        let parent = Self::media_attachment_for_owner_conn(
            conn,
            request.attachment_id,
            owner_session_id,
            canonical_project_digest,
        )?
        .context("security-blocked media attachment unavailable")?;
        Self::validate_recover_security_blocked_media_v1(request, parent.source_kind)?;
        let request_digest = security_recovery_request_digest(request)?;
        if let Some((stored_digest, receipt_json)) = conn.query_row(
            "SELECT request_digest,receipt_json FROM media_security_recovery_operations WHERE local_request_id=?1",
            [request.local_request_id.to_string()],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        ).optional()? {
            ensure!(stored_digest == request_digest, "local operation conflict");
            return Ok(SecurityRecoverySnapshotResult::Replay(
                serde_json::from_str(&receipt_json).context("decoding media recovery receipt")?,
            ));
        }
        let live_references: i64 = conn.query_row("SELECT (SELECT COUNT(*) FROM media_attachment_references WHERE attachment_id=?1 AND released_at_unix_ms IS NULL) + (SELECT COUNT(*) FROM media_attachment_component_leases WHERE attachment_id=?1 AND released_at_unix_ms IS NULL)", [request.attachment_id.to_string()], |row| row.get(0))?;
        let mut statement = conn.prepare("SELECT component_id,component_kind,component_generation,stable_identity_digest,byte_length,sha256,reservation_id,deletion_evidence_digest,storage_id FROM media_attachment_components WHERE attachment_id=?1 AND lifecycle_state <> 'deleted' ORDER BY component_id")?;
        let components = statement
            .query_map([request.attachment_id.to_string()], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, Option<String>>(7)?,
                    row.get::<_, String>(8)?,
                ))
            })?
            .map(|row| {
                let (
                    id,
                    kind,
                    generation,
                    identity,
                    length,
                    checksum,
                    reservation,
                    deletion,
                    storage_id,
                ) = row?;
                Ok(SecurityRecoveryComponentSnapshot {
                    component: VerifiedBlockedComponent {
                        component_id: Uuid::parse_str(&id)?,
                        component_kind: kind,
                        component_generation: parse_decimal(generation, "component generation")?,
                        stable_identity_digest: identity,
                        byte_length: parse_decimal(length, "component byte length")?,
                        sha256: checksum,
                        reservation_id: reservation,
                        deletion_evidence_digest: deletion,
                    },
                    storage_id: Uuid::parse_str(&storage_id)?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let affected_set_digest = security_recovery_affected_set_digest(&components);
        Ok(SecurityRecoverySnapshotResult::Current(
            SecurityRecoverySnapshot {
                attachment: parent,
                components,
                live_reference_count: u64::try_from(live_references)
                    .context("negative live reference count")?,
                request_digest,
                affected_set_digest,
            },
        ))
    }

    pub fn insert_media_attachment_component_conn(
        conn: &Connection,
        component: &MediaAttachmentComponent,
    ) -> Result<()> {
        ensure!(
            component.attachment_version > 0
                && component.component_generation > 0
                && component.byte_length > 0,
            "media component versions, generations, and bytes must be positive"
        );
        ensure!(
            matches!(
                component.component_kind.as_str(),
                "quarantined_original"
                    | "image_model"
                    | "browser_thumbnail"
                    | "audio_model"
                    | "video_model"
                    | "upload_temporary"
            ),
            "invalid media component kind"
        );
        ensure!(
            matches!(
                component.lifecycle_state.as_str(),
                "temporary" | "ready" | "cleanup_pending" | "deleted" | "security_blocked"
            ),
            "invalid media component state"
        );
        validate_digest(
            &component.stable_identity_digest,
            "component identity digest",
        )?;
        validate_digest(&component.sha256, "component checksum")?;
        let parent = media_attachment_by_id(conn, component.attachment_id)?
            .context("media component parent unavailable")?;
        ensure!(
            parent.attachment_version == component.attachment_version,
            "media component parent version mismatch"
        );
        ensure!(
            component_kind_compatible(
                &parent,
                &component.component_kind,
                &component.lifecycle_state
            ),
            "media component kind/lifecycle is incompatible with attachment source or media kind"
        );
        conn.execute(
            "INSERT INTO media_attachment_components (component_id,attachment_id,attachment_version,component_kind,storage_id,lifecycle_state,component_generation,stable_identity_digest,byte_length,sha256,reservation_id,created_at_unix_ms,updated_at_unix_ms) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
            params![component.component_id.to_string(),component.attachment_id.to_string(),decimal(component.attachment_version)?,component.component_kind,component.storage_id.to_string(),component.lifecycle_state,decimal(component.component_generation)?,component.stable_identity_digest,decimal(component.byte_length)?,component.sha256,component.reservation_id,component.created_at_unix_ms,component.updated_at_unix_ms],
        ).context("inserting media attachment component")?;
        Ok(())
    }

    pub fn insert_media_attachment_conn(
        conn: &Connection,
        record: &MediaAttachmentRecord,
    ) -> Result<()> {
        validate_new_record(record)?;
        conn.execute(
            "INSERT INTO media_attachments (attachment_id,session_id,canonical_project_digest,media_kind,source_kind,canonical_container,canonical_mime,availability,attachment_version,availability_generation,reference_generation,captured_capability_generation,source_identity_digest,source_byte_length,source_sha256,selected_video_stream_json,selected_audio_stream_json,created_at_unix_ms,updated_at_unix_ms,draft_expires_at_unix_ms,first_referenced_at_unix_ms) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21)",
            params![
                record.attachment_id.to_string(), record.session_id.to_string(),
                record.canonical_project_digest, record.media_kind.as_str(), record.source_kind.as_str(),
                record.canonical_container, record.canonical_mime, record.availability.as_str(),
                decimal(record.attachment_version)?, decimal(record.availability_generation)?,
                decimal(record.reference_generation)?, decimal(record.captured_capability_generation)?,
                record.source_identity_digest, decimal(record.source_byte_length)?, record.source_sha256,
                stream_json(&record.selected_video_stream)?, stream_json(&record.selected_audio_stream)?,
                record.created_at_unix_ms, record.updated_at_unix_ms, record.draft_expires_at_unix_ms,
                record.first_referenced_at_unix_ms,
            ],
        ).context("inserting media attachment")?;
        Ok(())
    }

    /// Loads only an exact session/project-owned attachment. A miss is the
    /// caller's uniform `media_attachment_unavailable` boundary.
    pub fn media_attachment_for_owner_conn(
        conn: &Connection,
        attachment_id: Uuid,
        session_id: Uuid,
        canonical_project_digest: &str,
    ) -> Result<Option<MediaAttachmentRecord>> {
        conn.query_row(
            "SELECT attachment_id,session_id,canonical_project_digest,media_kind,source_kind,canonical_container,canonical_mime,availability,attachment_version,availability_generation,reference_generation,captured_capability_generation,source_identity_digest,source_byte_length,source_sha256,selected_video_stream_json,selected_audio_stream_json,created_at_unix_ms,updated_at_unix_ms,draft_expires_at_unix_ms,first_referenced_at_unix_ms FROM media_attachments WHERE attachment_id=?1 AND session_id=?2 AND canonical_project_digest=?3",
            params![attachment_id.to_string(), session_id.to_string(), canonical_project_digest],
            decode_record,
        ).optional().context("loading owned media attachment")
    }

    pub fn transition_media_attachment_conn(
        conn: &Connection,
        attachment_id: Uuid,
        expected_version: u64,
        expected_availability_generation: u64,
        next: MediaAvailability,
        now_unix_ms: i64,
    ) -> Result<MediaAttachmentRecord> {
        let current = media_attachment_by_id(conn, attachment_id)?
            .context("media attachment does not exist")?;
        ensure!(
            current.attachment_version == expected_version,
            "stale attachment version"
        );
        ensure!(
            current.availability_generation == expected_availability_generation,
            "stale availability generation"
        );
        ensure!(
            current
                .availability
                .permits_transition(current.source_kind, next),
            "invalid media availability transition"
        );
        let generation = current
            .availability_generation
            .checked_add(1)
            .context("media availability generation overflow")?;
        let changed = conn.execute(
            "UPDATE media_attachments SET availability=?1,availability_generation=?2,updated_at_unix_ms=?3 WHERE attachment_id=?4 AND attachment_version=?5 AND availability_generation=?6",
            params![next.as_str(), decimal(generation)?, now_unix_ms, attachment_id.to_string(), decimal(expected_version)?, decimal(expected_availability_generation)?],
        ).context("transitioning media attachment")?;
        ensure!(
            changed == 1,
            "media attachment transition lost compare-and-swap"
        );
        media_attachment_by_id(conn, attachment_id)?
            .context("transitioned media attachment disappeared")
    }

    /// Acquires a durable, non-consuming reference. The unique consumer tuple
    /// makes exact submission retry return the original reference without a
    /// second generation increment.
    pub fn acquire_media_reference_conn(
        conn: &Connection,
        reference_id: Uuid,
        attachment_id: Uuid,
        expected_version: u64,
        session_id: Uuid,
        project_digest: &str,
        consumer_kind: MediaReferenceConsumerKind,
        consumer_id: &str,
        now_unix_ms: i64,
    ) -> Result<AcquiredMediaReference> {
        let attachment =
            Self::media_attachment_for_owner_conn(conn, attachment_id, session_id, project_digest)?
                .context("media attachment unavailable")?;
        ensure!(
            attachment.availability.is_ready(),
            "media attachment unavailable"
        );
        ensure!(
            attachment.attachment_version == expected_version,
            "media attachment unavailable"
        );
        if let Some(existing) = existing_reference(
            conn,
            attachment_id,
            expected_version,
            consumer_kind,
            consumer_id,
        )? {
            return Ok(existing);
        }
        let generation = attachment
            .reference_generation
            .checked_add(1)
            .context("media reference generation overflow")?;
        conn.execute(
            "INSERT INTO media_attachment_references (reference_id,attachment_id,attachment_version,consumer_kind,consumer_id,acquired_generation,acquired_at_unix_ms) VALUES (?1,?2,?3,?4,?5,?6,?7)",
            params![reference_id.to_string(), attachment_id.to_string(), decimal(expected_version)?, consumer_kind.as_str(), consumer_id, decimal(generation)?, now_unix_ms],
        ).context("inserting media attachment reference")?;
        let changed = conn.execute(
            "UPDATE media_attachments SET reference_generation=?1,first_referenced_at_unix_ms=COALESCE(first_referenced_at_unix_ms,?2),draft_expires_at_unix_ms=NULL,updated_at_unix_ms=?2 WHERE attachment_id=?3 AND reference_generation=?4",
            params![decimal(generation)?, now_unix_ms, attachment_id.to_string(), decimal(attachment.reference_generation)?],
        ).context("advancing media reference generation")?;
        ensure!(
            changed == 1,
            "media reference acquisition lost compare-and-swap"
        );
        Ok(AcquiredMediaReference {
            reference_id,
            attachment_id,
            attachment_version: expected_version,
            reference_generation: generation,
            inserted: true,
        })
    }

    pub fn create_media_cleanup_intent_conn(
        conn: &Connection,
        intent: &MediaCleanupIntent,
    ) -> Result<()> {
        ensure!(
            intent.attachment_version > 0
                && intent.expected_availability_generation > 0
                && intent.expected_reference_generation > 0,
            "media cleanup generations must be positive"
        );
        validate_digest(&intent.component_set_digest, "component set digest")?;
        ensure!(
            matches!(
                intent.reason.as_str(),
                "discard"
                    | "draft_expired"
                    | "session_retention"
                    | "session_deleted"
                    | "security_recovery"
            ),
            "invalid media cleanup reason"
        );
        let parent = media_attachment_by_id(conn, intent.attachment_id)?
            .context("media cleanup attachment unavailable")?;
        ensure!(
            parent.attachment_version == intent.attachment_version,
            "media cleanup attachment version mismatch"
        );
        ensure!(
            parent.availability_generation == intent.expected_availability_generation,
            "media cleanup availability generation mismatch"
        );
        ensure!(
            parent.reference_generation == intent.expected_reference_generation,
            "media cleanup reference generation mismatch"
        );
        ensure!(
            matches!(
                parent.availability,
                MediaAvailability::OwnedCleanupPending
                    | MediaAvailability::BorrowedCleanupPending
                    | MediaAvailability::SecurityBlocked
            ),
            "media cleanup intent requires cleanup-pending or recovery state"
        );
        let live_references: i64 = conn.query_row(
            "SELECT (SELECT COUNT(*) FROM media_attachment_references WHERE attachment_id=?1 AND attachment_version=?2 AND released_at_unix_ms IS NULL) + (SELECT COUNT(*) FROM media_attachment_component_leases WHERE attachment_id=?1 AND attachment_version=?2 AND released_at_unix_ms IS NULL)",
            params![intent.attachment_id.to_string(), decimal(intent.attachment_version)?],
            |row| row.get(0),
        ).context("counting live media references")?;
        ensure!(live_references == 0, "media attachment is in use");
        conn.execute(
            "INSERT INTO media_attachment_cleanup_intents (intent_id,attachment_id,attachment_version,expected_availability_generation,expected_reference_generation,component_set_digest,reason,created_at_unix_ms) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
            params![intent.intent_id.to_string(), intent.attachment_id.to_string(), decimal(intent.attachment_version)?, decimal(intent.expected_availability_generation)?, decimal(intent.expected_reference_generation)?, intent.component_set_digest, intent.reason, intent.created_at_unix_ms],
        ).context("inserting media cleanup intent")?;
        Ok(())
    }

    pub fn discard_unreferenced_media_attachment_conn(
        conn: &Connection,
        request: &DiscardUnreferencedMediaAttachmentV1,
        now_unix_ms: i64,
    ) -> Result<MediaDiscardDecision> {
        ensure!(
            request.schema_version == 1
                && request.kind == "discardUnreferencedMediaAttachment"
                && request.attachment_version > 0
                && request.availability_generation > 0
                && request.reference_generation > 0,
            "invalid discard request"
        );
        let record = media_attachment_by_id(conn, request.attachment_id)?
            .context("media_attachment_unavailable")?;
        let expected_origin=conn.query_row("SELECT client_draft_id,upload_id,upload_generation FROM media_attachment_upload_origins WHERE attachment_id=?1",[request.attachment_id.to_string()],|row|Ok(MediaOriginUploadV1{client_draft_id:Uuid::parse_str(&row.get::<_,String>(0)?).map_err(|_|rusqlite::Error::InvalidQuery)?,upload_id:Uuid::parse_str(&row.get::<_,String>(1)?).map_err(|_|rusqlite::Error::InvalidQuery)?,upload_generation:row.get::<_,String>(2)?.parse().map_err(|_|rusqlite::Error::InvalidQuery)?})).optional()?;
        ensure!(
            request.origin_upload == expected_origin,
            "discard origin conflict"
        );
        let reason = if request.attachment_version != record.attachment_version {
            Some(MediaDiscardReasonV1::StaleAttachmentVersion)
        } else if request.availability_generation != record.availability_generation {
            Some(MediaDiscardReasonV1::StaleAvailabilityGeneration)
        } else if request.reference_generation != record.reference_generation {
            Some(MediaDiscardReasonV1::StaleReferenceGeneration)
        } else if record.availability == MediaAvailability::SecurityBlocked {
            Some(MediaDiscardReasonV1::SecurityRecoveryRequired)
        } else if !matches!(
            record.availability,
            MediaAvailability::Registered
                | MediaAvailability::Quarantined
                | MediaAvailability::Probing
                | MediaAvailability::Decoding
                | MediaAvailability::Normalizing
                | MediaAvailability::Ready
                | MediaAvailability::ModelDerivativeUnavailable
                | MediaAvailability::SourceChanged
                | MediaAvailability::Failed
        ) {
            Some(MediaDiscardReasonV1::AvailabilityStateIneligible)
        } else {
            let live:i64=conn.query_row("SELECT (SELECT COUNT(*) FROM media_attachment_references WHERE attachment_id=?1 AND released_at_unix_ms IS NULL)+(SELECT COUNT(*) FROM media_attachment_component_leases WHERE attachment_id=?1 AND released_at_unix_ms IS NULL)",[request.attachment_id.to_string()],|row|row.get(0))?;
            if live > 0 {
                Some(MediaDiscardReasonV1::MediaAttachmentInUse)
            } else if record.availability_generation == u64::MAX {
                Some(MediaDiscardReasonV1::AvailabilityGenerationOverflow)
            } else {
                None
            }
        };
        if let Some(reason) = reason {
            return Ok(MediaDiscardDecision {
                attachment_id: record.attachment_id,
                attachment_version_before: record.attachment_version,
                availability_generation_before: record.availability_generation,
                availability_generation_after: record.availability_generation,
                reference_generation_before: record.reference_generation,
                reference_generation_after: record.reference_generation,
                outcome: MediaDiscardOutcomeV1::Rejected,
                reason,
            });
        }
        let next = record
            .availability_generation
            .checked_add(1)
            .context("availability generation overflow")?;
        let pending = if record.source_kind.is_borrowed() {
            MediaAvailability::BorrowedCleanupPending
        } else {
            MediaAvailability::OwnedCleanupPending
        };
        ensure!(conn.execute("UPDATE media_attachments SET availability=?1,availability_generation=?2,updated_at_unix_ms=?3 WHERE attachment_id=?4 AND availability_generation=?5 AND reference_generation=?6",params![pending.as_str(),decimal(next)?,now_unix_ms,record.attachment_id.to_string(),decimal(record.availability_generation)?,decimal(record.reference_generation)?])?==1,"discard lost compare-and-swap");
        let components = {
            let mut statement=conn.prepare("SELECT component_id,component_kind,component_generation FROM media_attachment_components WHERE attachment_id=?1 AND lifecycle_state<>'deleted' ORDER BY component_id")?;
            statement
                .query_map([record.attachment_id.to_string()], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?
        };
        let mut hasher = Sha256::new();
        hasher.update(b"media-cleanup-component-set-v1\0");
        for (component_id, kind, generation) in &components {
            hasher.update(component_id.as_bytes());
            hasher.update([0]);
            hasher.update(kind.as_bytes());
            hasher.update([0]);
            hasher.update(generation.as_bytes());
            hasher.update([0]);
            let next_component = generation
                .parse::<u64>()?
                .checked_add(1)
                .context("component generation overflow")?;
            ensure!(conn.execute("UPDATE media_attachment_components SET lifecycle_state='cleanup_pending',component_generation=?1,updated_at_unix_ms=?2 WHERE component_id=?3 AND component_generation=?4",params![decimal(next_component)?,now_unix_ms,component_id,generation])?==1,"discard component lost compare-and-swap");
        }
        let digest = hex_lower(&hasher.finalize());
        conn.execute("INSERT INTO media_attachment_cleanup_intents(intent_id,attachment_id,attachment_version,expected_availability_generation,expected_reference_generation,component_set_digest,reason,created_at_unix_ms) VALUES(?1,?2,?3,?4,?5,?6,'discard',?7)",params![Uuid::now_v7().to_string(),record.attachment_id.to_string(),decimal(record.attachment_version)?,decimal(next)?,decimal(record.reference_generation)?,digest,now_unix_ms])?;
        conn.execute("INSERT INTO media_attachment_transition_evidence(attachment_id,availability_generation,from_state,to_state,operation_id,committed_at_unix_ms) VALUES(?1,?2,?3,?4,?5,?6)",params![record.attachment_id.to_string(),decimal(next)?,record.availability.as_str(),pending.as_str(),Uuid::now_v7().to_string(),now_unix_ms])?;
        Ok(MediaDiscardDecision {
            attachment_id: record.attachment_id,
            attachment_version_before: record.attachment_version,
            availability_generation_before: record.availability_generation,
            availability_generation_after: next,
            reference_generation_before: record.reference_generation,
            reference_generation_after: record.reference_generation,
            outcome: MediaDiscardOutcomeV1::Applied,
            reason: MediaDiscardReasonV1::DiscardStarted,
        })
    }

    pub fn media_cleanup_intent_for_attachment_conn(
        conn: &Connection,
        attachment_id: Uuid,
    ) -> Result<Option<MediaCleanupIntent>> {
        conn.query_row(
            "SELECT intent_id,attachment_id,attachment_version,expected_availability_generation,expected_reference_generation,component_set_digest,reason,created_at_unix_ms FROM media_attachment_cleanup_intents WHERE attachment_id=?1",
            [attachment_id.to_string()],
            |row| {
                let intent_id = Uuid::parse_str(&row.get::<_, String>(0)?).map_err(|error| rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(error)))?;
                let persisted_attachment_id = Uuid::parse_str(&row.get::<_, String>(1)?).map_err(|error| rusqlite::Error::FromSqlConversionFailure(1, rusqlite::types::Type::Text, Box::new(error)))?;
                let parse = |column, field| parse_decimal(row.get(column)?, field).map_err(|error| rusqlite::Error::FromSqlConversionFailure(column, rusqlite::types::Type::Text, error.into()));
                Ok(MediaCleanupIntent {
                    intent_id,
                    attachment_id: persisted_attachment_id,
                    attachment_version: parse(2, "cleanup attachment version")?,
                    expected_availability_generation: parse(3, "cleanup availability generation")?,
                    expected_reference_generation: parse(4, "cleanup reference generation")?,
                    component_set_digest: row.get(5)?,
                    reason: row.get(6)?,
                    created_at_unix_ms: row.get(7)?,
                })
            },
        ).optional().context("loading media cleanup intent")
    }

    pub fn release_media_reference_conn(
        conn: &Connection,
        reference_id: Uuid,
        expected_reference_generation: u64,
        now_unix_ms: i64,
    ) -> Result<u64> {
        let attachment_id = conn.query_row(
            "SELECT attachment_id FROM media_attachment_references WHERE reference_id=?1 AND released_at_unix_ms IS NULL",
            [reference_id.to_string()],
            |row| row.get::<_, String>(0),
        ).optional().context("loading live media reference")?
            .context("media reference unavailable")?;
        let attachment_id =
            Uuid::parse_str(&attachment_id).context("invalid persisted media attachment id")?;
        let current = media_attachment_by_id(conn, attachment_id)?
            .context("referenced media attachment disappeared")?;
        ensure!(
            current.reference_generation == expected_reference_generation,
            "stale reference generation"
        );
        let next = current
            .reference_generation
            .checked_add(1)
            .context("media reference generation overflow")?;
        let released = conn.execute(
            "UPDATE media_attachment_references SET released_at_unix_ms=?1 WHERE reference_id=?2 AND released_at_unix_ms IS NULL",
            params![now_unix_ms, reference_id.to_string()],
        ).context("releasing media reference")?;
        ensure!(
            released == 1,
            "media reference release lost compare-and-swap"
        );
        let changed = conn.execute(
            "UPDATE media_attachments SET reference_generation=?1,updated_at_unix_ms=?2 WHERE attachment_id=?3 AND reference_generation=?4",
            params![decimal(next)?, now_unix_ms, attachment_id.to_string(), decimal(expected_reference_generation)?],
        ).context("advancing released media reference generation")?;
        ensure!(
            changed == 1,
            "media reference release lost attachment compare-and-swap"
        );
        Ok(next)
    }

    /// Atomically wins a ready component lease against discard/retention.
    /// The caller must open and verify the returned component while this row
    /// remains live; paths are intentionally not exposed here.
    pub fn acquire_media_component_lease_conn(
        conn: &Connection,
        lease_id: Uuid,
        attachment_id: Uuid,
        expected_version: u64,
        expected_availability_generation: u64,
        expected_capability_generation: u64,
        kind: MediaComponentLeaseKind,
        now_unix_ms: i64,
    ) -> Result<AcquiredMediaComponentLease> {
        ensure!(is_strict_uuid_v7(lease_id), "lease id must be UUIDv7");
        let attachment =
            media_attachment_by_id(conn, attachment_id)?.context("media attachment unavailable")?;
        ensure!(
            attachment.availability == MediaAvailability::Ready
                && attachment.attachment_version == expected_version
                && attachment.availability_generation == expected_availability_generation
                && attachment.captured_capability_generation == expected_capability_generation,
            "media attachment unavailable"
        );
        let component_kind = match (kind, attachment.media_kind) {
            (MediaComponentLeaseKind::Preview, MediaKind::Image) => "browser_thumbnail",
            (MediaComponentLeaseKind::Model, MediaKind::Image) => "image_model",
            (MediaComponentLeaseKind::Model, MediaKind::Audio) => "audio_model",
            (MediaComponentLeaseKind::Model, MediaKind::Video) => "video_model",
            _ => bail!("media attachment unavailable"),
        };
        let component = conn
            .query_row(
                "SELECT component_id,storage_id,component_generation,stable_identity_digest,byte_length,sha256,reservation_id,created_at_unix_ms,updated_at_unix_ms FROM media_attachment_components WHERE attachment_id=?1 AND attachment_version=?2 AND component_kind=?3 AND lifecycle_state='ready'",
                params![attachment_id.to_string(), decimal(expected_version)?, component_kind],
                |row| {
                    let uuid = |column| Uuid::parse_str(&row.get::<_, String>(column)?).map_err(|error| rusqlite::Error::FromSqlConversionFailure(column, rusqlite::types::Type::Text, Box::new(error)));
                    let number = |column, field| parse_decimal(row.get(column)?, field).map_err(|error| rusqlite::Error::FromSqlConversionFailure(column, rusqlite::types::Type::Text, error.into()));
                    Ok(MediaAttachmentComponent {
                        component_id: uuid(0)?, attachment_id, attachment_version: expected_version,
                        component_kind: component_kind.to_owned(), storage_id: uuid(1)?, lifecycle_state: "ready".into(),
                        component_generation: number(2, "component generation")?, stable_identity_digest: row.get(3)?,
                        byte_length: number(4, "component byte length")?, sha256: row.get(5)?, reservation_id: row.get(6)?,
                        created_at_unix_ms: row.get(7)?, updated_at_unix_ms: row.get(8)?,
                    })
                },
            )
            .optional()?
            .context("media attachment unavailable")?;
        conn.execute(
            "INSERT INTO media_attachment_component_leases(lease_id,attachment_id,attachment_version,component_id,lease_kind,expected_availability_generation,captured_capability_generation,acquired_at_unix_ms) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
            params![lease_id.to_string(), attachment_id.to_string(), decimal(expected_version)?, component.component_id.to_string(), kind.as_str(), decimal(expected_availability_generation)?, decimal(expected_capability_generation)?, now_unix_ms],
        ).context("acquiring media component lease")?;
        Ok(AcquiredMediaComponentLease {
            lease_id,
            attachment_id,
            attachment_version: expected_version,
            availability_generation: expected_availability_generation,
            captured_capability_generation: expected_capability_generation,
            component,
        })
    }

    pub fn release_media_component_lease_conn(
        conn: &Connection,
        lease_id: Uuid,
        now_unix_ms: i64,
    ) -> Result<()> {
        let changed = conn.execute(
            "UPDATE media_attachment_component_leases SET released_at_unix_ms=?1 WHERE lease_id=?2 AND released_at_unix_ms IS NULL",
            params![now_unix_ms, lease_id.to_string()],
        ).context("releasing media component lease")?;
        ensure!(changed == 1, "media component lease unavailable");
        Ok(())
    }
}

fn validate_new_record(record: &MediaAttachmentRecord) -> Result<()> {
    ensure!(
        record.attachment_version > 0
            && record.availability_generation > 0
            && record.reference_generation > 0
            && record.captured_capability_generation > 0
            && record.source_byte_length > 0,
        "media versions, generations, and byte length must be positive"
    );
    let expected = if record.source_kind.is_borrowed() {
        MediaAvailability::Registered
    } else {
        MediaAvailability::Quarantined
    };
    ensure!(
        record.availability == expected,
        "invalid initial media availability"
    );
    ensure!(
        record.source_kind == MediaSourceKind::AuthenticatedSessionUpload
            || record.draft_expires_at_unix_ms.is_none(),
        "draft expiry is upload-only"
    );
    validate_digest(&record.canonical_project_digest, "project digest")?;
    validate_digest(&record.source_identity_digest, "source identity digest")?;
    validate_digest(&record.source_sha256, "source checksum")?;
    ensure!(
        record.selected_video_stream.is_none() || record.media_kind == MediaKind::Video,
        "video stream requires video media kind"
    );
    ensure!(
        record.selected_audio_stream.is_none() || record.media_kind != MediaKind::Image,
        "audio stream is forbidden for images"
    );
    Ok(())
}

fn security_recovery_request_digest(request: &RecoverSecurityBlockedMediaV1) -> Result<String> {
    let canonical =
        serde_json::to_vec(request).context("encoding canonical media recovery request")?;
    Ok(hex_lower(&Sha256::digest(canonical)))
}

fn security_recovery_affected_set_digest(
    components: &[SecurityRecoveryComponentSnapshot],
) -> String {
    fn field(hasher: &mut Sha256, bytes: &[u8]) {
        hasher.update((bytes.len() as u64).to_be_bytes());
        hasher.update(bytes);
    }
    fn component(hasher: &mut Sha256, value: &VerifiedBlockedComponent) {
        field(hasher, value.component_id.as_bytes());
        field(hasher, value.component_kind.as_bytes());
        field(hasher, &value.component_generation.to_be_bytes());
        field(hasher, value.stable_identity_digest.as_bytes());
        field(hasher, &value.byte_length.to_be_bytes());
        field(hasher, value.sha256.as_bytes());
        field(hasher, value.reservation_id.as_bytes());
        match &value.deletion_evidence_digest {
            Some(digest) => {
                field(hasher, &[1]);
                field(hasher, digest.as_bytes());
            }
            None => field(hasher, &[0]),
        }
    }
    let mut affected = Sha256::new();
    field(&mut affected, b"media-security-affected-set-v1");
    for value in components {
        component(&mut affected, &value.component);
    }
    hex_lower(&affected.finalize())
}

fn component_recorded_evidence_digest(component: &VerifiedBlockedComponent) -> String {
    fn field(hasher: &mut Sha256, bytes: &[u8]) {
        hasher.update((bytes.len() as u64).to_be_bytes());
        hasher.update(bytes);
    }
    let mut hasher = Sha256::new();
    field(&mut hasher, component.component_id.as_bytes());
    field(&mut hasher, component.component_kind.as_bytes());
    field(&mut hasher, &component.component_generation.to_be_bytes());
    field(&mut hasher, component.stable_identity_digest.as_bytes());
    field(&mut hasher, &component.byte_length.to_be_bytes());
    field(&mut hasher, component.sha256.as_bytes());
    field(&mut hasher, component.reservation_id.as_bytes());
    field(
        &mut hasher,
        component
            .deletion_evidence_digest
            .as_deref()
            .unwrap_or("")
            .as_bytes(),
    );
    hex_lower(&hasher.finalize())
}

fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

fn component_kind_compatible(
    parent: &MediaAttachmentRecord,
    component_kind: &str,
    lifecycle_state: &str,
) -> bool {
    let kind_matches = match component_kind {
        "quarantined_original" => !parent.source_kind.is_borrowed(),
        "upload_temporary" => parent.source_kind == MediaSourceKind::AuthenticatedSessionUpload,
        "image_model" | "browser_thumbnail" => parent.media_kind == MediaKind::Image,
        "audio_model" => parent.media_kind == MediaKind::Audio,
        "video_model" => parent.media_kind == MediaKind::Video,
        _ => false,
    };
    kind_matches
        && matches!(
            lifecycle_state,
            "temporary" | "ready" | "cleanup_pending" | "deleted" | "security_blocked"
        )
        && (lifecycle_state != "temporary"
            || matches!(component_kind, "upload_temporary" | "quarantined_original"))
}

fn decimal(value: u64) -> Result<String> {
    ensure!(value > 0, "media u64 value must be positive");
    Ok(value.to_string())
}

fn parse_decimal(value: String, field: &'static str) -> Result<u64> {
    ensure!(
        !value.is_empty()
            && (value == "0" || !value.starts_with('0'))
            && value.bytes().all(|byte| byte.is_ascii_digit()),
        "invalid canonical {field}"
    );
    let parsed = value
        .parse::<u64>()
        .with_context(|| format!("invalid {field}"))?;
    ensure!(parsed > 0, "{field} must be positive");
    Ok(parsed)
}

fn validate_digest(value: &str, field: &str) -> Result<()> {
    ensure!(
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
        "{field} must be lowercase SHA-256"
    );
    Ok(())
}

fn is_strict_uuid_v7(value: Uuid) -> bool {
    !value.is_nil() && value.get_version_num() == 7 && value.get_variant() == uuid::Variant::RFC4122
}

fn stream_json(stream: &Option<SelectedMediaStream>) -> Result<Option<String>> {
    stream
        .as_ref()
        .map(|stream| {
            serde_json::to_string(&(stream.index, &stream.codec))
                .context("encoding selected media stream")
        })
        .transpose()
}

fn parse_stream(value: Option<String>) -> Result<Option<SelectedMediaStream>> {
    value
        .map(|value| {
            let (index, codec): (u32, String) =
                serde_json::from_str(&value).context("decoding selected media stream")?;
            ensure!(!codec.is_empty(), "selected media stream codec is empty");
            Ok(SelectedMediaStream { index, codec })
        })
        .transpose()
}

fn decode_record(row: &rusqlite::Row<'_>) -> rusqlite::Result<MediaAttachmentRecord> {
    decode_record_fallible(row).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, error.into())
    })
}

fn decode_record_fallible(row: &rusqlite::Row<'_>) -> Result<MediaAttachmentRecord> {
    Ok(MediaAttachmentRecord {
        attachment_id: Uuid::parse_str(&row.get::<_, String>(0)?)?,
        session_id: Uuid::parse_str(&row.get::<_, String>(1)?)?,
        canonical_project_digest: row.get(2)?,
        media_kind: MediaKind::parse(&row.get::<_, String>(3)?)?,
        source_kind: MediaSourceKind::parse(&row.get::<_, String>(4)?)?,
        canonical_container: row.get(5)?,
        canonical_mime: row.get(6)?,
        availability: MediaAvailability::parse(&row.get::<_, String>(7)?)?,
        attachment_version: parse_decimal(row.get(8)?, "attachment version")?,
        availability_generation: parse_decimal(row.get(9)?, "availability generation")?,
        reference_generation: parse_decimal(row.get(10)?, "reference generation")?,
        captured_capability_generation: parse_decimal(
            row.get(11)?,
            "captured capability generation",
        )?,
        source_identity_digest: row.get(12)?,
        source_byte_length: parse_decimal(row.get(13)?, "source byte length")?,
        source_sha256: row.get(14)?,
        selected_video_stream: parse_stream(row.get(15)?)?,
        selected_audio_stream: parse_stream(row.get(16)?)?,
        created_at_unix_ms: row.get(17)?,
        updated_at_unix_ms: row.get(18)?,
        draft_expires_at_unix_ms: row.get(19)?,
        first_referenced_at_unix_ms: row.get(20)?,
    })
}

fn media_attachment_by_id(conn: &Connection, id: Uuid) -> Result<Option<MediaAttachmentRecord>> {
    conn.query_row("SELECT attachment_id,session_id,canonical_project_digest,media_kind,source_kind,canonical_container,canonical_mime,availability,attachment_version,availability_generation,reference_generation,captured_capability_generation,source_identity_digest,source_byte_length,source_sha256,selected_video_stream_json,selected_audio_stream_json,created_at_unix_ms,updated_at_unix_ms,draft_expires_at_unix_ms,first_referenced_at_unix_ms FROM media_attachments WHERE attachment_id=?1", [id.to_string()], decode_record).optional().context("loading media attachment")
}

fn existing_reference(
    conn: &Connection,
    attachment_id: Uuid,
    version: u64,
    kind: MediaReferenceConsumerKind,
    consumer_id: &str,
) -> Result<Option<AcquiredMediaReference>> {
    conn.query_row("SELECT reference_id,acquired_generation FROM media_attachment_references WHERE attachment_id=?1 AND attachment_version=?2 AND consumer_kind=?3 AND consumer_id=?4", params![attachment_id.to_string(), decimal(version)?, kind.as_str(), consumer_id], |row| {
        let reference_id = Uuid::parse_str(&row.get::<_, String>(0)?).map_err(|error| rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(error)))?;
        let generation = parse_decimal(row.get(1)?, "acquired generation").map_err(|error| rusqlite::Error::FromSqlConversionFailure(1, rusqlite::types::Type::Text, error.into()))?;
        Ok(AcquiredMediaReference { reference_id, attachment_id, attachment_version: version, reference_generation: generation, inserted: false })
    }).optional().context("loading media attachment reference")
}

macro_rules! text_enum {
    ($ty:ty, {$($variant:ident => $value:literal),+ $(,)?}) => {
        impl $ty {
            pub fn as_str(self) -> &'static str { match self { $(Self::$variant => $value),+ } }
            fn parse(value: &str) -> Result<Self> { match value { $($value => Ok(Self::$variant),)+ _ => bail!("invalid {} `{value}`", stringify!($ty)) } }
        }
    };
}

text_enum!(MediaKind, { Image => "image", Audio => "audio", Video => "video" });
text_enum!(MediaSourceKind, { LocalPath => "local_path", RetainedHttps => "retained_https", AuthenticatedSessionUpload => "authenticated_session_upload" });
text_enum!(MediaReferenceConsumerKind, { Message => "message", Tool => "tool", Job => "job" });
text_enum!(MediaComponentLeaseKind, { Preview => "preview", Model => "model" });
text_enum!(MediaAvailability, {
    Registered => "registered", Quarantined => "quarantined", Probing => "probing", Decoding => "decoding",
    Normalizing => "normalizing", Ready => "ready", ModelDerivativeUnavailable => "model_derivative_unavailable",
    SourceChanged => "source_changed", Failed => "failed", SecurityBlocked => "security_blocked",
    OwnedCleanupPending => "owned_cleanup_pending", RetainedCopyDeleted => "retained_copy_deleted",
    BorrowedCleanupPending => "borrowed_cleanup_pending", BorrowedDerivativesDeleted => "borrowed_derivatives_deleted",
    MetadataDeleted => "metadata_deleted"
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn https_media_ingest_request_and_redacted_receipt_are_closed() {
        let operation_id = Uuid::now_v7();
        let session_id = Uuid::now_v7();
        let draft_id = Uuid::now_v7();
        let request_json = serde_json::json!({
            "schemaVersion": 1,
            "kind": "retainHttpsMedia",
            "localOperationId": operation_id,
            "ownerPrincipalDigest": "11".repeat(32),
            "sessionId": session_id,
            "canonicalProjectDigest": "22".repeat(32),
            "clientDraftId": draft_id,
            "requestedMediaKind": "image",
            "url": "https://media.example.test/private/signed.png?token=secret"
        });
        let request: RetainHttpsMediaV1 = serde_json::from_value(request_json.clone()).unwrap();
        assert_eq!(serde_json::to_value(&request).unwrap(), request_json);

        let receipt = RetainedHttpsMediaReceiptV1 {
            schema_version: 1,
            kind: "retainedHttpsMediaReceipt".into(),
            receipt_id: Uuid::now_v7(),
            local_operation_id: operation_id,
            owner_principal_digest: "11".repeat(32),
            session_id,
            canonical_project_digest: "22".repeat(32),
            client_draft_id: draft_id,
            operation_request_digest: "33".repeat(32),
            semantic_command_digest: "44".repeat(32),
            origin_scheme: "https".into(),
            redirect_location_classes: vec![HttpsRedirectLocationClassV1::CrossOrigin],
            path_segment_count: 2,
            safe_basename: Some("signed.png".into()),
            fetched_at_unix_ms: 1,
            result: HttpsRetentionResultV1::Rejected {
                reason: HttpsRetentionRejectionReasonV1::SourceUnavailable,
            },
            committed_at_unix_ms: 2,
        };
        let encoded = serde_json::to_string(&receipt).unwrap();
        assert!(!encoded.contains("media.example"));
        assert!(!encoded.contains("private/"));
        assert!(!encoded.contains("token"));
        assert!(!encoded.contains("secret"));
        assert_eq!(
            serde_json::from_str::<RetainedHttpsMediaReceiptV1>(&encoded).unwrap(),
            receipt
        );

        let mut unknown = request_json.clone();
        unknown
            .as_object_mut()
            .unwrap()
            .insert("extra".into(), true.into());
        assert!(serde_json::from_value::<RetainHttpsMediaV1>(unknown).is_err());
        let mut malformed = request_json;
        malformed["clientDraftId"] = serde_json::json!(draft_id.to_string().to_uppercase());
        assert!(serde_json::from_value::<RetainHttpsMediaV1>(malformed).is_err());
    }

    fn id(value: u128) -> Uuid {
        Uuid::from_u128(value)
    }

    #[test]
    fn media_owner_recovery_uuid_codec_matches_shared_malformed_vectors() {
        #[derive(Deserialize)]
        struct StrictUuid(#[serde(with = "strict_uuid_v7")] Uuid);
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../packages/cockpit-protocol/fixtures/media-owner-recovery-uuid-v1.json"
        ))
        .unwrap();
        let valid = fixture["valid"].as_str().unwrap();
        assert_eq!(
            serde_json::from_str::<StrictUuid>(&format!("\"{valid}\""))
                .unwrap()
                .0
                .to_string(),
            valid
        );
        for malformed in fixture["malformed"].as_array().unwrap() {
            assert!(
                serde_json::from_str::<StrictUuid>(&serde_json::to_string(malformed).unwrap())
                    .is_err(),
                "accepted {malformed}"
            );
        }
    }

    #[test]
    fn media_attachment_status_v1_codec_is_closed_and_path_free() {
        let attachment_id = Uuid::now_v7();
        let status = MediaAttachmentStatusV1 {
            schema_version: 1,
            kind: "mediaAttachmentStatus".into(),
            attachment_id,
            attachment_version: 1,
            media_kind: RequestedLocalPathMediaKind::Image,
            availability_generation: 1,
            reference_generation: 1,
            can_discard: true,
            preview_available: false,
            draft_expires_at_unix_ms: None,
            detail: MediaAttachmentStatusDetailV1::Registered,
        };
        let encoded = serde_json::to_value(&status).unwrap();
        assert_eq!(
            encoded,
            serde_json::json!({"schemaVersion":1,"kind":"mediaAttachmentStatus","attachmentId":attachment_id.to_string(),"attachmentVersion":1,"mediaKind":"image","availabilityGeneration":1,"referenceGeneration":1,"canDiscard":true,"previewAvailable":false,"availabilityState":"registered"})
        );
        let text = serde_json::to_string(&encoded).unwrap();
        assert_eq!(
            serde_json::from_str::<MediaAttachmentStatusV1>(&text).unwrap(),
            status
        );
        let mut unknown = encoded;
        unknown
            .as_object_mut()
            .unwrap()
            .insert("path".into(), serde_json::json!("/secret"));
        assert!(serde_json::from_value::<MediaAttachmentStatusV1>(unknown).is_err());
        let request = serde_json::json!({"schemaVersion":1,"kind":"getMediaAttachmentStatus","sessionId":Uuid::now_v7().to_string(),"canonicalProjectDigest":"11".repeat(32),"attachmentId":attachment_id.to_string(),"extra":true});
        assert!(serde_json::from_value::<GetMediaAttachmentStatusV1>(request).is_err());
    }

    #[test]
    fn local_media_mutation_v1_digests_and_chunk_bounds_are_exact() {
        let make = |operation_id| LocalMediaMutationV1 {
            schema_version: 1,
            kind: "localMediaMutation".into(),
            local_operation_id: operation_id,
            actor_principal_digest: "11".repeat(32),
            actor_role: LocalMediaActorRoleV1::Writer,
            payload: LocalMediaMutationPayloadV1::Append {
                session_id: Uuid::now_v7(),
                canonical_project_digest: "22".repeat(32),
                client_draft_id: Uuid::now_v7(),
                upload_id: Uuid::now_v7(),
                upload_generation: 1,
                chunk_index: 0,
                chunk_length: 262_144,
                chunk_sha256: "33".repeat(32),
            },
        };
        let first = make(Uuid::now_v7());
        let mut alias = first.clone();
        alias.local_operation_id = Uuid::now_v7();
        let first_digests = super::super::Db::local_media_mutation_digests(&first).unwrap();
        let alias_digests = super::super::Db::local_media_mutation_digests(&alias).unwrap();
        assert_ne!(first_digests.0, alias_digests.0);
        assert_eq!(first_digests.1, alias_digests.1);
        let encoded = serde_json::to_value(&first).unwrap();
        assert_eq!(encoded["payload"]["chunkLength"], 262_144);
        assert!(encoded.get("path").is_none());
        let mut over = first.clone();
        let LocalMediaMutationPayloadV1::Append { chunk_length, .. } = &mut over.payload else {
            unreachable!()
        };
        *chunk_length = 262_145;
        assert!(super::super::Db::validate_local_media_mutation_v1(&over).is_err());
        let mut zero = first;
        let LocalMediaMutationPayloadV1::Append { chunk_length, .. } = &mut zero.payload else {
            unreachable!()
        };
        *chunk_length = 0;
        assert!(super::super::Db::validate_local_media_mutation_v1(&zero).is_err());
    }

    #[test]
    fn media_attachment_source_lifecycles_are_closed() {
        assert!(
            MediaAvailability::Registered
                .permits_transition(MediaSourceKind::LocalPath, MediaAvailability::Probing)
        );
        assert!(!MediaAvailability::Registered.permits_transition(
            MediaSourceKind::LocalPath,
            MediaAvailability::OwnedCleanupPending
        ));
        assert!(MediaAvailability::Ready.permits_transition(
            MediaSourceKind::RetainedHttps,
            MediaAvailability::OwnedCleanupPending
        ));
        assert!(!MediaAvailability::Ready.permits_transition(
            MediaSourceKind::RetainedHttps,
            MediaAvailability::SourceChanged
        ));
        assert!(
            !MediaAvailability::RetainedCopyDeleted
                .permits_transition(MediaSourceKind::RetainedHttps, MediaAvailability::Ready)
        );
        assert!(!MediaAvailability::SecurityBlocked.permits_transition(
            MediaSourceKind::RetainedHttps,
            MediaAvailability::OwnedCleanupPending
        ));
        assert!(!MediaAvailability::SecurityBlocked.permits_transition(
            MediaSourceKind::LocalPath,
            MediaAvailability::BorrowedCleanupPending
        ));
    }

    #[test]
    fn media_attachment_exact_u64_is_canonical() {
        assert_eq!(
            parse_decimal(u64::MAX.to_string(), "generation").unwrap(),
            u64::MAX
        );
        assert!(parse_decimal("00".into(), "generation").is_err());
        assert!(parse_decimal("0".into(), "generation").is_err());
        assert!(parse_decimal("18446744073709551616".into(), "generation").is_err());
    }

    #[tokio::test]
    async fn media_attachment_transaction_exposes_readiness_ownership_and_capability_generation() {
        let db = super::super::Db::open_in_memory_async().await.unwrap();
        let session_id = id(1);
        let attachment_id = id(2);
        let project_digest = "11".repeat(32);
        let record = MediaAttachmentRecord {
            attachment_id,
            session_id,
            canonical_project_digest: project_digest.clone(),
            media_kind: MediaKind::Image,
            source_kind: MediaSourceKind::RetainedHttps,
            canonical_container: "png".into(),
            canonical_mime: "image/png".into(),
            availability: MediaAvailability::Quarantined,
            attachment_version: u64::MAX,
            availability_generation: 1,
            reference_generation: 1,
            captured_capability_generation: u64::MAX,
            source_identity_digest: "22".repeat(32),
            source_byte_length: u64::MAX,
            source_sha256: "33".repeat(32),
            selected_video_stream: None,
            selected_audio_stream: None,
            created_at_unix_ms: 10,
            updated_at_unix_ms: 10,
            draft_expires_at_unix_ms: None,
            first_referenced_at_unix_ms: None,
        };
        let inserted = record.clone();
        db.transaction(move |conn| {
            conn.execute(
                "INSERT INTO sessions (session_id,project_id,project_root,started_at,last_active_at) VALUES (?1,'project','/redacted',1,1)",
                [session_id.to_string()],
            )?;
            super::super::Db::insert_media_attachment_conn(conn, &inserted)
        })
        .await
        .unwrap();

        let loaded = db
            .read(move |conn| {
                super::super::Db::media_attachment_for_owner_conn(
                    conn,
                    attachment_id,
                    session_id,
                    &project_digest,
                )
            })
            .await
            .unwrap()
            .unwrap();
        assert!(!loaded.availability.is_ready());
        assert_eq!(loaded.attachment_version, u64::MAX);
        assert_eq!(loaded.source_byte_length, u64::MAX);
        assert_eq!(loaded.captured_capability_generation, u64::MAX);
    }

    #[tokio::test]
    async fn media_attachment_reference_is_durable_non_consuming_and_idempotent() {
        let db = super::super::Db::open_in_memory_async().await.unwrap();
        let session_id = id(11);
        let attachment_id = id(12);
        let project_digest = "44".repeat(32);
        let inserted_digest = project_digest.clone();
        db.transaction(move |conn| {
            conn.execute(
                "INSERT INTO sessions (session_id,project_id,project_root,started_at,last_active_at) VALUES (?1,'project','/redacted',1,1)",
                [session_id.to_string()],
            )?;
            let record = MediaAttachmentRecord {
                attachment_id,
                session_id,
                canonical_project_digest: inserted_digest,
                media_kind: MediaKind::Image,
                source_kind: MediaSourceKind::RetainedHttps,
                canonical_container: "png".into(),
                canonical_mime: "image/png".into(),
                availability: MediaAvailability::Quarantined,
                attachment_version: 1,
                availability_generation: 1,
                reference_generation: 1,
                captured_capability_generation: 7,
                source_identity_digest: "55".repeat(32),
                source_byte_length: 8,
                source_sha256: "66".repeat(32),
                selected_video_stream: None,
                selected_audio_stream: None,
                created_at_unix_ms: 1,
                updated_at_unix_ms: 1,
                draft_expires_at_unix_ms: None,
                first_referenced_at_unix_ms: None,
            };
            super::super::Db::insert_media_attachment_conn(conn, &record)?;
            let mut generation = 1;
            for state in [
                MediaAvailability::Probing,
                MediaAvailability::Decoding,
                MediaAvailability::Normalizing,
                MediaAvailability::Ready,
            ] {
                super::super::Db::transition_media_attachment_conn(
                    conn,
                    attachment_id,
                    1,
                    generation,
                    state,
                    generation as i64 + 1,
                )?;
                generation += 1;
            }
            let first = super::super::Db::acquire_media_reference_conn(
                conn,
                id(13),
                attachment_id,
                1,
                session_id,
                &project_digest,
                MediaReferenceConsumerKind::Message,
                "message-a",
                10,
            )?;
            let retry = super::super::Db::acquire_media_reference_conn(
                conn,
                id(14),
                attachment_id,
                1,
                session_id,
                &project_digest,
                MediaReferenceConsumerKind::Message,
                "message-a",
                11,
            )?;
            let second = super::super::Db::acquire_media_reference_conn(
                conn,
                id(15),
                attachment_id,
                1,
                session_id,
                &project_digest,
                MediaReferenceConsumerKind::Message,
                "message-b",
                12,
            )?;
            assert!(first.inserted);
            assert!(!retry.inserted);
            assert_eq!(retry.reference_id, first.reference_id);
            assert!(second.inserted);
            assert_eq!(second.reference_generation, first.reference_generation + 1);
            Ok(())
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn ready_component_lease_serializes_with_cleanup_and_capability_rotation() {
        let db = super::super::Db::open_in_memory_async().await.unwrap();
        let session_id = Uuid::now_v7();
        let attachment_id = Uuid::now_v7();
        let component_id = Uuid::now_v7();
        let storage_id = Uuid::now_v7();
        db.transaction(move |conn| {
            conn.execute("INSERT INTO sessions(session_id,project_id,project_root,started_at,last_active_at) VALUES(?1,'p','/redacted',1,1)",[session_id.to_string()])?;
            let record = MediaAttachmentRecord { attachment_id, session_id, canonical_project_digest:"11".repeat(32), media_kind:MediaKind::Image, source_kind:MediaSourceKind::RetainedHttps, canonical_container:"png".into(), canonical_mime:"image/png".into(), availability:MediaAvailability::Ready, attachment_version:1, availability_generation:5, reference_generation:1, captured_capability_generation:9, source_identity_digest:"22".repeat(32), source_byte_length:3, source_sha256:"33".repeat(32), selected_video_stream:None, selected_audio_stream:None, created_at_unix_ms:1, updated_at_unix_ms:1, draft_expires_at_unix_ms:None, first_referenced_at_unix_ms:None };
            super::super::Db::insert_media_attachment_conn(conn,&record)?;
            conn.execute("INSERT INTO media_attachment_components(component_id,attachment_id,attachment_version,component_kind,storage_id,lifecycle_state,component_generation,stable_identity_digest,byte_length,sha256,reservation_id,created_at_unix_ms,updated_at_unix_ms) VALUES(?1,?2,'1','browser_thumbnail',?3,'ready','1',?4,'3',?5,'reservation',1,1)",params![component_id.to_string(),attachment_id.to_string(),storage_id.to_string(),"44".repeat(32),"55".repeat(32)])?;
            assert!(super::super::Db::acquire_media_component_lease_conn(conn,Uuid::now_v7(),attachment_id,1,5,8,MediaComponentLeaseKind::Preview,2).is_err());
            let lease_id=Uuid::now_v7();
            let lease=super::super::Db::acquire_media_component_lease_conn(conn,lease_id,attachment_id,1,5,9,MediaComponentLeaseKind::Preview,2)?;
            assert_eq!(lease.component.component_id,component_id);
            let live:i64=conn.query_row("SELECT COUNT(*) FROM media_attachment_component_leases WHERE attachment_id=?1 AND released_at_unix_ms IS NULL",[attachment_id.to_string()],|row|row.get(0))?;
            assert_eq!(live,1);
            super::super::Db::release_media_component_lease_conn(conn,lease_id,3)?;
            assert!(super::super::Db::release_media_component_lease_conn(conn,lease_id,4).is_err());
            Ok(())
        }).await.unwrap();
    }

    #[test]
    fn media_attachment_component_compatibility_is_source_and_kind_closed() {
        let parent = MediaAttachmentRecord {
            attachment_id: id(21),
            session_id: id(22),
            canonical_project_digest: "77".repeat(32),
            media_kind: MediaKind::Audio,
            source_kind: MediaSourceKind::LocalPath,
            canonical_container: "wav".into(),
            canonical_mime: "audio/wav".into(),
            availability: MediaAvailability::Registered,
            attachment_version: 1,
            availability_generation: 1,
            reference_generation: 1,
            captured_capability_generation: 1,
            source_identity_digest: "88".repeat(32),
            source_byte_length: 1,
            source_sha256: "99".repeat(32),
            selected_video_stream: None,
            selected_audio_stream: Some(SelectedMediaStream {
                index: 0,
                codec: "pcm_s16le".into(),
            }),
            created_at_unix_ms: 1,
            updated_at_unix_ms: 1,
            draft_expires_at_unix_ms: None,
            first_referenced_at_unix_ms: None,
        };
        assert!(component_kind_compatible(&parent, "audio_model", "ready"));
        assert!(!component_kind_compatible(&parent, "video_model", "ready"));
        assert!(!component_kind_compatible(
            &parent,
            "quarantined_original",
            "ready"
        ));
        assert!(!component_kind_compatible(
            &parent,
            "audio_model",
            "temporary"
        ));
    }

    #[test]
    fn media_security_recovery_digest_binds_complete_component_evidence() {
        let component = VerifiedBlockedComponent {
            component_id: id(31),
            component_kind: "image_model".into(),
            component_generation: 4,
            stable_identity_digest: "aa".repeat(32),
            byte_length: 9,
            sha256: "bb".repeat(32),
            reservation_id: "reservation-1".into(),
            deletion_evidence_digest: Some("cc".repeat(32)),
        };
        let baseline = component_recorded_evidence_digest(&component);
        let mutations: [fn(&mut VerifiedBlockedComponent); 7] = [
            |value: &mut VerifiedBlockedComponent| value.component_kind = "video_model".into(),
            |value: &mut VerifiedBlockedComponent| value.component_generation += 1,
            |value: &mut VerifiedBlockedComponent| value.stable_identity_digest = "ee".repeat(32),
            |value: &mut VerifiedBlockedComponent| value.byte_length += 1,
            |value: &mut VerifiedBlockedComponent| value.sha256 = "ff".repeat(32),
            |value: &mut VerifiedBlockedComponent| value.reservation_id.push('x'),
            |value: &mut VerifiedBlockedComponent| value.deletion_evidence_digest = None,
        ];
        for mutation in mutations {
            let mut changed = component.clone();
            mutation(&mut changed);
            assert_ne!(component_recorded_evidence_digest(&changed), baseline);
        }
    }

    #[test]
    fn discard_fcdr_has_exact_actor_lengths_and_network_order() {
        let result_id = Uuid::now_v7();
        let operation_id = Uuid::now_v7();
        let attachment_id = Uuid::now_v7();
        let remote = MediaDiscardResultV1::Remote {
            schema_version: 1,
            kind: "mediaDiscardResult".into(),
            result_id,
            operation_id,
            request_digest: "11".repeat(32),
            attachment_id,
            requested_attachment_version: 1,
            attachment_version_before: 1,
            requested_availability_generation: 7,
            availability_generation_before: 7,
            availability_generation_after: 8,
            requested_reference_generation: 3,
            reference_generation_before: 3,
            reference_generation_after: 3,
            outcome: MediaDiscardOutcomeV1::Applied,
            reason: MediaDiscardReasonV1::DiscardStarted,
        };
        let bytes = remote.encode_fcdr().unwrap();
        assert_eq!(bytes.len(), 153);
        assert_eq!(&bytes[..6], b"FCDR\x01\x01");
        assert_eq!(&bytes[87..95], &1u64.to_be_bytes());
        assert_eq!(&bytes[151..], [1, 1]);
        let local = MediaDiscardResultV1::Local {
            schema_version: 1,
            kind: "mediaDiscardResult".into(),
            result_id,
            local_operation_id: operation_id,
            operation_request_digest: "11".repeat(32),
            semantic_command_digest: "22".repeat(32),
            attachment_id,
            requested_attachment_version: 1,
            attachment_version_before: 1,
            requested_availability_generation: 7,
            availability_generation_before: 7,
            availability_generation_after: 7,
            requested_reference_generation: 3,
            reference_generation_before: 3,
            reference_generation_after: 3,
            outcome: MediaDiscardOutcomeV1::Rejected,
            reason: MediaDiscardReasonV1::MediaAttachmentInUse,
        };
        let bytes = local.encode_fcdr().unwrap();
        assert_eq!(bytes.len(), 185);
        assert_eq!(&bytes[..6], b"FCDR\x01\x02");
        assert_eq!(&bytes[183..], [2, 2]);
    }

    #[tokio::test]
    async fn discard_snapshot_precedence_in_use_overflow_and_apply_are_stable() {
        let db = super::super::Db::open_in_memory_async().await.unwrap();
        let session = Uuid::now_v7();
        let make = |id| MediaAttachmentRecord {
            attachment_id: id,
            session_id: session,
            canonical_project_digest: "11".repeat(32),
            media_kind: MediaKind::Image,
            source_kind: MediaSourceKind::LocalPath,
            canonical_container: "png".into(),
            canonical_mime: "image/png".into(),
            availability: MediaAvailability::Registered,
            attachment_version: 1,
            availability_generation: 1,
            reference_generation: 1,
            captured_capability_generation: 1,
            source_identity_digest: "22".repeat(32),
            source_byte_length: 1,
            source_sha256: "33".repeat(32),
            selected_video_stream: None,
            selected_audio_stream: None,
            created_at_unix_ms: 1,
            updated_at_unix_ms: 1,
            draft_expires_at_unix_ms: None,
            first_referenced_at_unix_ms: None,
        };
        let applied = Uuid::now_v7();
        let in_use = Uuid::now_v7();
        let overflow = Uuid::now_v7();
        let reference_id = Uuid::now_v7();
        db.transaction(move|conn|{conn.execute("INSERT INTO sessions(session_id,project_id,project_root,started_at,last_active_at)VALUES(?1,'p','/redacted',1,1)",[session.to_string()])?;for id in [applied,in_use,overflow]{super::super::Db::insert_media_attachment_conn(conn,&make(id))?;}super::super::Db::acquire_media_reference_conn(conn,reference_id,in_use,1,session,&"11".repeat(32),MediaReferenceConsumerKind::Message,"message",2)?;conn.execute("UPDATE media_attachments SET availability_generation=?1 WHERE attachment_id=?2",params![u64::MAX.to_string(),overflow.to_string()])?;Ok(())}).await.unwrap();
        let request = |id, availability, reference| DiscardUnreferencedMediaAttachmentV1 {
            schema_version: 1,
            kind: "discardUnreferencedMediaAttachment".into(),
            attachment_id: id,
            attachment_version: 1,
            availability_generation: availability,
            reference_generation: reference,
            origin_upload: None,
        };
        let decisions = db
            .transaction(move |conn| {
                Ok((
                    super::super::Db::discard_unreferenced_media_attachment_conn(
                        conn,
                        &request(in_use, 1, 2),
                        3,
                    )?,
                    super::super::Db::discard_unreferenced_media_attachment_conn(
                        conn,
                        &request(overflow, u64::MAX, 1),
                        3,
                    )?,
                    super::super::Db::discard_unreferenced_media_attachment_conn(
                        conn,
                        &request(applied, 1, 1),
                        3,
                    )?,
                ))
            })
            .await
            .unwrap();
        assert_eq!(
            decisions.0.reason,
            MediaDiscardReasonV1::MediaAttachmentInUse
        );
        assert_eq!(
            decisions.1.reason,
            MediaDiscardReasonV1::AvailabilityGenerationOverflow
        );
        assert_eq!(decisions.2.reason, MediaDiscardReasonV1::DiscardStarted);
        assert_eq!(decisions.2.availability_generation_after, 2);
        let counts=db.read(move|conn|Ok((conn.query_row("SELECT COUNT(*) FROM media_attachment_cleanup_intents WHERE attachment_id=?1",[applied.to_string()],|row|row.get::<_,i64>(0))?,conn.query_row("SELECT COUNT(*) FROM media_attachment_cleanup_intents WHERE attachment_id IN (?1,?2)",params![in_use.to_string(),overflow.to_string()],|row|row.get::<_,i64>(0))?))).await.unwrap();
        assert_eq!(counts, (1, 0));
        let fresh = db
            .transaction(move |conn| {
                assert_eq!(
                    super::super::Db::release_media_reference_conn(conn, reference_id, 2, 4)?,
                    3
                );
                super::super::Db::discard_unreferenced_media_attachment_conn(
                    conn,
                    &DiscardUnreferencedMediaAttachmentV1 {
                        schema_version: 1,
                        kind: "discardUnreferencedMediaAttachment".into(),
                        attachment_id: in_use,
                        attachment_version: 1,
                        availability_generation: 1,
                        reference_generation: 3,
                        origin_upload: None,
                    },
                    5,
                )
            })
            .await
            .unwrap();
        assert_eq!(fresh.reason, MediaDiscardReasonV1::DiscardStarted);
        assert_eq!(
            (
                fresh.reference_generation_before,
                fresh.reference_generation_after
            ),
            (3, 3)
        );
    }
}
