//! Private held-handle storage recovery for security-blocked media.
//!
//! Transport callers cannot mint a proof. The snapshot, every no-follow open,
//! full read, post-read identity check, and reducer commit run inside one DB
//! writer transaction while all verified file handles remain live.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use anyhow::{Context, Result, ensure};
use cockpit_db::media_attachments::{
    LocalMediaOwnerReceiptV1, LocalPathRegistrationReceiptV1, LocalPathRegistrationResultV1,
    MediaAttachmentRecord, MediaAvailability, MediaKind,
    MediaSecurityRecoveryComponentTransitionV1, MediaSecurityRecoveryDisposition,
    MediaSecurityRecoveryOutcome, MediaSourceKind, RecoverSecurityBlockedMediaV1,
    RegisterLocalPathMediaV1, RequestedLocalPathMediaKind, SecurityRecoverySnapshot,
    SecurityRecoverySnapshotResult,
};
use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::external_journal::fsguard::DirGuard;

/// A borrowed source already opened by the local-path authority boundary.
/// Recovery never derives or reopens a caller path.
pub(crate) struct BorrowedSourceHandle {
    pub(crate) file: File,
    pub(crate) evidence_digest: String,
}

struct HeldHandleRecoveryProof {
    _handles: Vec<File>,
}

#[derive(Clone)]
pub(crate) struct MediaStorageRecovery {
    db: cockpit_db::Db,
    owned_root: std::sync::Arc<DirGuard>,
    borrowed_sources:
        std::sync::Arc<std::sync::Mutex<std::collections::HashMap<Uuid, BorrowedSourceHandle>>>,
}

impl MediaStorageRecovery {
    /// Reconcile durable upload rows against the held storage root before the
    /// daemon accepts upload traffic. Appends may have reached the file but
    /// not SQLite, so a longer temporary is safely truncated to the durable
    /// offset. Missing/short temporaries fail closed; expired drafts are
    /// securely removed and release their reservation in the same commit.
    pub(crate) async fn reconcile_media_uploads(&self, now_unix_ms: i64) -> Result<usize> {
        use cockpit_db::media_attachments::{
            MediaUploadLastTransitionV1, MediaUploadSystemActionV1, RemoteMediaOperationOutcomeV1,
        };
        let publication_intents=self.db.read(|conn|{let mut statement=conn.prepare("SELECT upload_id,temporary_storage_id,quarantine_storage_id,derivative_storage_ids_json FROM media_storage_publication_intents ORDER BY created_at_unix_ms,upload_id")?;let rows=statement.query_map([],|row|Ok((row.get::<_,String>(0)?,row.get::<_,String>(1)?,row.get::<_,String>(2)?,row.get::<_,String>(3)?)))?;rows.collect::<std::result::Result<Vec<_>,_>>().map_err(Into::into)}).await?;
        let mut repaired = 0usize;
        for (upload_id, temporary, quarantine, derivative_json) in publication_intents {
            let derivatives: Vec<String> = serde_json::from_str(&derivative_json)?;
            for derivative in derivatives {
                if let Ok(file) = self.owned_root.open_file_verified(&derivative) {
                    self.owned_root
                        .remove_file(&derivative)
                        .map_err(anyhow::Error::new)?;
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::MetadataExt as _;
                        ensure!(
                            file.metadata()?.nlink() == 0,
                            "orphan derivative was not deleted"
                        );
                    }
                }
            }
            let temporary_exists = self.owned_root.open_file_verified(&temporary).is_ok();
            if self.owned_root.open_file_verified(&quarantine).is_ok() {
                ensure!(
                    !temporary_exists,
                    "publication intent has both temporary and quarantine objects"
                );
                self.owned_root
                    .rename_into_noreplace(&quarantine, &self.owned_root, &temporary)
                    .map_err(anyhow::Error::new)?;
                self.owned_root.sync().map_err(anyhow::Error::new)?;
            }
            self.db
                .transaction(move |conn| {
                    conn.execute(
                        "DELETE FROM media_storage_publication_intents WHERE upload_id=?1",
                        [upload_id],
                    )?;
                    Ok(())
                })
                .await?;
            repaired += 1;
        }
        let rows = self.db.read(|conn| {
            let mut statement = conn.prepare("SELECT upload_id,temporary_storage_id,acknowledged_bytes,upload_generation,expires_at_unix_ms,reservation_id,state,terminal_reason FROM media_uploads WHERE state IN ('open','finalizing') ORDER BY creation_sequence")?;
            let rows = statement.query_map([], |row| Ok((row.get::<_,String>(0)?,row.get::<_,String>(1)?,row.get::<_,String>(2)?,row.get::<_,String>(3)?,row.get::<_,i64>(4)?,row.get::<_,String>(5)?,row.get::<_,String>(6)?,row.get::<_,Option<String>>(7)?)))?;
            rows.collect::<std::result::Result<Vec<_>, _>>().map_err(Into::into)
        }).await?;
        for (
            upload_id,
            storage_id,
            acknowledged,
            generation,
            expires,
            reservation_id,
            state,
            terminal_reason,
        ) in rows
        {
            let acknowledged = acknowledged.parse::<u64>()?;
            let generation = generation.parse::<u64>()?;
            if state == "finalizing" {
                let target = match terminal_reason.as_deref() {
                    Some("client_cancelled") => "cancelled",
                    Some("draft_expired") => "expired",
                    _ => anyhow::bail!("invalid upload cleanup intent"),
                };
                if let Ok(file) = self.owned_root.open_file_verified(&storage_id) {
                    self.owned_root
                        .remove_file(&storage_id)
                        .map_err(anyhow::Error::new)?;
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::MetadataExt as _;
                        ensure!(
                            file.metadata()?.nlink() == 0,
                            "intended upload temporary was not deleted"
                        );
                    }
                }
                let upload = upload_id.clone();
                let reservation = reservation_id.clone();
                self.db.transaction(move|conn|{let next=generation.checked_add(1).context("upload generation overflow")?;let changed=conn.execute("UPDATE media_uploads SET state=?1,upload_generation=?2,next_chunk_index=NULL,updated_at_unix_ms=?3 WHERE upload_id=?4 AND upload_generation=?5 AND state='finalizing'",params![target,next.to_string(),now_unix_ms,upload,generation.to_string()])?;ensure!(changed==1,"upload cleanup intent lost compare-and-swap");crate::media_reservation::cancel_reserved_media_conn(conn,&reservation,u64::try_from(now_unix_ms)?)?;Ok(())}).await?;
                repaired += 1;
                continue;
            }
            let opened = self.owned_root.open_file_verified(&storage_id);
            let mut file = match opened {
                Ok(file) => file,
                Err(_) => {
                    let transition = MediaUploadLastTransitionV1::System {
                        action: MediaUploadSystemActionV1::StartupReconcile,
                        outcome: RemoteMediaOperationOutcomeV1::Applied,
                    };
                    self.commit_upload_reconcile(
                        upload_id,
                        generation,
                        reservation_id,
                        "failed",
                        "storage_failure",
                        None,
                        transition,
                        now_unix_ms,
                    )
                    .await?;
                    repaired += 1;
                    continue;
                }
            };
            let length = file.metadata()?.len();
            if length < acknowledged {
                let transition = MediaUploadLastTransitionV1::System {
                    action: MediaUploadSystemActionV1::StartupReconcile,
                    outcome: RemoteMediaOperationOutcomeV1::Applied,
                };
                self.commit_upload_reconcile(
                    upload_id,
                    generation,
                    reservation_id,
                    "failed",
                    "storage_failure",
                    None,
                    transition,
                    now_unix_ms,
                )
                .await?;
                repaired += 1;
                continue;
            }
            if length > acknowledged {
                file.set_len(acknowledged)?;
                file.sync_all()?;
                repaired += 1;
            }
            if expires > now_unix_ms {
                continue;
            }
            let identity = stable_identity_digest(&file)?;
            let (_, checksum) = read_full_digest(&mut file)?;
            let evidence = crate::intel::hex_lower(&Sha256::digest(
                format!("media-upload-expire-v1\0{identity}\0{acknowledged}\0{checksum}")
                    .as_bytes(),
            ));
            let transition = MediaUploadLastTransitionV1::System {
                action: MediaUploadSystemActionV1::Expire,
                outcome: RemoteMediaOperationOutcomeV1::Applied,
            };
            let intent_upload = upload_id.clone();
            let intent_transition = serde_json::to_string(&transition)?;
            let intent_evidence = evidence.clone();
            self.db.transaction(move |conn| {
                let changed = conn.execute("UPDATE media_uploads SET state='finalizing',terminal_reason='draft_expired',cleanup_evidence_digest=?1,last_transition_json=?2,updated_at_unix_ms=?3 WHERE upload_id=?4 AND upload_generation=?5 AND state='open'",params![intent_evidence,intent_transition,now_unix_ms,intent_upload,generation.to_string()])?;
                ensure!(changed == 1, "upload expiry intent lost compare-and-swap");
                Ok(())
            }).await?;
            self.owned_root
                .remove_file(&storage_id)
                .map_err(anyhow::Error::new)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt as _;
                ensure!(
                    file.metadata()?.nlink() == 0,
                    "expired upload temporary was not deleted"
                );
            }
            self.commit_upload_reconcile(
                upload_id,
                generation,
                reservation_id,
                "expired",
                "draft_expired",
                Some(evidence),
                transition,
                now_unix_ms,
            )
            .await?;
            repaired += 1;
        }
        Ok(repaired)
    }

    async fn commit_upload_reconcile(
        &self,
        upload_id: String,
        generation: u64,
        reservation_id: String,
        state: &'static str,
        reason: &'static str,
        evidence: Option<String>,
        transition: cockpit_db::media_attachments::MediaUploadLastTransitionV1,
        now_unix_ms: i64,
    ) -> Result<()> {
        self.db.transaction(move |conn| {
            let next = generation.checked_add(1).context("upload generation overflow")?;
            let changed = conn.execute(
                "UPDATE media_uploads SET state=?1,upload_generation=?2,next_chunk_index=NULL,terminal_reason=?3,cleanup_evidence_digest=?4,last_transition_json=?5,updated_at_unix_ms=?6 WHERE upload_id=?7 AND upload_generation=?8 AND state IN ('open','finalizing')",
                params![state,next.to_string(),reason,evidence,serde_json::to_string(&transition)?,now_unix_ms,upload_id,generation.to_string()],
            )?;
            ensure!(changed == 1, "upload reconcile lost compare-and-swap");
            crate::media_reservation::cancel_reserved_media_conn(conn, &reservation_id, u64::try_from(now_unix_ms)?)?;
            Ok(())
        }).await
    }

    pub(crate) async fn finalize_media_upload(
        &self,
        request: cockpit_db::media_attachments::FinalizeMediaUploadV1,
        now_unix_ms: i64,
    ) -> Result<cockpit_db::media_attachments::LocalMediaMutationReceiptV1> {
        use cockpit_db::media_attachments::{
            LocalMediaMutationOutcomeV1, LocalMediaMutationPayloadV1, LocalMediaMutationReceiptV1,
            LocalMediaMutationTransitionV1, LocalMediaSubjectKindV1, MediaAttachmentComponent,
            MediaAttachmentRecord, MediaAvailability, MediaKind, MediaSourceKind,
            MediaUploadActionV1, MediaUploadLastTransitionV1, RemoteMediaOperationOutcomeV1,
        };
        cockpit_db::Db::validate_local_media_mutation_v1(&request)?;
        let LocalMediaMutationPayloadV1::Finalize {
            session_id,
            canonical_project_digest,
            client_draft_id,
            upload_id,
            upload_generation,
            chunk_count,
            total_bytes,
            object_sha256,
        } = &request.payload
        else {
            anyhow::bail!("local media action mismatch")
        };
        let session = *session_id;
        let project = canonical_project_digest.clone();
        let draft = *client_draft_id;
        let upload = *upload_id;
        let generation = *upload_generation;
        let chunks = *chunk_count;
        let total = *total_bytes;
        let expected = object_sha256.clone();
        let (request_digest, semantic_digest) =
            cockpit_db::Db::local_media_mutation_digests(&request)?;
        let domain = format!("finalize:{session}:{project}:{draft}:{upload}:{generation}");
        let op = request.local_operation_id;
        let pre_domain = domain.clone();
        let pre_request = request_digest.clone();
        let pre_semantic = semantic_digest.clone();
        if let Some(receipt) = self
            .db
            .transaction(move |conn| {
                preflight_local_operation(
                    conn,
                    op,
                    "finalize",
                    &pre_domain,
                    &pre_request,
                    &pre_semantic,
                    now_unix_ms,
                )
            })
            .await?
        {
            return Ok(receipt);
        }
        let query_project = project.clone();
        let snapshot=self.db.read(move|conn|conn.query_row("SELECT temporary_storage_id,acknowledged_bytes,acknowledged_chunks,state,upload_generation,reservation_id,media_kind FROM media_uploads WHERE upload_id=?1 AND session_id=?2 AND canonical_project_digest=?3 AND client_draft_id=?4",params![upload.to_string(),session.to_string(),query_project,draft.to_string()],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,u32>(2)?,r.get::<_,String>(3)?,r.get::<_,String>(4)?,r.get::<_,String>(5)?,r.get::<_,String>(6)?))).optional().map_err(Into::into)).await?.context("media_attachment_unavailable")?;
        ensure!(
            snapshot.3 == "open"
                && snapshot.4.parse::<u64>()? == generation
                && snapshot.2 == chunks
                && snapshot.1.parse::<u64>()? == total,
            "finalize count or length conflict"
        );
        let mut held = self
            .owned_root
            .open_file_verified(&snapshot.0)
            .map_err(anyhow::Error::new)?;
        let before = stable_identity_digest(&held)?;
        let (actual_len, actual_sha) = read_full_digest(&mut held)?;
        let after = stable_identity_digest(&held)?;
        ensure!(
            before == after && actual_len == total && actual_sha == expected,
            "finalize object checksum mismatch"
        );
        let (canonical_container, canonical_mime) =
            probe_upload_container(&mut held, media_kind_from_text(&snapshot.6)?)?;
        let normalized = if canonical_container == "png" {
            held.seek(SeekFrom::Start(0))?;
            let mut bytes = Vec::new();
            held.by_ref()
                .take(10 * 1024 * 1024 + 1)
                .read_to_end(&mut bytes)?;
            ensure!(bytes.len() <= 10 * 1024 * 1024, "resource_limit");
            Some(normalize_png_image(&bytes)?)
        } else {
            None
        };
        let storage_id = Uuid::now_v7();
        let target = storage_id.to_string();
        let planned_derivatives = normalized
            .map(|normalized| {
                vec![
                    (
                        "image_model",
                        Uuid::now_v7(),
                        normalized.model_png,
                        normalized.width,
                        normalized.height,
                    ),
                    (
                        "browser_thumbnail",
                        Uuid::now_v7(),
                        normalized.thumbnail_png,
                        normalized.thumbnail_width,
                        normalized.thumbnail_height,
                    ),
                ]
            })
            .unwrap_or_default();
        let intent_upload = upload.to_string();
        let intent_temporary = snapshot.0.clone();
        let intent_target = target.clone();
        let intent_derivatives = serde_json::to_string(
            &planned_derivatives
                .iter()
                .map(|(_, id, _, _, _)| id.to_string())
                .collect::<Vec<_>>(),
        )?;
        self.db.transaction(move|conn|{conn.execute("INSERT INTO media_storage_publication_intents(upload_id,temporary_storage_id,quarantine_storage_id,derivative_storage_ids_json,created_at_unix_ms) VALUES(?1,?2,?3,?4,?5)",params![intent_upload,intent_temporary,intent_target,intent_derivatives,now_unix_ms])?;Ok(())}).await?;
        self.owned_root
            .rename_into_noreplace(&snapshot.0, &self.owned_root, &target)
            .map_err(anyhow::Error::new)?;
        self.owned_root.sync().map_err(anyhow::Error::new)?;
        let reopened = self
            .owned_root
            .open_file_verified(&target)
            .map_err(anyhow::Error::new)?;
        ensure!(
            stable_identity_digest(&reopened)? == before,
            "quarantine rename identity mismatch"
        );
        drop(reopened);
        let mut derivative_files = Vec::new();
        let mut derivative_components = Vec::new();
        if !planned_derivatives.is_empty() {
            let publication = (|| -> Result<()> {
                for (kind, derivative_storage, bytes, width, height) in planned_derivatives {
                    let derivative_name = derivative_storage.to_string();
                    let mut derivative = self
                        .owned_root
                        .create_file_exclusive(&derivative_name)
                        .map_err(anyhow::Error::new)?;
                    derivative.write_all(&bytes)?;
                    derivative.sync_all()?;
                    let identity = stable_identity_digest(&derivative)?;
                    let (persisted_length, checksum) = read_full_digest(&mut derivative)?;
                    ensure!(
                        persisted_length == bytes.len() as u64,
                        "derivative write length mismatch"
                    );
                    ensure!(
                        checksum == crate::intel::hex_lower(&Sha256::digest(&bytes)),
                        "derivative write checksum mismatch"
                    );
                    ensure!(
                        identity == stable_identity_digest(&derivative)?,
                        "derivative identity changed after write"
                    );
                    derivative_files.push(derivative_name);
                    derivative_components.push((
                        kind.to_string(),
                        derivative_storage,
                        identity,
                        persisted_length,
                        checksum,
                        width,
                        height,
                    ));
                }
                self.owned_root.sync().map_err(anyhow::Error::new)?;
                Ok(())
            })();
            if let Err(error) = publication {
                for derivative in derivative_files {
                    let _ = self.owned_root.remove_file(&derivative);
                }
                self.owned_root
                    .rename_into_noreplace(&target, &self.owned_root, &snapshot.0)
                    .map_err(anyhow::Error::new)?;
                self.owned_root.sync().map_err(anyhow::Error::new)?;
                let cleanup_upload = upload.to_string();
                self.db
                    .transaction(move |conn| {
                        conn.execute(
                            "DELETE FROM media_storage_publication_intents WHERE upload_id=?1",
                            [cleanup_upload],
                        )?;
                        Ok(())
                    })
                    .await?;
                return Err(error);
            }
        }
        let attachment = Uuid::now_v7();
        let component = Uuid::now_v7();
        let media_kind = media_kind_from_text(&snapshot.6)?;
        let next = generation
            .checked_add(1)
            .context("upload generation overflow")?;
        let expires = now_unix_ms
            .checked_add(86_400_000)
            .context("draft expiry overflow")?;
        let mutation = request;
        let transition = MediaUploadLastTransitionV1::Local {
            action: MediaUploadActionV1::Finalize,
            local_operation_id: mutation.local_operation_id,
            outcome: RemoteMediaOperationOutcomeV1::Applied,
        };
        let record = MediaAttachmentRecord {
            attachment_id: attachment,
            session_id: session,
            canonical_project_digest: project.clone(),
            media_kind,
            source_kind: MediaSourceKind::AuthenticatedSessionUpload,
            canonical_container: canonical_container.into(),
            canonical_mime: canonical_mime.into(),
            availability: MediaAvailability::Quarantined,
            attachment_version: 1,
            availability_generation: 1,
            reference_generation: 1,
            captured_capability_generation: 1,
            source_identity_digest: before.clone(),
            source_byte_length: total,
            source_sha256: actual_sha.clone(),
            selected_video_stream: None,
            selected_audio_stream: None,
            created_at_unix_ms: now_unix_ms,
            updated_at_unix_ms: now_unix_ms,
            draft_expires_at_unix_ms: Some(expires),
            first_referenced_at_unix_ms: None,
        };
        let component_record = MediaAttachmentComponent {
            component_id: component,
            attachment_id: attachment,
            attachment_version: 1,
            component_kind: "quarantined_original".into(),
            storage_id,
            lifecycle_state: "ready".into(),
            component_generation: 1,
            stable_identity_digest: before,
            byte_length: total,
            sha256: actual_sha,
            reservation_id: snapshot.5.clone(),
            created_at_unix_ms: now_unix_ms,
            updated_at_unix_ms: now_unix_ms,
        };
        let ready = !derivative_components.is_empty();
        let reservation_id = snapshot.5.clone();
        let transition_operation_id = mutation.local_operation_id;
        let result=self.db.transaction(move|conn|{if let Some(receipt)=preflight_local_operation(conn,mutation.local_operation_id,"finalize",&domain,&request_digest,&semantic_digest,now_unix_ms)?{return Ok((receipt,false))}cockpit_db::Db::insert_media_attachment_conn(conn,&record)?;cockpit_db::Db::insert_media_attachment_component_conn(conn,&component_record)?;if ready {for (kind,storage,identity,length,checksum,width,height) in derivative_components {let id=Uuid::now_v7();let component=MediaAttachmentComponent{component_id:id,attachment_id:attachment,attachment_version:1,component_kind:kind,storage_id:storage,lifecycle_state:"ready".into(),component_generation:1,stable_identity_digest:identity,byte_length:length,sha256:checksum,reservation_id:reservation_id.clone(),created_at_unix_ms:now_unix_ms,updated_at_unix_ms:now_unix_ms};cockpit_db::Db::insert_media_attachment_component_conn(conn,&component)?;conn.execute("INSERT INTO media_image_component_dimensions(component_id,width,height) VALUES(?1,?2,?3)",params![id.to_string(),width,height])?;}let mut availability=MediaAvailability::Quarantined;let mut available_generation=1;for next_state in [MediaAvailability::Probing,MediaAvailability::Decoding,MediaAvailability::Normalizing,MediaAvailability::Ready]{cockpit_db::Db::transition_media_attachment_conn(conn,attachment,1,available_generation,next_state,now_unix_ms)?;let next_generation=available_generation.checked_add(1).context("availability generation overflow")?;conn.execute("INSERT INTO media_attachment_transition_evidence(attachment_id,availability_generation,from_state,to_state,operation_id,committed_at_unix_ms) VALUES(?1,?2,?3,?4,?5,?6)",params![attachment.to_string(),next_generation.to_string(),availability.as_str(),next_state.as_str(),transition_operation_id.to_string(),now_unix_ms])?;availability=next_state;available_generation=next_generation;}ensure!(availability==MediaAvailability::Ready,"image readiness transition failed");}conn.execute("INSERT INTO media_attachment_upload_origins(attachment_id,client_draft_id,upload_id,upload_generation) VALUES(?1,?2,?3,?4)",params![attachment.to_string(),draft.to_string(),upload.to_string(),next.to_string()])?;let changed=conn.execute("UPDATE media_uploads SET state='materialized',upload_generation=?1,next_chunk_index=NULL,attachment_id=?2,attachment_version='1',last_transition_json=?3,updated_at_unix_ms=?4 WHERE upload_id=?5 AND upload_generation=?6 AND state='open'",params![next.to_string(),attachment.to_string(),serde_json::to_string(&transition)?,now_unix_ms,upload.to_string(),generation.to_string()])?;ensure!(changed==1,"upload finalize lost compare-and-swap");let receipt=LocalMediaMutationReceiptV1{schema_version:1,kind:"localMediaMutationReceipt".into(),receipt_id:Uuid::now_v7(),local_operation_id:mutation.local_operation_id,actor_principal_digest:mutation.actor_principal_digest,action:"finalize".into(),subject_kind:LocalMediaSubjectKindV1::Upload,subject_id:upload,operation_request_digest:request_digest.clone(),semantic_command_digest:semantic_digest.clone(),outcome:LocalMediaMutationOutcomeV1::Applied,transition:LocalMediaMutationTransitionV1::UploadToAttachment{upload_generation_before:generation,upload_generation_after:next,attachment_version:1,availability_generation:if ready{5}else{1},reference_generation:1},discard_result:None,discard_result_digest:None,committed_at_unix_ms:now_unix_ms};commit_local_operation(conn,&receipt,"finalize",&domain,&request_digest,&semantic_digest,now_unix_ms)?;Ok((receipt,true))}).await;
        if result.as_ref().is_err() || result.as_ref().is_ok_and(|(_, applied)| !*applied) {
            self.owned_root
                .rename_into_noreplace(&target, &self.owned_root, &snapshot.0)
                .map_err(anyhow::Error::new)?;
            self.owned_root.sync().map_err(anyhow::Error::new)?;
            for derivative in derivative_files {
                let _ = self.owned_root.remove_file(&derivative);
            }
            let cleanup_upload = upload.to_string();
            self.db
                .transaction(move |conn| {
                    conn.execute(
                        "DELETE FROM media_storage_publication_intents WHERE upload_id=?1",
                        [cleanup_upload],
                    )?;
                    Ok(())
                })
                .await?;
        }
        result.map(|(receipt, _)| receipt)
    }
    pub(crate) async fn cancel_media_upload(
        &self,
        request: cockpit_db::media_attachments::CancelMediaUploadV1,
        now_unix_ms: i64,
    ) -> Result<cockpit_db::media_attachments::LocalMediaMutationReceiptV1> {
        use cockpit_db::media_attachments::{
            LocalMediaMutationOutcomeV1, LocalMediaMutationPayloadV1, LocalMediaMutationReceiptV1,
            LocalMediaMutationTransitionV1, LocalMediaSubjectKindV1, MediaUploadActionV1,
            MediaUploadLastTransitionV1, RemoteMediaOperationOutcomeV1,
        };
        cockpit_db::Db::validate_local_media_mutation_v1(&request)?;
        let LocalMediaMutationPayloadV1::Cancel {
            session_id,
            canonical_project_digest,
            client_draft_id,
            upload_id,
            upload_generation,
        } = &request.payload
        else {
            anyhow::bail!("local media action mismatch")
        };
        let session = *session_id;
        let project = canonical_project_digest.clone();
        let draft = *client_draft_id;
        let upload = *upload_id;
        let generation = *upload_generation;
        let (request_digest, semantic_digest) =
            cockpit_db::Db::local_media_mutation_digests(&request)?;
        let domain = format!("cancel:{session}:{project}:{draft}:{upload}:{generation}");
        let op = request.local_operation_id;
        let pre_domain = domain.clone();
        let pre_request = request_digest.clone();
        let pre_semantic = semantic_digest.clone();
        if let Some(receipt) = self
            .db
            .transaction(move |conn| {
                preflight_local_operation(
                    conn,
                    op,
                    "cancel",
                    &pre_domain,
                    &pre_request,
                    &pre_semantic,
                    now_unix_ms,
                )
            })
            .await?
        {
            let replay_upload = upload.to_string();
            let pending = self
                .db
                .read(move |conn| {
                    Ok(conn
                        .query_row(
                            "SELECT state='finalizing' FROM media_uploads WHERE upload_id=?1",
                            [replay_upload],
                            |row| row.get::<_, bool>(0),
                        )
                        .optional()?
                        .unwrap_or(false))
                })
                .await?;
            if pending {
                self.reconcile_media_uploads(now_unix_ms).await?;
            }
            return Ok(receipt);
        }
        let snapshot=self.db.read(move|conn|conn.query_row("SELECT temporary_storage_id,acknowledged_bytes,state,upload_generation,reservation_id FROM media_uploads WHERE upload_id=?1 AND session_id=?2 AND canonical_project_digest=?3 AND client_draft_id=?4",params![upload.to_string(),session.to_string(),project,draft.to_string()],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?,r.get::<_,String>(3)?,r.get::<_,String>(4)?))).optional().map_err(Into::into)).await?.context("media_attachment_unavailable")?;
        ensure!(
            snapshot.2 == "open" && snapshot.3.parse::<u64>()? == generation,
            "upload generation conflict"
        );
        let mut file = self
            .owned_root
            .open_file_verified(&snapshot.0)
            .map_err(anyhow::Error::new)?;
        let (length, checksum) = read_full_digest(&mut file)?;
        ensure!(
            length == snapshot.1.parse::<u64>()?,
            "upload temporary length mismatch"
        );
        let identity = stable_identity_digest(&file)?;
        let evidence = crate::intel::hex_lower(&Sha256::digest(
            format!("media-upload-delete-v1\0{identity}\0{length}\0{checksum}").as_bytes(),
        ));
        let mutation = request;
        let transition = MediaUploadLastTransitionV1::Local {
            action: MediaUploadActionV1::Cancel,
            local_operation_id: mutation.local_operation_id,
            outcome: RemoteMediaOperationOutcomeV1::Applied,
        };
        let next = generation
            .checked_add(1)
            .context("upload generation overflow")?;
        let receipt = LocalMediaMutationReceiptV1 {
            schema_version: 1,
            kind: "localMediaMutationReceipt".into(),
            receipt_id: Uuid::now_v7(),
            local_operation_id: mutation.local_operation_id,
            actor_principal_digest: mutation.actor_principal_digest,
            action: "cancel".into(),
            subject_kind: LocalMediaSubjectKindV1::Upload,
            subject_id: upload,
            operation_request_digest: request_digest.clone(),
            semantic_command_digest: semantic_digest.clone(),
            outcome: LocalMediaMutationOutcomeV1::Applied,
            transition: LocalMediaMutationTransitionV1::Upload {
                generation_before: generation,
                generation_after: next,
            },
            discard_result: None,
            discard_result_digest: None,
            committed_at_unix_ms: now_unix_ms,
        };
        let intent_receipt = receipt.clone();
        let intent_transition = serde_json::to_string(&transition)?;
        let intent_evidence = evidence.clone();
        self.db.transaction(move|conn|{if let Some(replay)=preflight_local_operation(conn,mutation.local_operation_id,"cancel",&domain,&request_digest,&semantic_digest,now_unix_ms)?{return Ok(replay)}let changed=conn.execute("UPDATE media_uploads SET state='finalizing',terminal_reason='client_cancelled',cleanup_evidence_digest=?1,last_transition_json=?2,updated_at_unix_ms=?3 WHERE upload_id=?4 AND upload_generation=?5 AND state='open'",params![intent_evidence,intent_transition,now_unix_ms,upload.to_string(),generation.to_string()])?;ensure!(changed==1,"upload cancel intent lost compare-and-swap");commit_local_operation(conn,&intent_receipt,"cancel",&domain,&request_digest,&semantic_digest,now_unix_ms)?;Ok(intent_receipt)}).await?;
        self.owned_root
            .remove_file(&snapshot.0)
            .map_err(anyhow::Error::new)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            ensure!(
                file.metadata()?.nlink() == 0,
                "held upload temporary was not deleted"
            );
        }
        let reservation = snapshot.4;
        self.db.transaction(move|conn|{let changed=conn.execute("UPDATE media_uploads SET state='cancelled',upload_generation=?1,next_chunk_index=NULL,updated_at_unix_ms=?2 WHERE upload_id=?3 AND upload_generation=?4 AND state='finalizing' AND terminal_reason='client_cancelled'",params![next.to_string(),now_unix_ms,upload.to_string(),generation.to_string()])?;ensure!(changed==1,"upload cancel completion lost compare-and-swap");crate::media_reservation::cancel_reserved_media_conn(conn,&reservation,u64::try_from(now_unix_ms)?)?;Ok(())}).await?;
        Ok(receipt)
    }
    pub(crate) async fn append_media_upload_chunk(
        &self,
        request: cockpit_db::media_attachments::AppendMediaUploadChunkV1,
        now_unix_ms: i64,
    ) -> Result<cockpit_db::media_attachments::LocalMediaMutationReceiptV1> {
        use base64::Engine as _;
        use cockpit_db::media_attachments::{
            LocalMediaMutationOutcomeV1, LocalMediaMutationPayloadV1, LocalMediaMutationReceiptV1,
            LocalMediaMutationTransitionV1, LocalMediaSubjectKindV1, MediaUploadActionV1,
            MediaUploadLastTransitionV1, RemoteMediaOperationOutcomeV1,
        };
        cockpit_db::Db::validate_local_media_mutation_v1(&request.mutation)?;
        let LocalMediaMutationPayloadV1::Append {
            session_id,
            canonical_project_digest,
            client_draft_id,
            upload_id,
            upload_generation,
            chunk_index,
            chunk_length,
            chunk_sha256,
        } = &request.mutation.payload
        else {
            anyhow::bail!("local media action mismatch")
        };
        let session_id = *session_id;
        let project = canonical_project_digest.clone();
        let draft = *client_draft_id;
        let upload_id = *upload_id;
        let generation = *upload_generation;
        let index = *chunk_index;
        let length = *chunk_length;
        let checksum = chunk_sha256.clone();
        let (request_digest, semantic_digest) =
            cockpit_db::Db::local_media_mutation_digests(&request.mutation)?;
        let domain =
            format!("append:{session_id}:{project}:{draft}:{upload_id}:{generation}:{index}");
        let bytes = base64::engine::general_purpose::STANDARD.decode(&request.data_base64)?;
        ensure!(
            bytes.len() == usize::try_from(length)?
                && crate::intel::hex_lower(&Sha256::digest(&bytes)) == checksum,
            "chunk bytes do not match binding"
        );
        let op = request.mutation.local_operation_id;
        let binding = request_digest.clone();
        let semantic = semantic_digest.clone();
        let domain_pre = domain.clone();
        if let Some(receipt) = self
            .db
            .transaction(move |conn| {
                preflight_local_operation(
                    conn,
                    op,
                    "append",
                    &domain_pre,
                    &binding,
                    &semantic,
                    now_unix_ms,
                )
            })
            .await?
        {
            return Ok(receipt);
        }
        let snapshot=self.db.read(move|conn|{conn.query_row("SELECT temporary_storage_id,acknowledged_bytes,next_chunk_index,state,upload_generation,declared_total_bytes FROM media_uploads WHERE upload_id=?1 AND session_id=?2 AND canonical_project_digest=?3 AND client_draft_id=?4",params![upload_id.to_string(),session_id.to_string(),project,draft.to_string()],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,u32>(2)?,r.get::<_,String>(3)?,r.get::<_,String>(4)?,r.get::<_,String>(5)?))).optional().map_err(Into::into)}).await?.context("media_attachment_unavailable")?;
        ensure!(
            snapshot.3 == "open" && snapshot.4.parse::<u64>()? == generation && snapshot.2 == index,
            "upload generation or chunk index conflict"
        );
        let offset = snapshot.1.parse::<u64>()?;
        let declared = snapshot.5.parse::<u64>()?;
        let after = offset
            .checked_add(u64::from(length))
            .context("upload length overflow")?;
        ensure!(after <= declared, "declared upload length exceeded");
        let mut file = self
            .owned_root
            .open_file_verified(&snapshot.0)
            .map_err(anyhow::Error::new)?;
        ensure!(
            file.metadata()?.len() == offset,
            "upload temporary differs from durable offset"
        );
        file.seek(SeekFrom::End(0))?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        let mutation = request.mutation;
        let transition = MediaUploadLastTransitionV1::Local {
            action: MediaUploadActionV1::Append,
            local_operation_id: mutation.local_operation_id,
            outcome: RemoteMediaOperationOutcomeV1::Applied,
        };
        let result=self.db.transaction(move|conn|{if let Some(receipt)=preflight_local_operation(conn,mutation.local_operation_id,"append",&domain,&request_digest,&semantic_digest,now_unix_ms)?{return Ok((receipt,false))}let next=generation.checked_add(1).context("upload generation overflow")?;let changed=conn.execute("UPDATE media_uploads SET upload_generation=?1,acknowledged_chunks=acknowledged_chunks+1,acknowledged_bytes=?2,next_chunk_index=?3,last_transition_json=?4,updated_at_unix_ms=?5 WHERE upload_id=?6 AND upload_generation=?7 AND next_chunk_index=?8 AND acknowledged_bytes=?9 AND state='open'",params![next.to_string(),after.to_string(),index.checked_add(1).context("chunk index overflow")?,serde_json::to_string(&transition)?,now_unix_ms,upload_id.to_string(),generation.to_string(),index,offset.to_string()])?;ensure!(changed==1,"upload append lost compare-and-swap");conn.execute("INSERT INTO media_upload_chunks(upload_id,chunk_index,byte_length,sha256,storage_offset,acknowledged_at_unix_ms) VALUES(?1,?2,?3,?4,?5,?6)",params![upload_id.to_string(),index,length,checksum,offset.to_string(),now_unix_ms])?;let receipt=LocalMediaMutationReceiptV1{schema_version:1,kind:"localMediaMutationReceipt".into(),receipt_id:Uuid::now_v7(),local_operation_id:mutation.local_operation_id,actor_principal_digest:mutation.actor_principal_digest,action:"append".into(),subject_kind:LocalMediaSubjectKindV1::Upload,subject_id:upload_id,operation_request_digest:request_digest.clone(),semantic_command_digest:semantic_digest.clone(),outcome:LocalMediaMutationOutcomeV1::Applied,transition:LocalMediaMutationTransitionV1::Upload{generation_before:generation,generation_after:next},discard_result:None,discard_result_digest:None,committed_at_unix_ms:now_unix_ms};commit_local_operation(conn,&receipt,"append",&domain,&request_digest,&semantic_digest,now_unix_ms)?;Ok((receipt,true))}).await;
        if result.as_ref().is_err() || result.as_ref().is_ok_and(|(_, applied)| !*applied) {
            file.set_len(offset)?;
            file.sync_all()?
        }
        result.map(|(receipt, _)| receipt)
    }
    pub(crate) async fn begin_media_upload(
        &self,
        request: cockpit_db::media_attachments::BeginMediaUploadV1,
        policy: &cockpit_config::config::media_budget::MediaResourcePolicy,
        monotonic_now_ms: u64,
        now_unix_ms: i64,
    ) -> Result<cockpit_db::media_attachments::LocalMediaMutationReceiptV1> {
        use cockpit_db::media_attachments::{
            LocalMediaMutationOutcomeV1, LocalMediaMutationPayloadV1, LocalMediaMutationReceiptV1,
            LocalMediaMutationTransitionV1, LocalMediaSubjectKindV1, MediaUploadActionV1,
            MediaUploadLastTransitionV1, RemoteMediaOperationOutcomeV1,
        };
        cockpit_db::Db::validate_local_media_mutation_v1(&request)?;
        let LocalMediaMutationPayloadV1::Begin {
            session_id,
            canonical_project_digest,
            client_draft_id,
            media_kind,
            declared_total_bytes,
            reservation_digest,
        } = &request.payload
        else {
            anyhow::bail!("local media action mismatch")
        };
        let session_id = *session_id;
        let canonical_project_digest = canonical_project_digest.clone();
        let client_draft_id = *client_draft_id;
        let media_kind = *media_kind;
        let declared_total_bytes = *declared_total_bytes;
        let reservation_digest = reservation_digest.clone();
        let (request_digest, semantic_digest) =
            cockpit_db::Db::local_media_mutation_digests(&request)?;
        let operation_id = request.local_operation_id.to_string();
        let binding = request_digest.clone();
        let semantic_preflight = semantic_digest.clone();
        let domain_preflight =
            format!("begin:{session_id}:{canonical_project_digest}:{client_draft_id}");
        let alias_id = request.local_operation_id;
        if let Some(receipt)=self.db.transaction(move|conn|{if let Some((stored,json))=conn.query_row("SELECT operation_request_digest,receipt_json FROM local_media_operations WHERE local_operation_id=?1",[operation_id],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?))).optional()?{ensure!(stored==binding,"local_operation_conflict");return Ok(Some(serde_json::from_str(&json)?))}if let Some((authoritative,stored_semantic,json))=conn.query_row("SELECT authoritative_operation_id,semantic_command_digest,receipt_json FROM local_media_operations WHERE action='begin' AND domain_key=?1 AND is_alias=0",[&domain_preflight],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?))).optional()?{ensure!(stored_semantic==semantic_preflight,"local_domain_conflict");conn.execute("INSERT INTO local_media_operations(local_operation_id,authoritative_operation_id,action,domain_key,operation_request_digest,semantic_command_digest,receipt_json,is_alias,committed_at_unix_ms) VALUES(?1,?2,'begin',?3,?4,?5,?6,1,?7)",params![alias_id.to_string(),authoritative,domain_preflight,binding,semantic_preflight,json,now_unix_ms])?;return Ok(Some(serde_json::from_str(&json)?))}Ok(None)}).await?{return Ok(receipt)}
        let upload_id = Uuid::now_v7();
        let storage_id = Uuid::now_v7();
        let reservation_id = format!("media-upload:{upload_id}");
        let plans = local_path_plans(policy, declared_total_bytes)?;
        let evaluated_digest = digest_json(b"media-upload-reservation-v1", &plans)?;
        ensure!(evaluated_digest == reservation_digest, "resource_limit");
        let file_name = storage_id.to_string();
        let file = self
            .owned_root
            .create_file_exclusive(&file_name)
            .map_err(anyhow::Error::new)?;
        file.sync_all()?;
        drop(file);
        let request_for_tx = request.clone();
        let semantic_for_tx = semantic_digest.clone();
        let request_for_digest = request_digest.clone();
        let result=self.db.transaction(move|conn|{
            if let Some((stored,json))=conn.query_row("SELECT operation_request_digest,receipt_json FROM local_media_operations WHERE local_operation_id=?1",[request_for_tx.local_operation_id.to_string()],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?))).optional()?{ensure!(stored==request_for_digest,"local_operation_conflict");return Ok(serde_json::from_str(&json)?)}
            let domain_key=format!("begin:{session_id}:{canonical_project_digest}:{client_draft_id}");
            if let Some((authoritative,stored_semantic,json))=conn.query_row("SELECT authoritative_operation_id,semantic_command_digest,receipt_json FROM local_media_operations WHERE action='begin' AND domain_key=?1 AND is_alias=0",[&domain_key],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?))).optional()?{ensure!(stored_semantic==semantic_for_tx,"local_domain_conflict");conn.execute("INSERT INTO local_media_operations(local_operation_id,authoritative_operation_id,action,domain_key,operation_request_digest,semantic_command_digest,receipt_json,is_alias,committed_at_unix_ms) VALUES(?1,?2,'begin',?3,?4,?5,?6,1,?7)",params![request_for_tx.local_operation_id.to_string(),authoritative,domain_key,request_for_digest,semantic_for_tx,json,now_unix_ms])?;return Ok(serde_json::from_str(&json)?)}
            crate::media_reservation::reserve_conn(conn,crate::media_reservation::ReserveRequest{reservation_id:reservation_id.clone(),recovery_id:reservation_id.clone(),owner:crate::media_reservation::MediaOwner{project_id:canonical_project_digest.clone(),session_id:session_id.to_string()},operation:"media_upload".into(),purpose:"authenticated_media".into(),plans,wall_ms:u64::try_from(now_unix_ms)?},monotonic_now_ms)?;
            let sequence:i64=conn.query_row("UPDATE media_creation_sequence SET next_value=next_value+1 WHERE singleton=1 RETURNING next_value-1",[],|r|r.get(0))?;let expires=now_unix_ms.checked_add(86_400_000).context("upload expiry overflow")?;
            let transition=MediaUploadLastTransitionV1::Local{action:MediaUploadActionV1::Begin,local_operation_id:request_for_tx.local_operation_id,outcome:RemoteMediaOperationOutcomeV1::Applied};
            conn.execute("INSERT INTO media_uploads(upload_id,session_id,canonical_project_digest,client_draft_id,media_kind,state,upload_generation,declared_total_bytes,acknowledged_chunks,acknowledged_bytes,next_chunk_index,expires_at_unix_ms,reservation_id,reservation_digest,temporary_storage_id,last_transition_json,creation_sequence,created_at_unix_ms,updated_at_unix_ms) VALUES(?1,?2,?3,?4,?5,'open','1',?6,0,'0',0,?7,?8,?9,?10,?11,?12,?13,?13)",params![upload_id.to_string(),session_id.to_string(),canonical_project_digest,client_draft_id.to_string(),serde_json::to_value(media_kind)?.as_str().context("media kind")?,declared_total_bytes.to_string(),expires,reservation_id,evaluated_digest,storage_id.to_string(),serde_json::to_string(&transition)?,sequence,now_unix_ms])?;
            let receipt=LocalMediaMutationReceiptV1{schema_version:1,kind:"localMediaMutationReceipt".into(),receipt_id:Uuid::now_v7(),local_operation_id:request_for_tx.local_operation_id,actor_principal_digest:request_for_tx.actor_principal_digest.clone(),action:"begin".into(),subject_kind:LocalMediaSubjectKindV1::Upload,subject_id:upload_id,operation_request_digest:request_for_digest.clone(),semantic_command_digest:semantic_for_tx.clone(),outcome:LocalMediaMutationOutcomeV1::Applied,transition:LocalMediaMutationTransitionV1::Upload{generation_before:0,generation_after:1},discard_result:None,discard_result_digest:None,committed_at_unix_ms:now_unix_ms};let json=serde_json::to_string(&receipt)?;
            conn.execute("INSERT INTO local_media_operations(local_operation_id,authoritative_operation_id,action,domain_key,operation_request_digest,semantic_command_digest,receipt_json,is_alias,committed_at_unix_ms) VALUES(?1,?1,'begin',?2,?3,?4,?5,0,?6)",params![request_for_tx.local_operation_id.to_string(),domain_key,request_for_digest,semantic_for_tx,json,now_unix_ms])?;conn.execute("INSERT INTO local_media_operation_audit(local_operation_id,outcome,committed_at_unix_ms) VALUES(?1,'applied',?2)",params![request_for_tx.local_operation_id.to_string(),now_unix_ms])?;Ok(receipt)
        }).await;
        if result.as_ref().is_err()
            || result
                .as_ref()
                .is_ok_and(|receipt| receipt.subject_id != upload_id)
        {
            let _ = self.owned_root.remove_file(&file_name);
        }
        result
    }
    pub(crate) async fn register_local_path(
        &self,
        request: RegisterLocalPathMediaV1,
        project_root: &Path,
        policy: &cockpit_config::config::media_budget::MediaResourcePolicy,
        monotonic_now_ms: u64,
        now_unix_ms: i64,
    ) -> Result<LocalPathRegistrationReceiptV1> {
        validate_registration(&request)?;
        let binding_digest = digest_json(b"local-path-binding-v1", &request)?;
        if let Some(receipt) = self.registration_replay(&request, &binding_digest).await? {
            return Ok(receipt);
        }
        let mut source = open_project_source(project_root, &request.path)?;
        let before = source.metadata()?;
        ensure!(
            before.is_file() && before.len() > 0,
            "media_attachment_unavailable"
        );
        let identity = stable_identity_digest(&source)?;
        let mtime_ns = modified_ns(&before)?;
        let mut hasher = Sha256::new();
        std::io::copy(&mut source, &mut hasher)?;
        source.seek(SeekFrom::Start(0))?;
        let sha256 = crate::intel::hex_lower(&hasher.finalize());
        let after = source.metadata()?;
        ensure!(
            before.len() == after.len()
                && identity == stable_identity_digest(&source)?
                && mtime_ns == modified_ns(&after)?,
            "source_changed_during_registration"
        );
        let canonical_path_digest =
            crate::intel::hex_lower(&Sha256::digest(request.path.as_bytes()));
        let authority_digest = crate::intel::hex_lower(&Sha256::digest(
            [
                request.canonical_project_digest.as_bytes(),
                canonical_path_digest.as_bytes(),
            ]
            .concat(),
        ));
        let evidence_digest = crate::intel::hex_lower(&Sha256::digest(format!("local-path-source-evidence-v1\0{canonical_path_digest}\0{identity}\0{}\0{mtime_ns}\0{sha256}", before.len()).as_bytes()));
        let request_digest = crate::intel::hex_lower(&Sha256::digest(
            [
                binding_digest.as_bytes(),
                authority_digest.as_bytes(),
                evidence_digest.as_bytes(),
            ]
            .concat(),
        ));
        let semantic_digest = crate::intel::hex_lower(&Sha256::digest(
            format!(
                "local-path-semantic-v1\0{}\0{}\0{}\0{}\0{}",
                request.session_id,
                request.canonical_project_digest,
                request.client_draft_id,
                serde_json::to_string(&request.requested_media_kind)?,
                evidence_digest
            )
            .as_bytes(),
        ));
        let attachment_id = Uuid::now_v7();
        let receipt_id = Uuid::now_v7();
        let reservation_id = format!("local-path:{attachment_id}");
        let plans = local_path_plans(policy, before.len())?;
        let reservation_digest = digest_json(b"local-path-reservation-v1", &plans)?;
        let held = BorrowedSourceHandle {
            file: source,
            evidence_digest: evidence_digest.clone(),
        };
        let request_for_tx = request.clone();
        let result = self.db.transaction(move |conn| {
            if let Some((stored_binding, receipt_json)) = conn.query_row("SELECT request_binding_digest,receipt_json FROM media_local_path_registration_operations WHERE local_operation_id=?1", [request_for_tx.local_operation_id.to_string()], |r| Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?))).optional()? {
                ensure!(stored_binding == binding_digest, "idempotency_conflict");
                return Ok((serde_json::from_str(&receipt_json)?, None));
            }
            if let Some((authoritative, stored_semantic, receipt_json)) = conn.query_row("SELECT authoritative_operation_id,semantic_command_digest,receipt_json FROM media_local_path_registration_operations WHERE session_id=?1 AND canonical_project_digest=?2 AND client_draft_id=?3 AND is_alias=0", params![request_for_tx.session_id.to_string(),request_for_tx.canonical_project_digest,request_for_tx.client_draft_id.to_string()], |r| Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?))).optional()? {
                ensure!(stored_semantic == semantic_digest, "idempotency_conflict");
                conn.execute("INSERT INTO media_local_path_registration_operations(local_operation_id,authoritative_operation_id,session_id,canonical_project_digest,client_draft_id,request_binding_digest,operation_request_digest,semantic_command_digest,receipt_json,committed_at_unix_ms,is_alias) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,1)", params![request_for_tx.local_operation_id.to_string(),authoritative,request_for_tx.session_id.to_string(),request_for_tx.canonical_project_digest,request_for_tx.client_draft_id.to_string(),binding_digest,request_digest,semantic_digest,receipt_json,now_unix_ms])?;
                return Ok((serde_json::from_str(&receipt_json)?, None));
            }
            let media_kind = match request_for_tx.requested_media_kind { RequestedLocalPathMediaKind::Image=>MediaKind::Image, RequestedLocalPathMediaKind::Audio=>MediaKind::Audio, RequestedLocalPathMediaKind::Video=>MediaKind::Video };
            crate::media_reservation::reserve_conn(conn, crate::media_reservation::ReserveRequest { reservation_id: reservation_id.clone(), recovery_id: reservation_id.clone(), owner: crate::media_reservation::MediaOwner { project_id: request_for_tx.canonical_project_digest.clone(), session_id: request_for_tx.session_id.to_string() }, operation: "local_path_attachment_registration".into(), purpose: "borrowed_media".into(), plans, wall_ms: u64::try_from(now_unix_ms).context("negative registration time")? }, monotonic_now_ms)?;
            let record=MediaAttachmentRecord{attachment_id,session_id:request_for_tx.session_id,canonical_project_digest:request_for_tx.canonical_project_digest.clone(),media_kind,source_kind:MediaSourceKind::LocalPath,canonical_container:"application/octet-stream".into(),canonical_mime:"application/octet-stream".into(),availability:MediaAvailability::Registered,attachment_version:1,availability_generation:1,reference_generation:1,captured_capability_generation:1,source_identity_digest:identity.clone(),source_byte_length:before.len(),source_sha256:sha256.clone(),selected_video_stream:None,selected_audio_stream:None,created_at_unix_ms:now_unix_ms,updated_at_unix_ms:now_unix_ms,draft_expires_at_unix_ms:None,first_referenced_at_unix_ms:None};
            cockpit_db::Db::insert_media_attachment_conn(conn,&record)?;
            let receipt=LocalPathRegistrationReceiptV1{schema_version:1,kind:"localPathMediaRegistrationReceipt".into(),receipt_id,local_operation_id:request_for_tx.local_operation_id,owner_principal_digest:request_for_tx.owner_principal_digest.clone(),session_id:request_for_tx.session_id,canonical_project_digest:request_for_tx.canonical_project_digest.clone(),client_draft_id:request_for_tx.client_draft_id,operation_request_digest:request_digest.clone(),semantic_command_digest:semantic_digest.clone(),result:LocalPathRegistrationResultV1::Registered{attachment_id,attachment_version:1,availability_state:"registered".into(),availability_generation:1,reference_generation:1,reservation_id:reservation_id.clone(),reservation_digest:reservation_digest.clone(),source_evidence_digest:evidence_digest.clone()},committed_at_unix_ms:now_unix_ms};
            let receipt_json=serde_json::to_string(&receipt)?;
            conn.execute("INSERT INTO media_local_path_registration_evidence(attachment_id,canonical_path_digest,path_authority_digest,source_evidence_digest,source_mtime_unix_ns,reservation_id,reservation_digest) VALUES(?1,?2,?3,?4,?5,?6,?7)",params![attachment_id.to_string(),canonical_path_digest,authority_digest,evidence_digest,mtime_ns.to_string(),reservation_id,reservation_digest])?;
            conn.execute("INSERT INTO media_local_path_registration_operations(local_operation_id,authoritative_operation_id,session_id,canonical_project_digest,client_draft_id,request_binding_digest,operation_request_digest,semantic_command_digest,receipt_json,committed_at_unix_ms,is_alias) VALUES(?1,?1,?2,?3,?4,?5,?6,?7,?8,?9,0)",params![request_for_tx.local_operation_id.to_string(),request_for_tx.session_id.to_string(),request_for_tx.canonical_project_digest,request_for_tx.client_draft_id.to_string(),binding_digest,request_digest,semantic_digest,receipt_json,now_unix_ms])?;
            conn.execute("INSERT INTO media_local_path_registration_audit(local_operation_id,outcome,committed_at_unix_ms) VALUES(?1,'registered',?2)",params![request_for_tx.local_operation_id.to_string(),now_unix_ms])?;
            Ok((receipt,Some(attachment_id)))
        }).await?;
        if let Some(id) = result.1 {
            self.register_local_path_source(id, held)?;
        }
        Ok(result.0)
    }

    async fn registration_replay(
        &self,
        request: &RegisterLocalPathMediaV1,
        binding: &str,
    ) -> Result<Option<LocalPathRegistrationReceiptV1>> {
        let id = request.local_operation_id.to_string();
        let binding = binding.to_owned();
        self.db.read(move|conn| { let row:Option<(String,String)>=conn.query_row("SELECT request_binding_digest,receipt_json FROM media_local_path_registration_operations WHERE local_operation_id=?1",[id],|r|Ok((r.get(0)?,r.get(1)?))).optional()?; match row { Some((stored,json))=>{ensure!(stored==binding,"idempotency_conflict");Ok(Some(serde_json::from_str(&json)?))},None=>Ok(None)}}).await
    }
    pub(crate) fn open_or_create(db: cockpit_db::Db, owned_root: &Path) -> Result<Self> {
        let root = DirGuard::open_root(owned_root, true)
            .map_err(anyhow::Error::new)
            .context("opening held media storage root")?;
        root.verify_private().map_err(anyhow::Error::new)?;
        Ok(Self {
            db,
            owned_root: std::sync::Arc::new(root),
            borrowed_sources: Default::default(),
        })
    }

    pub(crate) fn open(db: cockpit_db::Db, owned_root: &Path) -> Result<Self> {
        let root = DirGuard::open_root(owned_root, false)
            .map_err(anyhow::Error::new)
            .context("opening held media storage root")?;
        root.verify_private()
            .map_err(anyhow::Error::new)
            .context("verifying media storage root")?;
        Ok(Self {
            db,
            owned_root: std::sync::Arc::new(root),
            borrowed_sources: Default::default(),
        })
    }

    /// Transfer the already-open no-delete local-path handle from registration
    /// into daemon ownership. Recovery consumes it only after its attachment
    /// identity has been selected under the same Owner scope.
    pub(crate) fn register_local_path_source(
        &self,
        attachment_id: Uuid,
        source: BorrowedSourceHandle,
    ) -> Result<()> {
        ensure!(
            is_uuid_v7(attachment_id),
            "borrowed attachment id must be UUIDv7"
        );
        self.borrowed_sources
            .lock()
            .map_err(|_| anyhow::anyhow!("borrowed source registry poisoned"))?
            .insert(attachment_id, source);
        Ok(())
    }

    pub(crate) async fn recover(
        &self,
        request: RecoverSecurityBlockedMediaV1,
        owner_session_id: Uuid,
        canonical_project_digest: String,
        borrowed_source: Option<BorrowedSourceHandle>,
        now_unix_ms: i64,
    ) -> Result<LocalMediaOwnerReceiptV1> {
        let root = self.owned_root.clone();
        let borrowed_source =
            if request.disposition == MediaSecurityRecoveryDisposition::ResumeVerifiedCleanup {
                match borrowed_source {
                    Some(source) => Some(source),
                    None => self
                        .borrowed_sources
                        .lock()
                        .map_err(|_| anyhow::anyhow!("borrowed source registry poisoned"))?
                        .remove(&request.attachment_id),
                }
            } else {
                borrowed_source
            };
        self.db
            .transaction(move |conn| {
                let snapshot = match cockpit_db::Db::security_recovery_snapshot_conn(
                    conn,
                    &request,
                    owner_session_id,
                    &canonical_project_digest,
                )? {
                    SecurityRecoverySnapshotResult::Replay(receipt) => return Ok(receipt),
                    SecurityRecoverySnapshotResult::Current(snapshot) => snapshot,
                };
                cockpit_db::Db::validate_recover_security_blocked_media_v1(
                    &request,
                    snapshot.attachment.source_kind,
                )?;
                let mut held_proof = None;
                let verified = match request.disposition {
                    MediaSecurityRecoveryDisposition::RetainBlocked => false,
                    MediaSecurityRecoveryDisposition::ResumeVerifiedCleanup => {
                        match verify_all_handles(
                            &root,
                            &snapshot,
                            request.borrowed_source_evidence_digest.as_deref(),
                            borrowed_source,
                        ) {
                            Ok(proof) => {
                                held_proof = Some(proof);
                                true
                            }
                            Err(_) => false,
                        }
                    }
                };
                let receipt = commit_security_recovery(
                    conn,
                    &request,
                    &snapshot,
                    owner_session_id,
                    &canonical_project_digest,
                    verified,
                    now_unix_ms,
                )?;
                drop(held_proof);
                Ok(receipt)
            })
            .await
    }
}

fn is_uuid_v7(value: Uuid) -> bool {
    !value.is_nil() && value.get_version_num() == 7 && value.get_variant() == uuid::Variant::RFC4122
}

fn preflight_local_operation(
    conn: &Connection,
    operation_id: Uuid,
    action: &str,
    domain: &str,
    request_digest: &str,
    semantic_digest: &str,
    now: i64,
) -> Result<Option<cockpit_db::media_attachments::LocalMediaMutationReceiptV1>> {
    if let Some((stored,json))=conn.query_row("SELECT operation_request_digest,receipt_json FROM local_media_operations WHERE local_operation_id=?1",[operation_id.to_string()],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?))).optional()?{ensure!(stored==request_digest,"local_operation_conflict");return Ok(Some(serde_json::from_str(&json)?))}
    if let Some((authoritative,stored_semantic,json))=conn.query_row("SELECT authoritative_operation_id,semantic_command_digest,receipt_json FROM local_media_operations WHERE action=?1 AND domain_key=?2 AND is_alias=0",params![action,domain],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?))).optional()?{ensure!(stored_semantic==semantic_digest,"local_domain_conflict");conn.execute("INSERT INTO local_media_operations(local_operation_id,authoritative_operation_id,action,domain_key,operation_request_digest,semantic_command_digest,receipt_json,is_alias,committed_at_unix_ms) VALUES(?1,?2,?3,?4,?5,?6,?7,1,?8)",params![operation_id.to_string(),authoritative,action,domain,request_digest,semantic_digest,json,now])?;return Ok(Some(serde_json::from_str(&json)?))}
    Ok(None)
}

fn commit_local_operation(
    conn: &Connection,
    receipt: &cockpit_db::media_attachments::LocalMediaMutationReceiptV1,
    action: &str,
    domain: &str,
    request_digest: &str,
    semantic_digest: &str,
    now: i64,
) -> Result<()> {
    let json = serde_json::to_string(receipt)?;
    conn.execute("INSERT INTO local_media_operations(local_operation_id,authoritative_operation_id,action,domain_key,operation_request_digest,semantic_command_digest,receipt_json,is_alias,committed_at_unix_ms) VALUES(?1,?1,?2,?3,?4,?5,?6,0,?7)",params![receipt.local_operation_id.to_string(),action,domain,request_digest,semantic_digest,json,now])?;
    conn.execute("INSERT INTO local_media_operation_audit(local_operation_id,outcome,committed_at_unix_ms) VALUES(?1,?2,?3)",params![receipt.local_operation_id.to_string(),match receipt.outcome{cockpit_db::media_attachments::LocalMediaMutationOutcomeV1::Applied=>"applied",cockpit_db::media_attachments::LocalMediaMutationOutcomeV1::Rejected=>"rejected"},now])?;
    Ok(())
}

fn validate_registration(request: &RegisterLocalPathMediaV1) -> Result<()> {
    ensure!(
        request.schema_version == 1 && request.kind == "registerLocalPathMedia",
        "invalid local path registration schema or kind"
    );
    ensure!(
        is_uuid_v7(request.local_operation_id)
            && is_uuid_v7(request.session_id)
            && is_uuid_v7(request.client_draft_id),
        "local path registration ids must be UUIDv7"
    );
    ensure!(
        request.owner_principal_digest.len() == 64
            && request
                .owner_principal_digest
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
        "invalid owner digest"
    );
    ensure!(
        request.canonical_project_digest.len() == 64
            && request
                .canonical_project_digest
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
        "invalid project digest"
    );
    ensure!(!request.path.is_empty(), "media_attachment_unavailable");
    Ok(())
}

fn digest_json<T: Serialize>(domain: &[u8], value: &T) -> Result<String> {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update([0]);
    digest.update(serde_json::to_vec(value)?);
    Ok(crate::intel::hex_lower(&digest.finalize()))
}

fn local_path_plans(
    policy: &cockpit_config::config::media_budget::MediaResourcePolicy,
    byte_length: u64,
) -> Result<Vec<cockpit_config::config::media_budget::MediaReservationPlan>> {
    use cockpit_config::config::media_budget::{
        MediaDimension, MediaEvaluationRequest, PASTE_IMAGE_PROFILE,
    };
    [
        (MediaDimension::QueuedOperationsGlobal, 1),
        (MediaDimension::QueuedOperationsPerSession, 1),
        (MediaDimension::EncodedBytesPerObject, byte_length),
        (MediaDimension::RetainedBytesPerSession, byte_length),
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
        policy
            .evaluate(MediaEvaluationRequest {
                dimension,
                requested: Some(requested),
                current_scope: 0,
                profile: Some(PASTE_IMAGE_PROFILE),
                adapter_limit: None,
                request_limit: None,
            })
            .map_err(anyhow::Error::new)
    })
    .collect()
}

pub(crate) fn media_upload_reservation_digest(
    policy: &cockpit_config::config::media_budget::MediaResourcePolicy,
    declared_total_bytes: u64,
) -> Result<String> {
    digest_json(
        b"media-upload-reservation-v1",
        &local_path_plans(policy, declared_total_bytes)?,
    )
}

fn media_kind_from_text(value: &str) -> Result<MediaKind> {
    match value {
        "image" => Ok(MediaKind::Image),
        "audio" => Ok(MediaKind::Audio),
        "video" => Ok(MediaKind::Video),
        _ => anyhow::bail!("invalid upload media kind"),
    }
}

/// Byte-authoritative first-stage classification. Containers whose identity
/// also depends on stream evidence remain rejected until bounded FFprobe and
/// full decode-to-null have supplied that evidence.
fn probe_upload_container(
    file: &mut File,
    declared: MediaKind,
) -> Result<(&'static str, &'static str)> {
    let mut header = [0u8; 32];
    file.seek(SeekFrom::Start(0))?;
    let read = file.read(&mut header)?;
    file.seek(SeekFrom::Start(0))?;
    let bytes = &header[..read];
    let classified = if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        Some((MediaKind::Image, "png", "image/png"))
    } else if bytes.starts_with(b"\xff\xd8\xff") {
        Some((MediaKind::Image, "jpeg", "image/jpeg"))
    } else if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
        Some((MediaKind::Image, "gif", "image/gif"))
    } else if bytes.len() >= 12 && &bytes[..4] == b"RIFF" && &bytes[8..12] == b"WEBP" {
        Some((MediaKind::Image, "webp", "image/webp"))
    } else {
        None
    };
    let (kind, container, mime) = classified.context("ambiguous_or_unsupported_container")?;
    ensure!(kind == declared, "ambiguous_or_unsupported_container");
    Ok((container, mime))
}

struct NormalizedImageDerivatives {
    model_png: Vec<u8>,
    thumbnail_png: Vec<u8>,
    width: u32,
    height: u32,
    thumbnail_width: u32,
    thumbnail_height: u32,
}

fn normalize_png_image(bytes: &[u8]) -> Result<NormalizedImageDerivatives> {
    use image::{
        DynamicImage, GenericImageView as _, ImageDecoder as _, ImageFormat, ImageReader, Limits,
    };
    reject_png_color_metadata(bytes)?;
    let mut reader = ImageReader::with_format(std::io::Cursor::new(bytes), ImageFormat::Png);
    let mut limits = Limits::default();
    limits.max_image_width = Some(8_192);
    limits.max_image_height = Some(8_192);
    limits.max_alloc = Some(160_000_000);
    reader.limits(limits);
    let decoder = reader.into_decoder().context("invalid_media")?;
    let (width, height) = decoder.dimensions();
    ensure!(
        width > 0 && height > 0 && width <= 8_192 && height <= 8_192,
        "resource_limit"
    );
    ensure!(
        u64::from(width)
            .checked_mul(u64::from(height))
            .is_some_and(|p| p <= 40_000_000),
        "resource_limit"
    );
    let mut rgba = DynamicImage::from_decoder(decoder)
        .context("decode_failed")?
        .into_rgba8();
    for pixel in rgba.pixels_mut() {
        if pixel[3] == 0 {
            *pixel = image::Rgba([0, 0, 0, 0]);
        }
    }
    let model_png = encode_canonical_png(&rgba)?;
    let max_edge = u64::from(width.max(height));
    let (thumbnail_width, thumbnail_height) = if max_edge <= 256 {
        (width, height)
    } else {
        (
            u32::try_from((u64::from(width) * 256 / max_edge).max(1))?,
            u32::try_from((u64::from(height) * 256 / max_edge).max(1))?,
        )
    };
    let thumbnail = image::imageops::resize(
        &rgba,
        thumbnail_width,
        thumbnail_height,
        image::imageops::FilterType::Triangle,
    );
    let thumbnail_png = encode_canonical_png(&thumbnail)?;
    ensure!(thumbnail_png.len() <= 512 * 1024, "resource_limit");
    Ok(NormalizedImageDerivatives {
        model_png,
        thumbnail_png,
        width,
        height,
        thumbnail_width,
        thumbnail_height,
    })
}

fn encode_canonical_png(image: &image::RgbaImage) -> Result<Vec<u8>> {
    use image::ImageEncoder as _;
    let mut encoded = Vec::new();
    image::codecs::png::PngEncoder::new_with_quality(
        &mut encoded,
        image::codecs::png::CompressionType::Level(6),
        image::codecs::png::FilterType::Paeth,
    )
    .write_image(
        image,
        image.width(),
        image.height(),
        image::ExtendedColorType::Rgba8,
    )?;
    insert_png_srgb(encoded)
}

fn reject_png_color_metadata(bytes: &[u8]) -> Result<()> {
    ensure!(bytes.starts_with(b"\x89PNG\r\n\x1a\n"), "invalid_media");
    let mut offset = 8usize;
    let mut srgb = 0usize;
    while offset.checked_add(12).is_some_and(|end| end <= bytes.len()) {
        let length = u32::from_be_bytes(bytes[offset..offset + 4].try_into()?) as usize;
        let end = offset
            .checked_add(12)
            .and_then(|v| v.checked_add(length))
            .context("invalid_media")?;
        ensure!(end <= bytes.len(), "invalid_media");
        let kind = &bytes[offset + 4..offset + 8];
        ensure!(
            kind != b"iCCP" && kind != b"cICP" && kind != b"gAMA" && kind != b"cHRM",
            "unsupported_color_profile"
        );
        if kind == b"sRGB" {
            srgb += 1;
            ensure!(
                length == 1 && bytes[offset + 8] == 0 && srgb == 1,
                "unsupported_color_profile"
            );
        }
        offset = end;
        if kind == b"IEND" {
            ensure!(offset == bytes.len(), "invalid_media");
            return Ok(());
        }
    }
    anyhow::bail!("invalid_media")
}

fn insert_png_srgb(encoded: Vec<u8>) -> Result<Vec<u8>> {
    ensure!(
        encoded.len() >= 33 && &encoded[12..16] == b"IHDR",
        "normalization_failed"
    );
    let mut chunk = Vec::with_capacity(13);
    chunk.extend_from_slice(&1u32.to_be_bytes());
    chunk.extend_from_slice(b"sRGB");
    chunk.push(0);
    chunk.extend_from_slice(&png_crc32(b"sRGB\0").to_be_bytes());
    let mut out = Vec::with_capacity(encoded.len() + chunk.len());
    out.extend_from_slice(&encoded[..33]);
    out.extend_from_slice(&chunk);
    out.extend_from_slice(&encoded[33..]);
    Ok(out)
}

fn png_crc32(bytes: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb8_8320 & 0u32.wrapping_sub(crc & 1));
        }
    }
    !crc
}

fn modified_ns(metadata: &std::fs::Metadata) -> Result<u128> {
    Ok(metadata
        .modified()?
        .duration_since(std::time::UNIX_EPOCH)
        .context("source mtime predates epoch")?
        .as_nanos())
}

#[cfg(unix)]
fn open_project_source(root: &Path, relative: &str) -> Result<File> {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::path::Component;
    let parts = Path::new(relative)
        .components()
        .map(|part| match part {
            Component::Normal(name) => {
                CString::new(name.as_encoded_bytes()).map_err(anyhow::Error::new)
            }
            _ => Err(anyhow::anyhow!("media_attachment_unavailable")),
        })
        .collect::<Result<Vec<_>>>()?;
    ensure!(!parts.is_empty(), "media_attachment_unavailable");
    let mut current = std::fs::OpenOptions::new().read(true).open(root)?;
    for (index, name) in parts.iter().enumerate() {
        let flags = libc::O_RDONLY
            | libc::O_NOFOLLOW
            | libc::O_CLOEXEC
            | if index + 1 == parts.len() {
                0
            } else {
                libc::O_DIRECTORY
            };
        let fd = unsafe { libc::openat(current.as_raw_fd(), name.as_ptr(), flags) };
        if fd < 0 {
            return Err(anyhow::anyhow!("media_attachment_unavailable"));
        }
        current = unsafe { File::from_raw_fd(fd) };
    }
    Ok(current)
}

#[cfg(windows)]
fn open_project_source(root: &Path, relative: &str) -> Result<File> {
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::FromRawHandle;
    use std::path::Component;
    ensure!(
        Path::new(relative)
            .components()
            .all(|c| matches!(c, Component::Normal(_))),
        "media_attachment_unavailable"
    );
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn CreateFileW(
            name: *const u16,
            access: u32,
            share: u32,
            security: *mut core::ffi::c_void,
            creation: u32,
            flags: u32,
            template: *mut core::ffi::c_void,
        ) -> *mut core::ffi::c_void;
    }
    const GENERIC_READ: u32 = 0x8000_0000;
    const FILE_SHARE_READ: u32 = 1;
    const FILE_SHARE_WRITE: u32 = 2;
    const OPEN_EXISTING: u32 = 3;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    let mut current = root.canonicalize()?;
    let mut held = Vec::new();
    crate::goal_scratch::verify_private_dacl(&current)
        .context("project root DACL is not protected")?;
    for component in Path::new(relative).components() {
        let Component::Normal(name) = component else {
            anyhow::bail!("media_attachment_unavailable")
        };
        current.push(name);
        let wide: Vec<u16> = current.as_os_str().encode_wide().chain(Some(0)).collect();
        let raw = unsafe {
            CreateFileW(
                wide.as_ptr(),
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                std::ptr::null_mut(),
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
                std::ptr::null_mut(),
            )
        };
        ensure!(raw as isize != -1, "media_attachment_unavailable");
        let file = unsafe { File::from_raw_handle(raw) };
        let meta = file.metadata()?;
        use std::os::windows::fs::MetadataExt as _;
        ensure!(
            meta.file_attributes() & 0x400 == 0,
            "media_attachment_unavailable"
        );
        crate::goal_scratch::verify_private_dacl(&current)
            .context("source component DACL is not protected")?;
        held.push(file);
    }
    let final_file = held.pop().context("media_attachment_unavailable")?;
    ensure!(
        final_file.metadata()?.is_file(),
        "media_attachment_unavailable"
    );
    Ok(final_file)
}

fn commit_security_recovery(
    conn: &Connection,
    request: &RecoverSecurityBlockedMediaV1,
    snapshot: &SecurityRecoverySnapshot,
    owner_session_id: Uuid,
    canonical_project_digest: &str,
    held_handles_verified: bool,
    now_unix_ms: i64,
) -> Result<LocalMediaOwnerReceiptV1> {
    let current = match cockpit_db::Db::security_recovery_snapshot_conn(
        conn,
        request,
        owner_session_id,
        canonical_project_digest,
    )? {
        SecurityRecoverySnapshotResult::Replay(receipt) => return Ok(receipt),
        SecurityRecoverySnapshotResult::Current(current) => current,
    };
    ensure!(&current == snapshot, "security recovery snapshot changed");
    let exact_set = snapshot.components.len() == request.affected_components.len()
        && snapshot
            .components
            .iter()
            .zip(&request.affected_components)
            .all(|(stored, requested)| {
                stored.component.component_id == requested.component_id
                    && stored.component.component_kind == requested.component_kind
                    && stored.component.component_generation == requested.component_generation
                    && recorded_component_digest(&stored.component)
                        == requested.recorded_evidence_digest
            });
    let stale = snapshot.attachment.attachment_version != request.attachment_version
        || snapshot.attachment.availability_generation != request.expected_availability_generation
        || snapshot.attachment.availability != MediaAvailability::SecurityBlocked
        || !exact_set;
    let outcome = if stale {
        MediaSecurityRecoveryOutcome::RejectedStale
    } else if snapshot.live_reference_count != 0 {
        MediaSecurityRecoveryOutcome::RejectedInUse
    } else if request.disposition == MediaSecurityRecoveryDisposition::RetainBlocked {
        MediaSecurityRecoveryOutcome::RetainedBlocked
    } else if held_handles_verified {
        MediaSecurityRecoveryOutcome::CleanupResumed
    } else {
        MediaSecurityRecoveryOutcome::RejectedUnverifiable
    };
    let mut components = Vec::with_capacity(snapshot.components.len());
    for stored in &snapshot.components {
        let before = stored.component.component_generation;
        let after = if outcome == MediaSecurityRecoveryOutcome::CleanupResumed {
            before
                .checked_add(1)
                .context("media component generation overflow")?
        } else {
            before
        };
        components.push(MediaSecurityRecoveryComponentTransitionV1 {
            component_id: stored.component.component_id,
            component_kind: stored.component.component_kind.clone(),
            generation_before: before,
            generation_after: after,
        });
        if outcome == MediaSecurityRecoveryOutcome::CleanupResumed {
            ensure!(conn.execute("UPDATE media_attachment_components SET lifecycle_state='cleanup_pending',component_generation=?1,updated_at_unix_ms=?2 WHERE component_id=?3 AND component_generation=?4", params![after.to_string(),now_unix_ms,stored.component.component_id.to_string(),before.to_string()])? == 1, "security recovery component CAS failed");
        }
    }
    let generation_before = snapshot.attachment.availability_generation;
    let generation_after = if outcome == MediaSecurityRecoveryOutcome::CleanupResumed {
        generation_before
            .checked_add(1)
            .context("media availability generation overflow")?
    } else {
        generation_before
    };
    if outcome == MediaSecurityRecoveryOutcome::CleanupResumed {
        let next_state = if snapshot.attachment.source_kind == MediaSourceKind::LocalPath {
            "borrowed_cleanup_pending"
        } else {
            "owned_cleanup_pending"
        };
        ensure!(conn.execute("UPDATE media_attachments SET availability=?1,availability_generation=?2,updated_at_unix_ms=?3 WHERE attachment_id=?4 AND attachment_version=?5 AND availability_generation=?6 AND availability='security_blocked'", params![next_state,generation_after.to_string(),now_unix_ms,request.attachment_id.to_string(),request.attachment_version.to_string(),generation_before.to_string()])? == 1, "security recovery aggregate CAS failed");
        conn.execute("INSERT INTO media_attachment_cleanup_intents (intent_id,attachment_id,attachment_version,expected_availability_generation,expected_reference_generation,component_set_digest,reason,created_at_unix_ms) VALUES (?1,?2,?3,?4,?5,?6,'security_recovery',?7)", params![Uuid::now_v7().to_string(),request.attachment_id.to_string(),request.attachment_version.to_string(),generation_after.to_string(),snapshot.attachment.reference_generation.to_string(),snapshot.affected_set_digest,now_unix_ms])?;
    }
    let receipt = LocalMediaOwnerReceiptV1 {
        schema_version: 1,
        kind: "localMediaOwnerRecovery".into(),
        receipt_id: Uuid::now_v7(),
        local_request_id: request.local_request_id,
        owner_principal_digest: request.owner_principal_digest.clone(),
        attachment_id: request.attachment_id,
        attachment_version: request.attachment_version,
        disposition: request.disposition,
        request_digest: snapshot.request_digest.clone(),
        affected_set_digest: snapshot.affected_set_digest.clone(),
        outcome,
        availability_generation_before: generation_before,
        availability_generation_after: generation_after,
        components,
        committed_at_unix_ms: now_unix_ms,
    };
    conn.execute("INSERT INTO media_security_recovery_operations (local_request_id,owner_principal_digest,attachment_id,attachment_version,request_digest,affected_set_digest,receipt_json,committed_at_unix_ms) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)", params![request.local_request_id.to_string(),request.owner_principal_digest,request.attachment_id.to_string(),request.attachment_version.to_string(),snapshot.request_digest,snapshot.affected_set_digest,serde_json::to_string(&receipt)?,now_unix_ms])?;
    Ok(receipt)
}

fn recorded_component_digest(
    component: &cockpit_db::media_attachments::VerifiedBlockedComponent,
) -> String {
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

fn verify_all_handles(
    root: &DirGuard,
    snapshot: &SecurityRecoverySnapshot,
    expected_borrowed_evidence: Option<&str>,
    borrowed_source: Option<BorrowedSourceHandle>,
) -> Result<HeldHandleRecoveryProof> {
    root.verify_private().map_err(anyhow::Error::new)?;
    let mut handles = Vec::with_capacity(snapshot.components.len() + 1);
    if snapshot.attachment.source_kind == cockpit_db::media_attachments::MediaSourceKind::LocalPath
    {
        let mut source = borrowed_source.context("borrowed source handle is required")?;
        let before = stable_identity_digest(&source.file)?;
        let (length, checksum) = read_full_digest(&mut source.file)?;
        let after = stable_identity_digest(&source.file)?;
        ensure!(
            before == after
                && before == snapshot.attachment.source_identity_digest
                && length == snapshot.attachment.source_byte_length
                && checksum == snapshot.attachment.source_sha256,
            "borrowed source changed while held"
        );
        ensure!(
            Some(source.evidence_digest.as_str()) == expected_borrowed_evidence,
            "borrowed source evidence does not match the request"
        );
        handles.push(source.file);
    } else {
        ensure!(
            borrowed_source.is_none(),
            "unexpected borrowed source handle"
        );
    }
    for stored in &snapshot.components {
        let name = stored.storage_id.to_string();
        let mut file = root.open_file_verified(&name).map_err(anyhow::Error::new)?;
        let before = stable_identity_digest(&file)?;
        let (length, checksum) = read_full_digest(&mut file)?;
        let after = stable_identity_digest(&file)?;
        ensure!(before == after, "component identity changed while held");
        ensure!(
            before == stored.component.stable_identity_digest,
            "component identity mismatch"
        );
        ensure!(
            length == stored.component.byte_length,
            "component length mismatch"
        );
        ensure!(
            checksum == stored.component.sha256,
            "component checksum mismatch"
        );
        handles.push(file);
    }
    Ok(HeldHandleRecoveryProof { _handles: handles })
}

fn source_evidence_digest(
    file: &mut File,
    expected_identity: &str,
    expected_length: u64,
    expected_checksum: &str,
) -> Result<String> {
    let before = stable_identity_digest(file)?;
    ensure!(
        before == expected_identity,
        "borrowed source identity mismatch"
    );
    let (length, checksum) = read_full_digest(file)?;
    let after = stable_identity_digest(file)?;
    ensure!(
        before == after,
        "borrowed source identity changed while held"
    );
    ensure!(length == expected_length, "borrowed source length mismatch");
    ensure!(
        checksum == expected_checksum,
        "borrowed source checksum mismatch"
    );
    let mut digest = Sha256::new();
    digest.update(b"borrowed-source-evidence-v1");
    digest.update(before.as_bytes());
    digest.update(length.to_be_bytes());
    digest.update(checksum.as_bytes());
    Ok(hex_lower(&digest.finalize()))
}

fn read_full_digest(file: &mut File) -> Result<(u64, String)> {
    file.seek(SeekFrom::Start(0))?;
    let mut digest = Sha256::new();
    let mut length = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        length = length
            .checked_add(read as u64)
            .context("media length overflow")?;
        digest.update(&buffer[..read]);
    }
    Ok((length, hex_lower(&digest.finalize())))
}

#[cfg(unix)]
fn stable_identity_digest(file: &File) -> Result<String> {
    use std::os::unix::fs::MetadataExt;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file() && metadata.nlink() == 1,
        "media object is not singly-linked regular file"
    );
    let mut digest = Sha256::new();
    digest.update(b"unix-file-identity-v1");
    digest.update(metadata.dev().to_be_bytes());
    digest.update(metadata.ino().to_be_bytes());
    Ok(hex_lower(&digest.finalize()))
}

#[cfg(windows)]
fn stable_identity_digest(file: &File) -> Result<String> {
    use std::os::windows::io::AsRawHandle as _;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
    };

    let metadata = file.metadata()?;
    ensure!(metadata.is_file(), "media object is not a regular file");
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    unsafe { GetFileInformationByHandle(HANDLE(file.as_raw_handle()), &mut information) }
        .context("querying held Windows media identity")?;
    ensure!(
        information.nNumberOfLinks == 1,
        "media object is not singly linked"
    );
    ensure!(
        information.dwFileAttributes & 0x400 == 0,
        "media object is a reparse point"
    );
    let mut digest = Sha256::new();
    digest.update(b"windows-file-identity-v1");
    digest.update(information.dwVolumeSerialNumber.to_be_bytes());
    digest.update(information.nFileIndexHigh.to_be_bytes());
    digest.update(information.nFileIndexLow.to_be_bytes());
    Ok(hex_lower(&digest.finalize()))
}

fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(value, "{byte:02x}");
    }
    value
}

#[cfg(all(test, unix))]
mod tests {
    use std::io::Write;

    use cockpit_db::media_attachments::{
        MediaAttachmentComponent, MediaAttachmentRecord, MediaAvailability, MediaKind,
        MediaSecurityRecoveryOutcome, MediaSourceKind, RecoverSecurityBlockedComponentV1,
    };
    use uuid::Uuid;

    use super::*;

    #[test]
    fn upload_container_probe_is_byte_authoritative_and_kind_exact() {
        for (bytes, container, mime) in [
            (&b"\x89PNG\r\n\x1a\n"[..], "png", "image/png"),
            (&b"\xff\xd8\xff\xe0"[..], "jpeg", "image/jpeg"),
            (&b"GIF89a"[..], "gif", "image/gif"),
            (&b"RIFF\x04\0\0\0WEBP"[..], "webp", "image/webp"),
        ] {
            let mut file = tempfile::tempfile().unwrap();
            file.write_all(bytes).unwrap();
            assert_eq!(
                probe_upload_container(&mut file, MediaKind::Image).unwrap(),
                (container, mime)
            );
        }
        let mut wrong_kind = tempfile::tempfile().unwrap();
        wrong_kind.write_all(b"\x89PNG\r\n\x1a\n").unwrap();
        assert!(probe_upload_container(&mut wrong_kind, MediaKind::Audio).is_err());
        let mut caller_claim = tempfile::tempfile().unwrap();
        caller_claim.write_all(b"photo.png").unwrap();
        assert!(probe_upload_container(&mut caller_claim, MediaKind::Image).is_err());
    }

    #[test]
    fn png_normalization_is_deterministic_bounded_and_metadata_minimal() {
        let source = image::RgbaImage::from_raw(2, 1, vec![255, 0, 0, 255, 90, 80, 70, 0]).unwrap();
        let mut input = std::io::Cursor::new(Vec::new());
        image::DynamicImage::ImageRgba8(source)
            .write_to(&mut input, image::ImageFormat::Png)
            .unwrap();
        let first = normalize_png_image(input.get_ref()).unwrap();
        let second = normalize_png_image(input.get_ref()).unwrap();
        assert_eq!(first.model_png, second.model_png);
        assert_eq!((first.width, first.height), (2, 1));
        assert_eq!((first.thumbnail_width, first.thumbnail_height), (2, 1));
        assert_eq!(first.thumbnail_png, first.model_png);
        let chunks = png_chunk_names(&first.model_png);
        assert_eq!(chunks, vec![*b"IHDR", *b"sRGB", *b"IDAT", *b"IEND"]);
        let decoded =
            image::load_from_memory_with_format(&first.model_png, image::ImageFormat::Png)
                .unwrap()
                .into_rgba8();
        assert_eq!(decoded.get_pixel(1, 0).0, [0, 0, 0, 0]);
    }

    fn png_chunk_names(bytes: &[u8]) -> Vec<[u8; 4]> {
        let mut names = Vec::new();
        let mut offset = 8usize;
        while offset + 12 <= bytes.len() {
            let length = u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
            names.push(bytes[offset + 4..offset + 8].try_into().unwrap());
            offset += 12 + length;
        }
        names
    }

    #[tokio::test]
    async fn local_path_registration_reserves_atomically_replays_and_conflicts() {
        let temp = tempfile::TempDir::new().unwrap();
        let project = temp.path().join("project");
        std::fs::create_dir(&project).unwrap();
        std::fs::write(project.join("source.bin"), b"held borrowed source").unwrap();
        let db = cockpit_db::Db::open_in_memory_async().await.unwrap();
        let session_id = Uuid::now_v7();
        db.transaction(move |conn| { conn.execute("INSERT INTO sessions(session_id,project_id,project_root,started_at,last_active_at) VALUES(?1,'project','/redacted',1,1)",[session_id.to_string()])?; Ok(()) }).await.unwrap();
        let recovery =
            MediaStorageRecovery::open_or_create(db.clone(), &temp.path().join("media")).unwrap();
        let request = RegisterLocalPathMediaV1 {
            schema_version: 1,
            kind: "registerLocalPathMedia".into(),
            local_operation_id: Uuid::now_v7(),
            owner_principal_digest: "22".repeat(32),
            session_id,
            canonical_project_digest: "11".repeat(32),
            client_draft_id: Uuid::now_v7(),
            requested_media_kind: RequestedLocalPathMediaKind::Image,
            path: "source.bin".into(),
        };
        let policy = cockpit_config::config::media_budget::MediaResourcePolicy::default();
        let first = recovery
            .register_local_path(request.clone(), &project, &policy, 1, 10)
            .await
            .unwrap();
        assert_eq!(
            recovery
                .register_local_path(request.clone(), &project, &policy, 2, 11)
                .await
                .unwrap(),
            first
        );
        std::fs::remove_file(project.join("source.bin")).unwrap();
        assert_eq!(
            recovery
                .register_local_path(request.clone(), &project, &policy, 3, 12)
                .await
                .unwrap(),
            first,
            "exact replay must not reopen the path"
        );
        let mut conflict = request;
        conflict.requested_media_kind = RequestedLocalPathMediaKind::Audio;
        assert!(
            recovery
                .register_local_path(conflict, &project, &policy, 4, 13)
                .await
                .unwrap_err()
                .to_string()
                .contains("idempotency_conflict")
        );
        let counts = db
            .read(|conn| {
                Ok((
                    conn.query_row("SELECT COUNT(*) FROM media_attachments", [], |r| {
                        r.get::<_, i64>(0)
                    })?,
                    conn.query_row("SELECT COUNT(*) FROM media_reservations", [], |r| {
                        r.get::<_, i64>(0)
                    })?,
                ))
            })
            .await
            .unwrap();
        assert_eq!(counts, (1, 1));
    }

    #[tokio::test]
    async fn local_path_registration_fault_rolls_back_reservation_and_attachment() {
        let temp = tempfile::TempDir::new().unwrap();
        let project = temp.path().join("project");
        std::fs::create_dir(&project).unwrap();
        std::fs::write(project.join("source.bin"), b"source").unwrap();
        let db = cockpit_db::Db::open_in_memory_async().await.unwrap();
        let session_id = Uuid::now_v7();
        db.transaction(move|conn|{conn.execute("INSERT INTO sessions(session_id,project_id,project_root,started_at,last_active_at) VALUES(?1,'project','/redacted',1,1)",[session_id.to_string()])?;conn.execute_batch("CREATE TRIGGER fail_local_evidence BEFORE INSERT ON media_local_path_registration_evidence BEGIN SELECT RAISE(ABORT,'injected registration fault'); END;")?;Ok(())}).await.unwrap();
        let recovery =
            MediaStorageRecovery::open_or_create(db.clone(), &temp.path().join("media")).unwrap();
        let request = RegisterLocalPathMediaV1 {
            schema_version: 1,
            kind: "registerLocalPathMedia".into(),
            local_operation_id: Uuid::now_v7(),
            owner_principal_digest: "22".repeat(32),
            session_id,
            canonical_project_digest: "11".repeat(32),
            client_draft_id: Uuid::now_v7(),
            requested_media_kind: RequestedLocalPathMediaKind::Image,
            path: "source.bin".into(),
        };
        assert!(
            recovery
                .register_local_path(
                    request,
                    &project,
                    &cockpit_config::config::media_budget::MediaResourcePolicy::default(),
                    1,
                    10
                )
                .await
                .is_err()
        );
        let counts = db
            .read(|conn| {
                Ok((
                    conn.query_row("SELECT COUNT(*) FROM media_attachments", [], |r| {
                        r.get::<_, i64>(0)
                    })?,
                    conn.query_row("SELECT COUNT(*) FROM media_reservations", [], |r| {
                        r.get::<_, i64>(0)
                    })?,
                ))
            })
            .await
            .unwrap();
        assert_eq!(counts, (0, 0));
    }

    #[tokio::test]
    async fn media_upload_begin_is_atomic_replayable_and_domain_unique() {
        use base64::Engine as _;
        use cockpit_db::media_attachments::{
            LocalMediaActorRoleV1, LocalMediaMutationPayloadV1, LocalMediaMutationReceiptV1,
            LocalMediaMutationTransitionV1, LocalMediaMutationV1,
        };
        let temp = tempfile::TempDir::new().unwrap();
        let database_path = temp.path().join("cockpit.db");
        let db = cockpit_db::Db::open(&database_path).unwrap();
        let session_id = Uuid::now_v7();
        db.transaction(move|conn|{conn.execute("INSERT INTO sessions(session_id,project_id,project_root,started_at,last_active_at) VALUES(?1,'project','/redacted',1,1)",[session_id.to_string()])?;Ok(())}).await.unwrap();
        let recovery =
            MediaStorageRecovery::open_or_create(db.clone(), &temp.path().join("media")).unwrap();
        let policy = cockpit_config::config::media_budget::MediaResourcePolicy::default();
        let mut encoded = std::io::Cursor::new(Vec::new());
        image::DynamicImage::ImageRgba8(image::RgbaImage::from_pixel(
            1,
            1,
            image::Rgba([1, 2, 3, 255]),
        ))
        .write_to(&mut encoded, image::ImageFormat::Png)
        .unwrap();
        let bytes: &[u8] = Box::leak(encoded.into_inner().into_boxed_slice());
        let byte_length = bytes.len() as u64;
        let plans = local_path_plans(&policy, byte_length).unwrap();
        let reservation_digest = digest_json(b"media-upload-reservation-v1", &plans).unwrap();
        let request = LocalMediaMutationV1 {
            schema_version: 1,
            kind: "localMediaMutation".into(),
            local_operation_id: Uuid::now_v7(),
            actor_principal_digest: "11".repeat(32),
            actor_role: LocalMediaActorRoleV1::Owner,
            payload: LocalMediaMutationPayloadV1::Begin {
                session_id,
                canonical_project_digest: "22".repeat(32),
                client_draft_id: Uuid::now_v7(),
                media_kind: RequestedLocalPathMediaKind::Image,
                declared_total_bytes: byte_length,
                reservation_digest,
            },
        };
        let first = recovery
            .begin_media_upload(request.clone(), &policy, 1, 10)
            .await
            .unwrap();
        let upload_id = first.subject_id;
        let draft_id = match &request.payload {
            LocalMediaMutationPayloadV1::Begin {
                client_draft_id, ..
            } => *client_draft_id,
            _ => unreachable!(),
        };
        assert!(matches!(
            first.transition,
            LocalMediaMutationTransitionV1::Upload {
                generation_before: 0,
                generation_after: 1
            }
        ));
        assert_eq!(
            recovery
                .begin_media_upload(request.clone(), &policy, 2, 11)
                .await
                .unwrap(),
            first
        );
        let mut alias = request.clone();
        alias.local_operation_id = Uuid::now_v7();
        assert_eq!(
            recovery
                .begin_media_upload(alias, &policy, 3, 12)
                .await
                .unwrap(),
            first
        );
        let mut conflict = request;
        let LocalMediaMutationPayloadV1::Begin {
            declared_total_bytes,
            ..
        } = &mut conflict.payload
        else {
            unreachable!()
        };
        *declared_total_bytes = byte_length - 1;
        assert!(
            recovery
                .begin_media_upload(conflict, &policy, 4, 13)
                .await
                .unwrap_err()
                .to_string()
                .contains("conflict")
        );
        let upload_for_intent = upload_id.to_string();
        let temporary: String = db
            .read(move |conn| {
                Ok(conn.query_row(
                    "SELECT temporary_storage_id FROM media_uploads WHERE upload_id=?1",
                    [upload_for_intent],
                    |row| row.get(0),
                )?)
            })
            .await
            .unwrap();
        let quarantine = Uuid::now_v7().to_string();
        let orphan = Uuid::now_v7().to_string();
        std::fs::rename(
            temp.path().join("media").join(&temporary),
            temp.path().join("media").join(&quarantine),
        )
        .unwrap();
        std::fs::write(temp.path().join("media").join(&orphan), b"orphan").unwrap();
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(
            temp.path().join("media").join(&orphan),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        let intent_upload = upload_id.to_string();
        let intent_temporary = temporary.clone();
        let intent_quarantine = quarantine.clone();
        let intent_derivatives = serde_json::to_string(&vec![orphan.clone()]).unwrap();
        db.transaction(move|conn|{conn.execute("INSERT INTO media_storage_publication_intents(upload_id,temporary_storage_id,quarantine_storage_id,derivative_storage_ids_json,created_at_unix_ms) VALUES(?1,?2,?3,?4,14)",params![intent_upload,intent_temporary,intent_quarantine,intent_derivatives])?;Ok(())}).await.unwrap();
        drop(recovery);
        let recovery = MediaStorageRecovery::open(db.clone(), &temp.path().join("media")).unwrap();
        assert_eq!(recovery.reconcile_media_uploads(15).await.unwrap(), 1);
        assert!(temp.path().join("media").join(&temporary).exists());
        assert!(!temp.path().join("media").join(&quarantine).exists());
        assert!(!temp.path().join("media").join(&orphan).exists());
        let append = cockpit_db::media_attachments::AppendMediaUploadChunkV1 {
            mutation: LocalMediaMutationV1 {
                schema_version: 1,
                kind: "localMediaMutation".into(),
                local_operation_id: Uuid::now_v7(),
                actor_principal_digest: "11".repeat(32),
                actor_role: LocalMediaActorRoleV1::Owner,
                payload: LocalMediaMutationPayloadV1::Append {
                    session_id,
                    canonical_project_digest: "22".repeat(32),
                    client_draft_id: draft_id,
                    upload_id,
                    upload_generation: 1,
                    chunk_index: 0,
                    chunk_length: byte_length as u32,
                    chunk_sha256: crate::intel::hex_lower(&Sha256::digest(bytes)),
                },
            },
            data_base64: base64::engine::general_purpose::STANDARD.encode(bytes),
        };
        let appended = recovery
            .append_media_upload_chunk(append.clone(), 20)
            .await
            .unwrap();
        assert!(matches!(
            appended.transition,
            LocalMediaMutationTransitionV1::Upload {
                generation_before: 1,
                generation_after: 2
            }
        ));
        assert_eq!(
            recovery
                .append_media_upload_chunk(append, 21)
                .await
                .unwrap(),
            appended
        );
        let upload_for_storage = upload_id.to_string();
        let temporary_storage: String = db
            .read(move |conn| {
                Ok(conn.query_row(
                    "SELECT temporary_storage_id FROM media_uploads WHERE upload_id=?1",
                    [upload_for_storage],
                    |row| row.get(0),
                )?)
            })
            .await
            .unwrap();
        std::fs::OpenOptions::new()
            .append(true)
            .open(temp.path().join("media").join(&temporary_storage))
            .unwrap()
            .write_all(b"uncommitted")
            .unwrap();
        let reopened = MediaStorageRecovery::open(db.clone(), &temp.path().join("media")).unwrap();
        assert_eq!(reopened.reconcile_media_uploads(22).await.unwrap(), 1);
        assert_eq!(
            std::fs::metadata(temp.path().join("media").join(&temporary_storage))
                .unwrap()
                .len(),
            byte_length
        );
        let cancel = LocalMediaMutationV1 {
            schema_version: 1,
            kind: "localMediaMutation".into(),
            local_operation_id: Uuid::now_v7(),
            actor_principal_digest: "11".repeat(32),
            actor_role: LocalMediaActorRoleV1::Owner,
            payload: LocalMediaMutationPayloadV1::Cancel {
                session_id,
                canonical_project_digest: "22".repeat(32),
                client_draft_id: draft_id,
                upload_id,
                upload_generation: 2,
            },
        };
        db.transaction(|conn| {conn.execute_batch("CREATE TRIGGER fail_cancel_completion BEFORE UPDATE OF state ON media_uploads WHEN NEW.state='cancelled' BEGIN SELECT RAISE(ABORT,'injected cancel completion crash'); END;")?;Ok(())}).await.unwrap();
        assert!(
            recovery
                .cancel_media_upload(cancel.clone(), 30)
                .await
                .unwrap_err()
                .to_string()
                .contains("injected cancel completion crash")
        );
        let cancel_operation = cancel.local_operation_id.to_string();
        let cancelled: LocalMediaMutationReceiptV1 = db
            .read(move |conn| {
                Ok(serde_json::from_str(&conn.query_row(
                    "SELECT receipt_json FROM local_media_operations WHERE local_operation_id=?1",
                    [cancel_operation],
                    |row| row.get::<_, String>(0),
                )?)?)
            })
            .await
            .unwrap();
        db.transaction(|conn| {
            conn.execute_batch("DROP TRIGGER fail_cancel_completion")?;
            Ok(())
        })
        .await
        .unwrap();
        drop(recovery);
        let recovery = MediaStorageRecovery::open(db.clone(), &temp.path().join("media")).unwrap();
        assert_eq!(recovery.reconcile_media_uploads(31).await.unwrap(), 1);
        assert!(matches!(
            cancelled.transition,
            LocalMediaMutationTransitionV1::Upload {
                generation_before: 2,
                generation_after: 3
            }
        ));
        assert_eq!(
            recovery.cancel_media_upload(cancel, 32).await.unwrap(),
            cancelled
        );
        let status = db
            .read(move |conn| {
                cockpit_db::Db::media_upload_status_for_owner_conn(
                    conn,
                    &cockpit_db::media_attachments::GetMediaUploadStatusV1 {
                        schema_version: 1,
                        kind: "getMediaUploadStatus".into(),
                        session_id,
                        canonical_project_digest: "22".repeat(32),
                        client_draft_id: draft_id,
                        upload_id,
                        upload_generation: 3,
                    },
                )
            })
            .await
            .unwrap()
            .unwrap();
        assert_eq!(status.acknowledged_bytes, byte_length);
        assert_eq!(status.expires_at_unix_ms, 86_400_010);
        assert!(matches!(
            status.detail,
            cockpit_db::media_attachments::MediaUploadStateDetailV1::Cancelled {
                reason: cockpit_db::media_attachments::MediaUploadTerminalReasonV1::ClientCancelled
            }
        ));
        let second_draft = Uuid::now_v7();
        let second_begin = LocalMediaMutationV1 {
            schema_version: 1,
            kind: "localMediaMutation".into(),
            local_operation_id: Uuid::now_v7(),
            actor_principal_digest: "11".repeat(32),
            actor_role: LocalMediaActorRoleV1::Owner,
            payload: LocalMediaMutationPayloadV1::Begin {
                session_id,
                canonical_project_digest: "22".repeat(32),
                client_draft_id: second_draft,
                media_kind: RequestedLocalPathMediaKind::Image,
                declared_total_bytes: byte_length,
                reservation_digest: digest_json(
                    b"media-upload-reservation-v1",
                    &local_path_plans(&policy, byte_length).unwrap(),
                )
                .unwrap(),
            },
        };
        let second = recovery
            .begin_media_upload(second_begin, &policy, 40, 40)
            .await
            .unwrap();
        let second_upload = second.subject_id;
        let second_append = cockpit_db::media_attachments::AppendMediaUploadChunkV1 {
            mutation: LocalMediaMutationV1 {
                schema_version: 1,
                kind: "localMediaMutation".into(),
                local_operation_id: Uuid::now_v7(),
                actor_principal_digest: "11".repeat(32),
                actor_role: LocalMediaActorRoleV1::Owner,
                payload: LocalMediaMutationPayloadV1::Append {
                    session_id,
                    canonical_project_digest: "22".repeat(32),
                    client_draft_id: second_draft,
                    upload_id: second_upload,
                    upload_generation: 1,
                    chunk_index: 0,
                    chunk_length: byte_length as u32,
                    chunk_sha256: crate::intel::hex_lower(&Sha256::digest(bytes)),
                },
            },
            data_base64: base64::engine::general_purpose::STANDARD.encode(bytes),
        };
        recovery
            .append_media_upload_chunk(second_append, 41)
            .await
            .unwrap();
        let finalize = LocalMediaMutationV1 {
            schema_version: 1,
            kind: "localMediaMutation".into(),
            local_operation_id: Uuid::now_v7(),
            actor_principal_digest: "11".repeat(32),
            actor_role: LocalMediaActorRoleV1::Owner,
            payload: LocalMediaMutationPayloadV1::Finalize {
                session_id,
                canonical_project_digest: "22".repeat(32),
                client_draft_id: second_draft,
                upload_id: second_upload,
                upload_generation: 2,
                chunk_count: 1,
                total_bytes: byte_length,
                object_sha256: crate::intel::hex_lower(&Sha256::digest(bytes)),
            },
        };
        db.transaction(|conn| {
            conn.execute_batch(
                "CREATE TRIGGER fail_upload_attachment_insert BEFORE INSERT ON media_attachments BEGIN SELECT RAISE(ABORT,'injected upload attachment failure'); END;",
            )?;
            Ok(())
        })
        .await
        .unwrap();
        assert!(
            recovery
                .finalize_media_upload(finalize.clone(), 42)
                .await
                .unwrap_err()
                .to_string()
                .contains("injected upload attachment failure")
        );
        let failed_counts = db
            .read(|conn| {
                Ok((
                    conn.query_row("SELECT COUNT(*) FROM media_attachments", [], |row| {
                        row.get::<_, i64>(0)
                    })?,
                    conn.query_row(
                        "SELECT COUNT(*) FROM local_media_operations WHERE action='finalize'",
                        [],
                        |row| row.get::<_, i64>(0),
                    )?,
                    conn.query_row(
                        "SELECT state FROM media_uploads WHERE upload_id=?1",
                        [second_upload.to_string()],
                        |row| row.get::<_, String>(0),
                    )?,
                ))
            })
            .await
            .unwrap();
        assert_eq!(failed_counts, (0, 0, "open".to_string()));
        assert_eq!(
            std::fs::read_dir(temp.path().join("media"))
                .unwrap()
                .count(),
            1,
            "failed publication restores exactly the upload temporary"
        );
        db.transaction(|conn| {
            conn.execute_batch("DROP TRIGGER fail_upload_attachment_insert")?;
            Ok(())
        })
        .await
        .unwrap();
        for (trigger, table) in [
            (
                "fail_upload_component_insert",
                "media_attachment_components",
            ),
            (
                "fail_upload_origin_insert",
                "media_attachment_upload_origins",
            ),
            ("fail_upload_operation_insert", "local_media_operations"),
            ("fail_upload_audit_insert", "local_media_operation_audit"),
        ] {
            let create = format!(
                "CREATE TRIGGER {trigger} BEFORE INSERT ON {table} BEGIN SELECT RAISE(ABORT,'injected finalize tranche failure'); END;"
            );
            db.transaction(move |conn| {
                conn.execute_batch(&create)?;
                Ok(())
            })
            .await
            .unwrap();
            assert!(
                recovery
                    .finalize_media_upload(finalize.clone(), 43)
                    .await
                    .unwrap_err()
                    .to_string()
                    .contains("injected finalize tranche failure")
            );
            let graph_counts = db
                .read(|conn| {
                    Ok((
                        conn.query_row("SELECT COUNT(*) FROM media_attachments", [], |row| {
                            row.get::<_, i64>(0)
                        })?,
                        conn.query_row(
                            "SELECT COUNT(*) FROM media_attachment_components",
                            [],
                            |row| row.get::<_, i64>(0),
                        )?,
                        conn.query_row(
                            "SELECT COUNT(*) FROM media_attachment_upload_origins",
                            [],
                            |row| row.get::<_, i64>(0),
                        )?,
                        conn.query_row(
                            "SELECT COUNT(*) FROM local_media_operations WHERE action='finalize'",
                            [],
                            |row| row.get::<_, i64>(0),
                        )?,
                    ))
                })
                .await
                .unwrap();
            assert_eq!(graph_counts, (0, 0, 0, 0));
            assert_eq!(
                std::fs::read_dir(temp.path().join("media"))
                    .unwrap()
                    .count(),
                1
            );
            let drop_trigger = format!("DROP TRIGGER {trigger}");
            db.transaction(move |conn| {
                conn.execute_batch(&drop_trigger)?;
                Ok(())
            })
            .await
            .unwrap();
        }
        let finalized = recovery
            .finalize_media_upload(finalize.clone(), 44)
            .await
            .unwrap();
        assert!(matches!(
            finalized.transition,
            LocalMediaMutationTransitionV1::UploadToAttachment {
                upload_generation_before: 2,
                upload_generation_after: 3,
                attachment_version: 1,
                availability_generation: 5,
                reference_generation: 1
            }
        ));
        assert_eq!(
            recovery.finalize_media_upload(finalize, 45).await.unwrap(),
            finalized
        );
        let finalized_status = db
            .read(move |conn| {
                cockpit_db::Db::media_upload_status_for_owner_conn(
                    conn,
                    &cockpit_db::media_attachments::GetMediaUploadStatusV1 {
                        schema_version: 1,
                        kind: "getMediaUploadStatus".into(),
                        session_id,
                        canonical_project_digest: "22".repeat(32),
                        client_draft_id: second_draft,
                        upload_id: second_upload,
                        upload_generation: 3,
                    },
                )
            })
            .await
            .unwrap()
            .unwrap();
        assert_eq!(finalized_status.acknowledged_bytes, byte_length);
        assert!(matches!(
            finalized_status.detail,
            cockpit_db::media_attachments::MediaUploadStateDetailV1::Materialized {
                attachment_id: _,
                attachment_version: 1,
            }
        ));
        let canonical: (String, String) = db
            .read(|conn| {
                Ok(conn.query_row(
                    "SELECT canonical_container,canonical_mime FROM media_attachments",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )?)
            })
            .await
            .unwrap();
        assert_eq!(canonical, ("png".into(), "image/png".into()));
        let ready_status = db
            .read(move |conn| {
                let attachment_id: String =
                    conn.query_row("SELECT attachment_id FROM media_attachments", [], |row| {
                        row.get(0)
                    })?;
                cockpit_db::Db::media_attachment_status_for_owner_conn(
                    conn,
                    &cockpit_db::media_attachments::GetMediaAttachmentStatusV1 {
                        schema_version: 1,
                        kind: "getMediaAttachmentStatus".into(),
                        session_id,
                        canonical_project_digest: "22".repeat(32),
                        attachment_id: Uuid::parse_str(&attachment_id)?,
                    },
                )
            })
            .await
            .unwrap()
            .unwrap();
        assert_eq!(ready_status.availability_generation, 5);
        assert!(ready_status.preview_available);
        assert!(matches!(
            ready_status.detail,
            cockpit_db::media_attachments::MediaAttachmentStatusDetailV1::Ready {
                preview: Some(_),
                ..
            }
        ));
        let publication_evidence: (i64, i64) = db
            .read(|conn| {
                Ok((
                    conn.query_row(
                        "SELECT COUNT(*) FROM media_attachment_transition_evidence",
                        [],
                        |row| row.get(0),
                    )?,
                    conn.query_row(
                        "SELECT COUNT(*) FROM media_storage_publication_intents",
                        [],
                        |row| row.get(0),
                    )?,
                ))
            })
            .await
            .unwrap();
        assert_eq!(publication_evidence, (4, 0));
        let counts = db
            .read(|conn| {
                Ok((
                    conn.query_row("SELECT COUNT(*) FROM media_uploads", [], |r| {
                        r.get::<_, i64>(0)
                    })?,
                    conn.query_row("SELECT COUNT(*) FROM media_reservations", [], |r| {
                        r.get::<_, i64>(0)
                    })?,
                    conn.query_row("SELECT COUNT(*) FROM local_media_operations", [], |r| {
                        r.get::<_, i64>(0)
                    })?,
                    conn.query_row("SELECT COUNT(*) FROM media_upload_chunks", [], |r| {
                        r.get::<_, i64>(0)
                    })?,
                ))
            })
            .await
            .unwrap();
        assert_eq!(counts, (2, 2, 7, 2));
        assert_eq!(
            std::fs::read_dir(temp.path().join("media"))
                .unwrap()
                .count(),
            3
        );
        let state: String = db
            .read(|conn| {
                Ok(conn.query_row("SELECT state FROM media_reservations", [], |r| r.get(0))?)
            })
            .await
            .unwrap();
        assert_eq!(state, "released");
    }

    #[tokio::test]
    async fn expired_upload_is_deleted_released_and_survives_reopen() {
        use cockpit_db::media_attachments::{
            LocalMediaActorRoleV1, LocalMediaMutationPayloadV1, LocalMediaMutationV1,
            MediaUploadStateDetailV1, MediaUploadTerminalReasonV1,
        };
        let temp = tempfile::TempDir::new().unwrap();
        let database_path = temp.path().join("expiry.db");
        let db = cockpit_db::Db::open(&database_path).unwrap();
        let session_id = Uuid::now_v7();
        db.transaction(move |conn| {
            conn.execute("INSERT INTO sessions(session_id,project_id,project_root,started_at,last_active_at) VALUES(?1,'project','/redacted',1,1)",[session_id.to_string()])?;
            Ok(())
        }).await.unwrap();
        let root = temp.path().join("media");
        let recovery = MediaStorageRecovery::open_or_create(db.clone(), &root).unwrap();
        let policy = cockpit_config::config::media_budget::MediaResourcePolicy::default();
        let draft = Uuid::now_v7();
        let receipt = recovery
            .begin_media_upload(
                LocalMediaMutationV1 {
                    schema_version: 1,
                    kind: "localMediaMutation".into(),
                    local_operation_id: Uuid::now_v7(),
                    actor_principal_digest: "11".repeat(32),
                    actor_role: LocalMediaActorRoleV1::Owner,
                    payload: LocalMediaMutationPayloadV1::Begin {
                        session_id,
                        canonical_project_digest: "22".repeat(32),
                        client_draft_id: draft,
                        media_kind: RequestedLocalPathMediaKind::Image,
                        declared_total_bytes: 7,
                        reservation_digest: digest_json(
                            b"media-upload-reservation-v1",
                            &local_path_plans(&policy, 7).unwrap(),
                        )
                        .unwrap(),
                    },
                },
                &policy,
                1,
                10,
            )
            .await
            .unwrap();
        db.transaction(|conn|{conn.execute_batch("CREATE TRIGGER fail_expiry_completion BEFORE UPDATE OF state ON media_uploads WHEN NEW.state='expired' BEGIN SELECT RAISE(ABORT,'injected expiry completion crash'); END;")?;Ok(())}).await.unwrap();
        assert!(
            recovery
                .reconcile_media_uploads(86_400_010)
                .await
                .unwrap_err()
                .to_string()
                .contains("injected expiry completion crash")
        );
        db.transaction(|conn| {
            conn.execute_batch("DROP TRIGGER fail_expiry_completion")?;
            Ok(())
        })
        .await
        .unwrap();
        drop(recovery);
        drop(db);
        let db = cockpit_db::Db::open(&database_path).unwrap();
        let reopened = MediaStorageRecovery::open(db.clone(), &root).unwrap();
        assert_eq!(
            reopened.reconcile_media_uploads(86_400_010).await.unwrap(),
            1
        );
        assert_eq!(
            reopened.reconcile_media_uploads(86_400_011).await.unwrap(),
            0
        );
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), 0);
        let upload_id = receipt.subject_id;
        let status = db
            .read(move |conn| {
                cockpit_db::Db::media_upload_status_for_owner_conn(
                    conn,
                    &cockpit_db::media_attachments::GetMediaUploadStatusV1 {
                        schema_version: 1,
                        kind: "getMediaUploadStatus".into(),
                        session_id,
                        canonical_project_digest: "22".repeat(32),
                        client_draft_id: draft,
                        upload_id,
                        upload_generation: 2,
                    },
                )
            })
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            status.detail,
            MediaUploadStateDetailV1::Expired {
                reason: MediaUploadTerminalReasonV1::DraftExpired
            }
        ));
        let reservation_state: String = db
            .read(|conn| {
                Ok(conn.query_row("SELECT state FROM media_reservations", [], |row| row.get(0))?)
            })
            .await
            .unwrap();
        assert_eq!(reservation_state, "released");
    }

    struct Fixture {
        _temp: tempfile::TempDir,
        root_path: std::path::PathBuf,
        db: cockpit_db::Db,
        request: RecoverSecurityBlockedMediaV1,
        storage_id: Uuid,
        session_id: Uuid,
        project_digest: String,
        borrowed_source: Option<BorrowedSourceHandle>,
    }

    async fn fixture() -> Fixture {
        fixture_for(false).await
    }

    async fn fixture_for(borrowed: bool) -> Fixture {
        let temp = tempfile::TempDir::new().unwrap();
        let root_path = temp.path().join("media");
        let root = DirGuard::open_root(&root_path, true).unwrap();
        let storage_id = Uuid::now_v7();
        let mut file = root.create_file_exclusive(&storage_id.to_string()).unwrap();
        file.write_all(b"verified media bytes").unwrap();
        file.sync_all().unwrap();
        let identity = stable_identity_digest(&file).unwrap();
        let (byte_length, checksum) = read_full_digest(&mut file).unwrap();
        let (
            source_kind,
            source_identity,
            source_length,
            source_checksum,
            source_evidence,
            borrowed_source,
        ) = if borrowed {
            let source_path = temp.path().join("borrowed-source.bin");
            std::fs::write(&source_path, b"borrowed source bytes").unwrap();
            let mut source = std::fs::OpenOptions::new()
                .read(true)
                .open(&source_path)
                .unwrap();
            let identity = stable_identity_digest(&source).unwrap();
            let (length, checksum) = read_full_digest(&mut source).unwrap();
            let evidence =
                source_evidence_digest(&mut source, &identity, length, &checksum).unwrap();
            (
                MediaSourceKind::LocalPath,
                identity,
                length,
                checksum,
                Some(evidence.clone()),
                Some(BorrowedSourceHandle {
                    file: source,
                    evidence_digest: evidence,
                }),
            )
        } else {
            (
                MediaSourceKind::RetainedHttps,
                "22".repeat(32),
                1,
                "33".repeat(32),
                None,
                None,
            )
        };

        let db = cockpit_db::Db::open_in_memory_async().await.unwrap();
        let session_id = Uuid::now_v7();
        let project_digest = "11".repeat(32);
        let inserted_project_digest = project_digest.clone();
        let attachment_id = Uuid::now_v7();
        let component_id = Uuid::now_v7();
        let component = MediaAttachmentComponent {
            component_id,
            attachment_id,
            attachment_version: 1,
            component_kind: "image_model".into(),
            storage_id,
            lifecycle_state: "security_blocked".into(),
            component_generation: 1,
            stable_identity_digest: identity.clone(),
            byte_length,
            sha256: checksum.clone(),
            reservation_id: "media-storage-recovery-test".into(),
            created_at_unix_ms: 1,
            updated_at_unix_ms: 1,
        };
        let inserted = component.clone();
        let initial_availability = if borrowed {
            MediaAvailability::Registered
        } else {
            MediaAvailability::Quarantined
        };
        let inserted_source_identity = source_identity.clone();
        let inserted_source_checksum = source_checksum.clone();
        db.transaction(move |conn| {
            conn.execute("INSERT INTO sessions (session_id,project_id,project_root,started_at,last_active_at) VALUES (?1,'project','/redacted',1,1)", [session_id.to_string()])?;
            cockpit_db::Db::insert_media_attachment_conn(conn, &MediaAttachmentRecord {
                attachment_id,
                session_id,
                canonical_project_digest: inserted_project_digest,
                media_kind: MediaKind::Image,
                source_kind,
                canonical_container: "png".into(),
                canonical_mime: "image/png".into(),
                availability: initial_availability,
                attachment_version: 1,
                availability_generation: 1,
                reference_generation: 1,
                captured_capability_generation: 1,
                source_identity_digest: inserted_source_identity,
                source_byte_length: source_length,
                source_sha256: inserted_source_checksum,
                selected_video_stream: None,
                selected_audio_stream: None,
                created_at_unix_ms: 1,
                updated_at_unix_ms: 1,
                draft_expires_at_unix_ms: None,
                first_referenced_at_unix_ms: None,
            })?;
            cockpit_db::Db::transition_media_attachment_conn(conn, attachment_id, 1, 1, MediaAvailability::SecurityBlocked, 2)?;
            cockpit_db::Db::insert_media_attachment_component_conn(conn, &inserted)
        }).await.unwrap();
        let proof_component = cockpit_db::media_attachments::VerifiedBlockedComponent {
            component_id,
            component_kind: component.component_kind.clone(),
            component_generation: 1,
            stable_identity_digest: identity,
            byte_length,
            sha256: checksum,
            reservation_id: component.reservation_id,
            deletion_evidence_digest: None,
        };
        let request = RecoverSecurityBlockedMediaV1 {
            schema_version: 1,
            kind: "recoverSecurityBlockedMedia".into(),
            local_request_id: Uuid::now_v7(),
            owner_principal_digest: "44".repeat(32),
            attachment_id,
            attachment_version: 1,
            expected_availability_generation: 2,
            affected_components: vec![RecoverSecurityBlockedComponentV1 {
                component_id,
                component_kind: "image_model".into(),
                component_generation: 1,
                recorded_evidence_digest: recorded_evidence_digest(&proof_component),
            }],
            borrowed_source_evidence_digest: source_evidence,
            disposition: MediaSecurityRecoveryDisposition::ResumeVerifiedCleanup,
        };
        Fixture {
            _temp: temp,
            root_path,
            db,
            request,
            storage_id,
            session_id,
            project_digest,
            borrowed_source,
        }
    }

    fn recorded_evidence_digest(
        component: &cockpit_db::media_attachments::VerifiedBlockedComponent,
    ) -> String {
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
        field(&mut hasher, b"");
        hex_lower(&hasher.finalize())
    }

    #[tokio::test]
    async fn media_storage_recovery_success_replay_conflict_and_reopen() {
        let fixture = fixture().await;
        let recovery = MediaStorageRecovery::open(fixture.db.clone(), &fixture.root_path).unwrap();
        let receipt = recovery
            .recover(
                fixture.request.clone(),
                fixture.session_id,
                fixture.project_digest.clone(),
                None,
                10,
            )
            .await
            .unwrap();
        assert_eq!(
            receipt.outcome,
            MediaSecurityRecoveryOutcome::CleanupResumed
        );
        assert_eq!(receipt.availability_generation_after, 3);
        let replay = recovery
            .recover(
                fixture.request.clone(),
                fixture.session_id,
                fixture.project_digest.clone(),
                None,
                99,
            )
            .await
            .unwrap();
        assert_eq!(replay, receipt);
        let mut conflict = fixture.request.clone();
        conflict.disposition = MediaSecurityRecoveryDisposition::RetainBlocked;
        assert!(
            recovery
                .recover(
                    conflict,
                    fixture.session_id,
                    fixture.project_digest.clone(),
                    None,
                    100
                )
                .await
                .unwrap_err()
                .to_string()
                .contains("local operation conflict")
        );
        drop(recovery);
        let reopened = MediaStorageRecovery::open(fixture.db, &fixture.root_path).unwrap();
        assert_eq!(
            reopened
                .recover(
                    fixture.request,
                    fixture.session_id,
                    fixture.project_digest,
                    None,
                    101
                )
                .await
                .unwrap(),
            receipt
        );
    }

    #[tokio::test]
    async fn media_storage_recovery_fault_is_terminal_and_nonmutating() {
        let fixture = fixture().await;
        std::fs::OpenOptions::new()
            .write(true)
            .open(fixture.root_path.join(fixture.storage_id.to_string()))
            .unwrap()
            .write_all(b"tampered")
            .unwrap();
        let recovery = MediaStorageRecovery::open(fixture.db.clone(), &fixture.root_path).unwrap();
        let receipt = recovery
            .recover(
                fixture.request.clone(),
                fixture.session_id,
                fixture.project_digest.clone(),
                None,
                10,
            )
            .await
            .unwrap();
        assert_eq!(
            receipt.outcome,
            MediaSecurityRecoveryOutcome::RejectedUnverifiable
        );
        assert_eq!(
            receipt.availability_generation_before,
            receipt.availability_generation_after
        );
        assert_eq!(
            receipt.components[0].generation_before,
            receipt.components[0].generation_after
        );
        assert_eq!(
            recovery
                .recover(
                    fixture.request,
                    fixture.session_id,
                    fixture.project_digest,
                    None,
                    11
                )
                .await
                .unwrap(),
            receipt
        );
    }

    #[tokio::test]
    async fn borrowed_media_recovery_uses_registered_handle_and_replays() {
        let mut fixture = fixture_for(true).await;
        let recovery = MediaStorageRecovery::open(fixture.db.clone(), &fixture.root_path).unwrap();
        recovery
            .register_local_path_source(
                fixture.request.attachment_id,
                fixture.borrowed_source.take().unwrap(),
            )
            .unwrap();
        let receipt = recovery
            .recover(
                fixture.request.clone(),
                fixture.session_id,
                fixture.project_digest.clone(),
                None,
                20,
            )
            .await
            .unwrap();
        assert_eq!(
            receipt.outcome,
            MediaSecurityRecoveryOutcome::CleanupResumed
        );
        assert_eq!(
            recovery
                .recover(
                    fixture.request,
                    fixture.session_id,
                    fixture.project_digest,
                    None,
                    21
                )
                .await
                .unwrap(),
            receipt
        );
    }

    #[tokio::test]
    async fn borrowed_media_recovery_without_registered_handle_is_rejected() {
        let fixture = fixture_for(true).await;
        let recovery = MediaStorageRecovery::open(fixture.db, &fixture.root_path).unwrap();
        let receipt = recovery
            .recover(
                fixture.request,
                fixture.session_id,
                fixture.project_digest,
                None,
                20,
            )
            .await
            .unwrap();
        assert_eq!(
            receipt.outcome,
            MediaSecurityRecoveryOutcome::RejectedUnverifiable
        );
    }
}
