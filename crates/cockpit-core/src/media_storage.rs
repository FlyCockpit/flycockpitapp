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
    AcquiredMediaComponentLease, HttpsRedirectLocationClassV1, HttpsRetentionRejectionReasonV1,
    HttpsRetentionResultV1, LocalMediaOwnerReceiptV1, LocalPathRegistrationReceiptV1,
    LocalPathRegistrationResultV1, MediaAttachmentRecord, MediaAvailability,
    MediaComponentLeaseKind, MediaKind, MediaSecurityRecoveryComponentTransitionV1,
    MediaSecurityRecoveryDisposition, MediaSecurityRecoveryOutcome, MediaSourceKind,
    RecoverSecurityBlockedMediaV1, RegisterLocalPathMediaV1, RequestedLocalPathMediaKind,
    RetainHttpsMediaV1, RetainedHttpsMediaReceiptV1, SecurityRecoverySnapshot,
    SecurityRecoverySnapshotResult, SelectedMediaStream,
};
use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::external_journal::ExternalJournalError;
use crate::external_journal::fsguard::DirGuard;

fn open_optional_verified(root: &DirGuard, name: &str) -> Result<Option<File>> {
    match root.open_file_verified(name) {
        Ok(file) => Ok(Some(file)),
        Err(ExternalJournalError::CapsuleMissing(_)) => Ok(None),
        Err(error) => Err(anyhow::Error::new(error)
            .context("storage_security_violation while reopening publication object")),
    }
}

/// A borrowed source already opened by the local-path authority boundary.
/// Recovery never derives or reopens a caller path.
pub(crate) struct BorrowedSourceHandle {
    pub(crate) file: File,
    pub(crate) evidence_digest: String,
}

struct HeldHandleRecoveryProof {
    _handles: Vec<File>,
}

/// A DB-authorized component lease and the exact no-follow handle proven by
/// that acquisition transaction. Consumers never receive a storage name.
pub(crate) struct HeldMediaComponentLease {
    db: cockpit_db::Db,
    authority: AcquiredMediaComponentLease,
    file: File,
}

impl HeldMediaComponentLease {
    #[cfg(test)]
    pub(crate) fn authority(&self) -> &AcquiredMediaComponentLease {
        &self.authority
    }

    async fn block_after_failed_proof(&self, now_unix_ms: i64) -> Result<()> {
        block_component_lease_after_failed_proof(&self.db, self.authority.clone(), now_unix_ms)
            .await
    }

    /// Complete-read verification is deliberately coupled to durable release.
    /// Failure atomically blocks the aggregate/component and records evidence.
    pub(crate) async fn read_verified(mut self, now_unix_ms: i64) -> Result<Vec<u8>> {
        let proof = (|| -> Result<Vec<u8>> {
            let before = stable_identity_digest(&self.file)?;
            ensure!(
                before == self.authority.component.stable_identity_digest,
                "storage_security_violation"
            );
            self.file.seek(SeekFrom::Start(0))?;
            let mut bytes = Vec::new();
            Read::by_ref(&mut self.file)
                .take(self.authority.component.byte_length.saturating_add(1))
                .read_to_end(&mut bytes)?;
            ensure!(
                bytes.len() as u64 == self.authority.component.byte_length
                    && crate::intel::hex_lower(&Sha256::digest(&bytes))
                        == self.authority.component.sha256,
                "storage_security_violation"
            );
            ensure!(
                stable_identity_digest(&self.file)? == before,
                "storage_security_violation"
            );
            Ok(bytes)
        })();
        let bytes = match proof {
            Ok(bytes) => bytes,
            Err(error) => {
                self.block_after_failed_proof(now_unix_ms).await?;
                return Err(error);
            }
        };
        let lease_id = self.authority.lease_id;
        self.db
            .transaction(move |conn| {
                cockpit_db::Db::release_media_component_lease_conn(conn, lease_id, now_unix_ms)
            })
            .await?;
        Ok(bytes)
    }
}

async fn block_component_lease_after_failed_proof(
    db: &cockpit_db::Db,
    authority: AcquiredMediaComponentLease,
    now_unix_ms: i64,
) -> Result<()> {
    db.transaction(move |conn| {
        let next_attachment = authority.availability_generation.checked_add(1).context("availability generation overflow")?;
        let next_component = authority.component.component_generation.checked_add(1).context("component generation overflow")?;
        let changed = conn.execute("UPDATE media_attachments SET availability='security_blocked',availability_generation=?1,updated_at_unix_ms=?2 WHERE attachment_id=?3 AND attachment_version=?4 AND availability='ready' AND availability_generation=?5",params![next_attachment.to_string(),now_unix_ms,authority.attachment_id.to_string(),authority.attachment_version.to_string(),authority.availability_generation.to_string()])?;
        ensure!(changed == 1,"media security transition lost compare-and-swap");
        let changed = conn.execute("UPDATE media_attachment_components SET lifecycle_state='security_blocked',component_generation=?1,updated_at_unix_ms=?2 WHERE component_id=?3 AND component_generation=?4 AND lifecycle_state='ready'",params![next_component.to_string(),now_unix_ms,authority.component.component_id.to_string(),authority.component.component_generation.to_string()])?;
        ensure!(changed == 1,"media component security transition lost compare-and-swap");
        conn.execute("INSERT INTO media_attachment_transition_evidence(attachment_id,availability_generation,from_state,to_state,operation_id,committed_at_unix_ms) VALUES(?1,?2,'ready','security_blocked',?3,?4)",params![authority.attachment_id.to_string(),next_attachment.to_string(),authority.lease_id.to_string(),now_unix_ms])?;
        conn.execute("INSERT INTO media_component_security_evidence(lease_id,attachment_id,component_id,reason,recorded_at_unix_ms) VALUES(?1,?2,?3,'storage_security_violation',?4)",params![authority.lease_id.to_string(),authority.attachment_id.to_string(),authority.component.component_id.to_string(),now_unix_ms])?;
        cockpit_db::Db::release_media_component_lease_conn(conn,authority.lease_id,now_unix_ms)?;
        Ok(())
    }).await
}

#[derive(Clone)]
pub(crate) struct MediaStorageRecovery {
    db: cockpit_db::Db,
    owned_root: std::sync::Arc<DirGuard>,
    borrowed_sources:
        std::sync::Arc<std::sync::Mutex<std::collections::HashMap<Uuid, BorrowedSourceHandle>>>,
    av_runner: std::sync::Arc<dyn AvRuntimeRunner>,
    https_fetcher: std::sync::Arc<dyn crate::media_https::HttpsMediaFetcher>,
    #[cfg(test)]
    av_runtime_override: Option<ApprovedAvRuntime>,
    #[cfg(test)]
    fail_processing_output_proof: bool,
}

impl MediaStorageRecovery {
    async fn finish_retained_https_orphan(
        &self,
        operation_id: Uuid,
        storage_id: &str,
        now_unix_ms: i64,
    ) -> Result<()> {
        let proof = if let Some(mut file) = open_optional_verified(&self.owned_root, storage_id)? {
            let identity = stable_identity_digest(&file)?;
            let (length, checksum) = read_full_digest(&mut file)?;
            ensure!(
                stable_identity_digest(&file)? == identity,
                "storage_security_violation"
            );
            self.owned_root
                .remove_file(storage_id)
                .map_err(anyhow::Error::new)?;
            self.owned_root.sync().map_err(anyhow::Error::new)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt as _;
                ensure!(
                    file.metadata()?.nlink() == 0,
                    "retained HTTPS orphan was not deleted"
                );
            }
            (
                "verified_unlink",
                digest_json(
                    b"retained-https-orphan-unlink-v1",
                    &(storage_id, identity, length, checksum),
                )?,
            )
        } else {
            self.owned_root.sync().map_err(anyhow::Error::new)?;
            (
                "verified_absent_before_create",
                digest_json(b"retained-https-orphan-absent-v1", &storage_id)?,
            )
        };
        let operation = operation_id.to_string();
        let storage = storage_id.to_owned();
        self.db.transaction(move|conn|{
            conn.execute("INSERT OR IGNORE INTO media_retained_https_orphan_cleanup_evidence(local_operation_id,storage_id,evidence_digest,outcome,completed_at_unix_ms) VALUES(?1,?2,?3,?4,?5)",params![operation,storage,proof.1,proof.0,now_unix_ms])?;
            conn.execute("DELETE FROM media_retained_https_publication_intents WHERE local_operation_id=?1 AND storage_id=?2",params![operation,storage])?;
            Ok(())
        }).await
    }
    /// Claims and completes retained-HTTPS work through the same strict image
    /// or A/V preparation pipeline used by upload Finalize.
    pub(crate) async fn process_retained_https_jobs(&self, now_unix_ms: i64) -> Result<usize> {
        let reclaim_before = now_unix_ms.saturating_sub(300_000);
        let jobs=self.db.read(move|conn|{let mut statement=conn.prepare("SELECT j.job_id,j.attachment_id,j.expected_attachment_version,j.expected_availability_generation,j.source_evidence_digest,c.storage_id,c.stable_identity_digest,c.byte_length,c.sha256,c.reservation_id,j.state,a.media_kind FROM media_attachment_processing_jobs j JOIN media_attachments a ON a.attachment_id=j.attachment_id JOIN media_attachment_components c ON c.attachment_id=a.attachment_id AND c.component_kind='quarantined_original' WHERE (j.state='pending' OR (j.state='claimed' AND j.claimed_at_unix_ms<=?1)) AND a.source_kind='retained_https' ORDER BY j.created_at_unix_ms,j.job_id")?;statement.query_map([reclaim_before],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?,r.get::<_,String>(3)?,r.get::<_,String>(4)?,r.get::<_,String>(5)?,r.get::<_,String>(6)?,r.get::<_,String>(7)?,r.get::<_,String>(8)?,r.get::<_,String>(9)?,r.get::<_,String>(10)?,r.get::<_,String>(11)?)))?.collect::<std::result::Result<Vec<_>,_>>().map_err(Into::into)}).await?;
        let mut completed = 0;
        for (
            job,
            attachment,
            version,
            generation,
            source_evidence,
            storage,
            identity,
            length,
            checksum,
            reservation,
            prior_state,
            media_kind,
        ) in jobs
        {
            let job_id = Uuid::parse_str(&job)?;
            let attachment_id = Uuid::parse_str(&attachment)?;
            let expected_version = version.parse::<u64>()?;
            let expected_generation = generation.parse::<u64>()?;
            let claimed=self.db.transaction(move|conn|{let changed=conn.execute("UPDATE media_attachment_processing_jobs SET state='claimed',claimed_at_unix_ms=?1,claim_attempt=claim_attempt+1 WHERE job_id=?2 AND (state='pending' OR (state='claimed' AND claimed_at_unix_ms<=?3))",params![now_unix_ms,job_id.to_string(),reclaim_before])?;if changed==0{return Ok(false)}

            if prior_state=="pending"{cockpit_db::Db::transition_media_attachment_conn(conn,attachment_id,expected_version,expected_generation,MediaAvailability::Probing,now_unix_ms)?;conn.execute("INSERT INTO media_attachment_transition_evidence(attachment_id,availability_generation,from_state,to_state,operation_id,committed_at_unix_ms) VALUES(?1,?2,'quarantined','probing',?3,?4)",params![attachment_id.to_string(),(expected_generation+1).to_string(),job_id.to_string(),now_unix_ms])?;}Ok(true)}).await?;
            if !claimed {
                continue;
            }
            let requested_kind = media_kind_from_text(&media_kind)?;
            let source = (|| -> Result<_> {
                let mut held = self
                    .owned_root
                    .open_file_verified(&storage)
                    .map_err(anyhow::Error::new)?;
                ensure!(
                    stable_identity_digest(&held)? == identity,
                    "storage_security_violation"
                );
                let (actual_length, actual_checksum) = read_full_digest(&mut held)?;
                ensure!(
                    actual_length == length.parse::<u64>()?
                        && actual_checksum == checksum
                        && stable_identity_digest(&held)? == identity,
                    "storage_security_violation"
                );
                let (container, mime) = probe_upload_container(&mut held, requested_kind)?;
                held.seek(SeekFrom::Start(0))?;
                let mut bytes = Vec::new();
                held.read_to_end(&mut bytes)?;
                Ok((container.to_owned(), mime.to_owned(), bytes))
            })();
            let (container, mime, bytes) = match source {
                Ok(value) => value,
                Err(error) => {
                    if error.to_string().contains("storage_security_violation")
                        || error.downcast_ref::<ExternalJournalError>().is_some()
                    {
                        self.db.transaction(move|conn|{let(component_id,component_generation):(String,String)=conn.query_row("SELECT component_id,component_generation FROM media_attachment_components WHERE attachment_id=?1 AND component_kind='quarantined_original'",[attachment_id.to_string()],|r|Ok((r.get(0)?,r.get(1)?)))?;let blocked_generation=expected_generation.checked_add(2).context("availability generation overflow")?;cockpit_db::Db::transition_media_attachment_conn(conn,attachment_id,expected_version,expected_generation+1,MediaAvailability::SecurityBlocked,now_unix_ms)?;conn.execute("UPDATE media_attachment_components SET lifecycle_state='security_blocked',component_generation=?1,updated_at_unix_ms=?2 WHERE component_id=?3 AND component_generation=?4",params![(component_generation.parse::<u64>()?+1).to_string(),now_unix_ms,component_id,component_generation])?;conn.execute("INSERT INTO media_attachment_transition_evidence(attachment_id,availability_generation,from_state,to_state,operation_id,committed_at_unix_ms) VALUES(?1,?2,'probing','security_blocked',?3,?4)",params![attachment_id.to_string(),blocked_generation.to_string(),job_id.to_string(),now_unix_ms])?;conn.execute("INSERT INTO media_attachment_processing_security_evidence(job_id,attachment_id,component_id,reason,recorded_at_unix_ms) VALUES(?1,?2,?3,'storage_security_violation',?4)",params![job_id.to_string(),attachment_id.to_string(),component_id,now_unix_ms])?;conn.execute("UPDATE media_attachment_processing_jobs SET state='completed',completed_at_unix_ms=?1 WHERE job_id=?2",params![now_unix_ms,job_id.to_string()])?;Ok(())}).await?;
                        completed += 1;
                        continue;
                    }
                    let reason = closed_media_failure_reason(&error);
                    self.db.transaction(move|conn|{let failed_generation=expected_generation.checked_add(2).context("availability generation overflow")?;cockpit_db::Db::transition_media_attachment_conn(conn,attachment_id,expected_version,expected_generation+1,MediaAvailability::Failed,now_unix_ms)?;conn.execute("INSERT INTO media_attachment_transition_evidence(attachment_id,availability_generation,from_state,to_state,operation_id,committed_at_unix_ms) VALUES(?1,?2,'probing','failed',?3,?4)",params![attachment_id.to_string(),failed_generation.to_string(),job_id.to_string(),now_unix_ms])?;conn.execute("INSERT INTO media_attachment_failure_reasons(attachment_id,reason,recorded_at_unix_ms) VALUES(?1,?2,?3)",params![attachment_id.to_string(),reason,now_unix_ms])?;conn.execute("INSERT INTO media_attachment_processing_failure_evidence(job_id,attachment_id,reason,recorded_at_unix_ms) VALUES(?1,?2,'processing_failed',?3)",params![job_id.to_string(),attachment_id.to_string(),now_unix_ms])?;conn.execute("UPDATE media_attachment_processing_jobs SET state='completed',completed_at_unix_ms=?1 WHERE job_id=?2 AND state='claimed'",params![now_unix_ms,job_id.to_string()])?;Ok(())}).await?;
                    completed += 1;
                    continue;
                }
            };
            let (container, mime, outputs, av_evidence, terminal) =
                if requested_kind == MediaKind::Image {
                    let normalized = if bytes.len() <= 10 * 1024 * 1024 {
                        normalize_image(&bytes, &container).ok()
                    } else {
                        None
                    };
                    if let Some(normalized) = normalized {
                        (
                            container,
                            mime,
                            vec![
                                (
                                    "image_model",
                                    Uuid::now_v7(),
                                    normalized.model_png,
                                    Some((normalized.width, normalized.height)),
                                ),
                                (
                                    "browser_thumbnail",
                                    Uuid::now_v7(),
                                    normalized.thumbnail_png,
                                    Some((normalized.thumbnail_width, normalized.thumbnail_height)),
                                ),
                            ],
                            None,
                            None,
                        )
                    } else {
                        (
                            container,
                            mime,
                            Vec::new(),
                            None,
                            Some(MediaAvailability::Failed),
                        )
                    }
                } else {
                    let prepared = self
                        .prepare_av_normalization(AvNormalizationInput {
                            bytes,
                            initial_container: container,
                            initial_mime: mime,
                        })
                        .await;
                    (
                        prepared.canonical_container,
                        prepared.canonical_mime,
                        prepared.derivatives,
                        prepared.evidence,
                        prepared.terminal_availability,
                    )
                };
            if let Some(terminal) = terminal {
                let terminal_text = terminal.as_str().to_owned();
                self.db
                    .transaction(move |conn| {
                        let mut current_generation = expected_generation
                            .checked_add(1)
                            .context("availability generation overflow")?;
                        if terminal == MediaAvailability::ModelDerivativeUnavailable {
                            for (from, next) in [
                                ("probing", MediaAvailability::Decoding),
                                ("decoding", MediaAvailability::Normalizing),
                                ("normalizing", MediaAvailability::ModelDerivativeUnavailable),
                            ] {
                                cockpit_db::Db::transition_media_attachment_conn(
                                    conn,
                                    attachment_id,
                                    expected_version,
                                    current_generation,
                                    next,
                                    now_unix_ms,
                                )?;
                                current_generation = current_generation
                                    .checked_add(1)
                                    .context("availability generation overflow")?;
                                conn.execute(
                                    "INSERT INTO media_attachment_transition_evidence(attachment_id,availability_generation,from_state,to_state,operation_id,committed_at_unix_ms) VALUES(?1,?2,?3,?4,?5,?6)",
                                    params![attachment_id.to_string(),current_generation.to_string(),from,next.as_str(),job_id.to_string(),now_unix_ms],
                                )?;
                            }
                        } else {
                            cockpit_db::Db::transition_media_attachment_conn(
                                conn,
                                attachment_id,
                                expected_version,
                                current_generation,
                                terminal,
                                now_unix_ms,
                            )?;
                            current_generation = current_generation
                                .checked_add(1)
                                .context("availability generation overflow")?;
                            conn.execute(
                                "INSERT INTO media_attachment_transition_evidence(attachment_id,availability_generation,from_state,to_state,operation_id,committed_at_unix_ms) VALUES(?1,?2,'probing',?3,?4,?5)",
                                params![attachment_id.to_string(),current_generation.to_string(),terminal_text,job_id.to_string(),now_unix_ms],
                            )?;
                            conn.execute("INSERT INTO media_attachment_failure_reasons(attachment_id,reason,recorded_at_unix_ms) VALUES(?1,'normalization_failed',?2)",params![attachment_id.to_string(),now_unix_ms])?;
                        }
                        conn.execute("INSERT INTO media_attachment_processing_failure_evidence(job_id,attachment_id,reason,recorded_at_unix_ms) VALUES(?1,?2,?3,?4)",params![job_id.to_string(),attachment_id.to_string(),if terminal==MediaAvailability::ModelDerivativeUnavailable{"model_runtime_unavailable"}else{"processing_failed"},now_unix_ms])?;
                        conn.execute("UPDATE media_attachment_processing_jobs SET state='completed',completed_at_unix_ms=?1 WHERE job_id=?2 AND state='claimed'",params![now_unix_ms,job_id.to_string()])?;
                        Ok(())
                    })
                    .await?;
                completed += 1;
                continue;
            }
            let intent_outputs = serde_json::to_string(
                &outputs
                    .iter()
                    .map(|(_, id, _, _)| id.to_string())
                    .collect::<Vec<_>>(),
            )?;
            let intent_job = job_id.to_string();
            let security_outputs = intent_outputs.clone();
            self.db.transaction(move|conn|{conn.execute("INSERT OR IGNORE INTO media_attachment_processing_publication_intents(job_id,output_ids_json,created_at_unix_ms) VALUES(?1,?2,?3)",params![intent_job,intent_outputs,now_unix_ms])?;Ok(())}).await?;
            let mut components = Vec::new();
            let mut names = Vec::new();
            let output_proof = (|| -> Result<()> {
                #[cfg(test)]
                ensure!(
                    !self.fail_processing_output_proof,
                    "injected processing output proof failure"
                );
                for (kind, id, bytes, dimensions) in outputs {
                    let name = id.to_string();
                    let mut file = self
                        .owned_root
                        .create_file_exclusive(&name)
                        .map_err(anyhow::Error::new)?;
                    file.write_all(&bytes)?;
                    file.sync_all()?;
                    let output_identity = stable_identity_digest(&file)?;
                    let (output_length, output_checksum) = read_full_digest(&mut file)?;
                    ensure!(
                        output_length == bytes.len() as u64
                            && output_checksum == crate::intel::hex_lower(&Sha256::digest(&bytes))
                            && stable_identity_digest(&file)? == output_identity,
                        "storage_security_violation"
                    );
                    names.push(name);
                    components.push((
                        kind,
                        id,
                        output_identity,
                        output_length,
                        output_checksum,
                        dimensions,
                    ));
                }
                self.owned_root.sync().map_err(anyhow::Error::new)?;
                Ok(())
            })();
            if output_proof.is_err() {
                self.reconcile_media_uploads(now_unix_ms).await?;
                self.db.transaction(move|conn|{let blocked=expected_generation.checked_add(2).context("availability generation overflow")?;cockpit_db::Db::transition_media_attachment_conn(conn,attachment_id,expected_version,expected_generation+1,MediaAvailability::SecurityBlocked,now_unix_ms)?;conn.execute("INSERT INTO media_attachment_transition_evidence(attachment_id,availability_generation,from_state,to_state,operation_id,committed_at_unix_ms) VALUES(?1,?2,'probing','security_blocked',?3,?4)",params![attachment_id.to_string(),blocked.to_string(),job_id.to_string(),now_unix_ms])?;conn.execute("INSERT INTO media_attachment_processing_output_security_evidence(job_id,attachment_id,output_ids_json,reason,recorded_at_unix_ms) VALUES(?1,?2,?3,'storage_security_violation',?4)",params![job_id.to_string(),attachment_id.to_string(),security_outputs,now_unix_ms])?;conn.execute("UPDATE media_attachment_processing_jobs SET state='completed',completed_at_unix_ms=?1 WHERE job_id=?2",params![now_unix_ms,job_id.to_string()])?;Ok(())}).await?;
                completed += 1;
                continue;
            }
            let names_on_error = names.clone();
            let result=self.db.transaction(move|conn|{for(kind,id,identity,length,checksum,dimensions)in components{let component=cockpit_db::media_attachments::MediaAttachmentComponent{component_id:id,attachment_id,attachment_version:expected_version,component_kind:kind.into(),storage_id:id,lifecycle_state:"ready".into(),component_generation:1,stable_identity_digest:identity,byte_length:length,sha256:checksum,reservation_id:reservation.clone(),created_at_unix_ms:now_unix_ms,updated_at_unix_ms:now_unix_ms};cockpit_db::Db::insert_media_attachment_component_conn(conn,&component)?;if let Some((width,height))=dimensions{conn.execute("INSERT INTO media_image_component_dimensions(component_id,width,height) VALUES(?1,?2,?3)",params![id.to_string(),width,height])?;}}if let Some(evidence)=av_evidence{conn.execute("INSERT INTO media_av_normalization_evidence(attachment_id,runtime_fingerprint,probe_digest,decode_digest,plan_digest,derivative_checksum) VALUES(?1,?2,?3,?4,?5,?6)",params![attachment_id.to_string(),evidence.runtime_fingerprint,evidence.probe_digest,evidence.decode_digest,evidence.plan_digest,evidence.derivative_checksum])?;}conn.execute("UPDATE media_attachments SET canonical_container=?1,canonical_mime=?2 WHERE attachment_id=?3",params![container,mime,attachment_id.to_string()])?;let mut current=expected_generation+1;for next in[MediaAvailability::Decoding,MediaAvailability::Normalizing,MediaAvailability::Ready]{cockpit_db::Db::transition_media_attachment_conn(conn,attachment_id,expected_version,current,next,now_unix_ms)?;let after=current+1;conn.execute("INSERT INTO media_attachment_transition_evidence(attachment_id,availability_generation,from_state,to_state,operation_id,committed_at_unix_ms) VALUES(?1,?2,?3,?4,?5,?6)",params![attachment_id.to_string(),after.to_string(),if current==2{"probing"}else if current==3{"decoding"}else{"normalizing"},next.as_str(),job_id.to_string(),now_unix_ms])?;current=after;}conn.execute("UPDATE media_attachment_processing_jobs SET state='completed',completed_at_unix_ms=?1 WHERE job_id=?2 AND state='claimed' AND source_evidence_digest=?3",params![now_unix_ms,job_id.to_string(),source_evidence])?;conn.execute("DELETE FROM media_attachment_processing_publication_intents WHERE job_id=?1",[job_id.to_string()])?;Ok(())}).await;
            if let Err(error) = result {
                for name in names_on_error {
                    let _ = self.owned_root.remove_file(&name);
                }
                let _ = self.owned_root.sync();
                return Err(error);
            }
            completed += 1;
        }
        Ok(completed)
    }
    pub(crate) async fn retain_https_media(
        &self,
        request: RetainHttpsMediaV1,
        policy: &cockpit_config::config::media_budget::MediaResourcePolicy,
        monotonic_now_ms: u64,
        now_unix_ms: i64,
    ) -> Result<RetainedHttpsMediaReceiptV1> {
        ensure!(
            request.schema_version == 1 && request.kind == "retainHttpsMedia",
            "media_attachment_unavailable"
        );
        let binding = digest_json(b"retained-https-binding-v1", &request)?;
        let semantic_digest = digest_json(
            b"retained-https-semantic-v1",
            &(
                &request.owner_principal_digest,
                request.session_id,
                &request.canonical_project_digest,
                request.client_draft_id,
                request.requested_media_kind,
                &request.url,
            ),
        )?;
        let operation_id = request.local_operation_id.to_string();
        let binding_preflight = binding.clone();
        if let Some(receipt) = self.db.read(move |conn| {
            let row: Option<(String,String)> = conn.query_row("SELECT request_binding_digest,receipt_json FROM media_retained_https_operations WHERE local_operation_id=?1",[operation_id],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
            match row { Some((stored,json)) => { ensure!(stored == binding_preflight,"idempotency_conflict"); Ok(Some(serde_json::from_str(&json)?)) }, None => Ok(None) }
        }).await? { return Ok(receipt); }
        let alias_request = request.clone();
        let alias_binding = binding.clone();
        let alias_semantic = semantic_digest.clone();
        if let Some(receipt)=self.db.transaction(move|conn|{
            if let Some((authoritative,stored_semantic,json))=conn.query_row("SELECT authoritative_operation_id,semantic_command_digest,receipt_json FROM media_retained_https_operations WHERE session_id=?1 AND canonical_project_digest=?2 AND client_draft_id=?3 AND is_alias=0",params![alias_request.session_id.to_string(),alias_request.canonical_project_digest,alias_request.client_draft_id.to_string()],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?))).optional()? { ensure!(stored_semantic==alias_semantic,"idempotency_conflict"); conn.execute("INSERT INTO media_retained_https_operations(local_operation_id,authoritative_operation_id,session_id,canonical_project_digest,client_draft_id,request_binding_digest,operation_request_digest,semantic_command_digest,receipt_json,committed_at_unix_ms,is_alias) VALUES(?1,?2,?3,?4,?5,?6,?6,?7,?8,?9,1)",params![alias_request.local_operation_id.to_string(),authoritative,alias_request.session_id.to_string(),alias_request.canonical_project_digest,alias_request.client_draft_id.to_string(),alias_binding,alias_semantic,json,now_unix_ms])?; return Ok(Some(serde_json::from_str(&json)?)); } Ok(None)
        }).await? { return Ok(receipt); }

        let storage_id = Uuid::now_v7();
        let storage_name = storage_id.to_string();
        let intent_operation = request.local_operation_id.to_string();
        let intent_storage = storage_name.clone();
        self.db
            .transaction(move |conn| {
                conn.execute(
                    "INSERT INTO media_retained_https_publication_intents(local_operation_id,storage_id,created_at_unix_ms) VALUES(?1,?2,?3)",
                    params![intent_operation, intent_storage, now_unix_ms],
                )?;
                Ok(())
            })
            .await?;
        let mut held = self
            .owned_root
            .create_file_exclusive(&storage_name)
            .map_err(anyhow::Error::new)?;
        self.owned_root.sync().map_err(anyhow::Error::new)?;
        let async_file = tokio::fs::File::from_std(held.try_clone()?);
        let mut async_file = async_file;
        let fetch = self
            .https_fetcher
            .fetch(
                &request.url,
                &mut async_file,
                &crate::media_https::HttpsFetchLimits::default(),
            )
            .await;
        let fetch = match fetch {
            Ok(fetch) => fetch,
            Err(error) => {
                self.finish_retained_https_orphan(
                    request.local_operation_id,
                    &storage_name,
                    now_unix_ms,
                )
                .await?;
                let text = error.to_string();
                let reason = if text.contains("requires HTTPS")
                    || text.contains("userinfo")
                    || text.contains("fragment")
                    || text.contains("forbidden destination")
                    || text.contains("redirect")
                {
                    HttpsRetentionRejectionReasonV1::InvalidHttpsSource
                } else if text.contains("byte limit") || text.contains("empty retained") {
                    HttpsRetentionRejectionReasonV1::ResourceLimit
                } else {
                    HttpsRetentionRejectionReasonV1::SourceUnavailable
                };
                let rejected = RetainedHttpsMediaReceiptV1 {
                    schema_version: 1,
                    kind: "retainedHttpsMediaReceipt".into(),
                    receipt_id: Uuid::now_v7(),
                    local_operation_id: request.local_operation_id,
                    owner_principal_digest: request.owner_principal_digest.clone(),
                    session_id: request.session_id,
                    canonical_project_digest: request.canonical_project_digest.clone(),
                    client_draft_id: request.client_draft_id,
                    operation_request_digest: binding.clone(),
                    semantic_command_digest: semantic_digest.clone(),
                    origin_scheme: "https".into(),
                    redirect_location_classes: Vec::new(),
                    path_segment_count: 0,
                    safe_basename: None,
                    fetched_at_unix_ms: now_unix_ms,
                    result: HttpsRetentionResultV1::Rejected { reason },
                    committed_at_unix_ms: now_unix_ms,
                };
                let rejected_json = serde_json::to_string(&rejected)?;
                let rejected_request = request.clone();
                return self.db.transaction(move |conn| {
                    conn.execute("INSERT INTO media_retained_https_operations(local_operation_id,authoritative_operation_id,session_id,canonical_project_digest,client_draft_id,request_binding_digest,operation_request_digest,semantic_command_digest,receipt_json,committed_at_unix_ms,is_alias) VALUES(?1,?1,?2,?3,?4,?5,?5,?6,?7,?8,0)",params![rejected_request.local_operation_id.to_string(),rejected_request.session_id.to_string(),rejected_request.canonical_project_digest,rejected_request.client_draft_id.to_string(),binding,semantic_digest,rejected_json,now_unix_ms])?;
                    conn.execute("INSERT INTO media_retained_https_audit(local_operation_id,outcome,committed_at_unix_ms) VALUES(?1,'rejected',?2)",params![rejected_request.local_operation_id.to_string(),now_unix_ms])?;
                    Ok(rejected)
                }).await;
            }
        };
        async_file.sync_all().await?;
        drop(async_file);
        held.seek(SeekFrom::Start(0))?;
        let identity = stable_identity_digest(&held)?;
        let (reread_length, reread_checksum) = read_full_digest(&mut held)?;
        ensure!(
            reread_length == fetch.byte_length && reread_checksum == fetch.sha256,
            "storage_security_violation"
        );
        ensure!(
            stable_identity_digest(&held)? == identity,
            "storage_security_violation"
        );

        let attachment_id = Uuid::now_v7();
        let component_id = Uuid::now_v7();
        let receipt_id = Uuid::now_v7();
        let reservation_id = format!("retained-https:{attachment_id}");
        let plans = local_path_plans(policy, fetch.byte_length)?;
        let reservation_digest = digest_json(b"retained-https-reservation-v1", &plans)?;
        // Operation identity is request-only; fetched bytes belong exclusively
        // to source evidence and cannot alter replay classification.
        let request_digest = binding.clone();
        let source_evidence_digest = digest_json(
            b"retained-https-source-evidence-v1",
            &(
                &identity,
                fetch.byte_length,
                &fetch.sha256,
                &fetch.provenance,
            ),
        )?;
        let redirect_classes = fetch
            .provenance
            .redirect_classes
            .iter()
            .map(|class| match class {
                crate::media_https::RedirectLocationClass::SameOrigin => {
                    HttpsRedirectLocationClassV1::SameOrigin
                }
                crate::media_https::RedirectLocationClass::CrossOrigin => {
                    HttpsRedirectLocationClassV1::CrossOrigin
                }
            })
            .collect::<Vec<_>>();
        let path_segment_count = fetch.provenance.path_segment_count;
        let safe_basename = fetch.provenance.safe_basename.clone();
        let media_kind = match request.requested_media_kind {
            RequestedLocalPathMediaKind::Image => MediaKind::Image,
            RequestedLocalPathMediaKind::Audio => MediaKind::Audio,
            RequestedLocalPathMediaKind::Video => MediaKind::Video,
        };
        let record = MediaAttachmentRecord {
            attachment_id,
            session_id: request.session_id,
            canonical_project_digest: request.canonical_project_digest.clone(),
            media_kind,
            source_kind: MediaSourceKind::RetainedHttps,
            canonical_container: "application/octet-stream".into(),
            canonical_mime: "application/octet-stream".into(),
            availability: MediaAvailability::Quarantined,
            attachment_version: 1,
            availability_generation: 1,
            reference_generation: 1,
            captured_capability_generation: 1,
            source_identity_digest: identity.clone(),
            source_byte_length: fetch.byte_length,
            source_sha256: fetch.sha256.clone(),
            selected_video_stream: None,
            selected_audio_stream: None,
            created_at_unix_ms: now_unix_ms,
            updated_at_unix_ms: now_unix_ms,
            draft_expires_at_unix_ms: None,
            first_referenced_at_unix_ms: None,
        };
        let component = cockpit_db::media_attachments::MediaAttachmentComponent {
            component_id,
            attachment_id,
            attachment_version: 1,
            component_kind: "quarantined_original".into(),
            storage_id,
            lifecycle_state: "ready".into(),
            component_generation: 1,
            stable_identity_digest: identity,
            byte_length: fetch.byte_length,
            sha256: fetch.sha256,
            reservation_id: reservation_id.clone(),
            created_at_unix_ms: now_unix_ms,
            updated_at_unix_ms: now_unix_ms,
        };
        let receipt = RetainedHttpsMediaReceiptV1 {
            schema_version: 1,
            kind: "retainedHttpsMediaReceipt".into(),
            receipt_id,
            local_operation_id: request.local_operation_id,
            owner_principal_digest: request.owner_principal_digest.clone(),
            session_id: request.session_id,
            canonical_project_digest: request.canonical_project_digest.clone(),
            client_draft_id: request.client_draft_id,
            operation_request_digest: request_digest.clone(),
            semantic_command_digest: semantic_digest.clone(),
            origin_scheme: "https".into(),
            redirect_location_classes: redirect_classes.clone(),
            path_segment_count,
            safe_basename: safe_basename.clone(),
            fetched_at_unix_ms: now_unix_ms,
            result: HttpsRetentionResultV1::Retained {
                attachment_id,
                attachment_version: 1,
                availability_state: "quarantined".into(),
                availability_generation: 1,
                reference_generation: 1,
                reservation_id: reservation_id.clone(),
                reservation_digest: reservation_digest.clone(),
                source_evidence_digest: source_evidence_digest.clone(),
            },
            committed_at_unix_ms: now_unix_ms,
        };
        let receipt_json = serde_json::to_string(&receipt)?;
        let request_for_tx = request.clone();
        let result=self.db.transaction(move|conn|{
            if let Some((authoritative,stored_semantic,json))=conn.query_row("SELECT authoritative_operation_id,semantic_command_digest,receipt_json FROM media_retained_https_operations WHERE session_id=?1 AND canonical_project_digest=?2 AND client_draft_id=?3 AND is_alias=0",params![request_for_tx.session_id.to_string(),request_for_tx.canonical_project_digest,request_for_tx.client_draft_id.to_string()],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?))).optional()? { ensure!(stored_semantic==semantic_digest,"idempotency_conflict"); conn.execute("INSERT INTO media_retained_https_operations(local_operation_id,authoritative_operation_id,session_id,canonical_project_digest,client_draft_id,request_binding_digest,operation_request_digest,semantic_command_digest,receipt_json,committed_at_unix_ms,is_alias) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,1)",params![request_for_tx.local_operation_id.to_string(),authoritative,request_for_tx.session_id.to_string(),request_for_tx.canonical_project_digest,request_for_tx.client_draft_id.to_string(),binding,request_digest,semantic_digest,json,now_unix_ms])?; return Ok(serde_json::from_str(&json)?); }
            crate::media_reservation::reserve_conn(conn,crate::media_reservation::ReserveRequest{reservation_id:reservation_id.clone(),recovery_id:reservation_id.clone(),owner:crate::media_reservation::MediaOwner{project_id:request_for_tx.canonical_project_digest.clone(),session_id:request_for_tx.session_id.to_string()},operation:"retained_https_ingest".into(),purpose:"retained_media".into(),plans,wall_ms:u64::try_from(now_unix_ms)?},monotonic_now_ms)?;
            cockpit_db::Db::insert_media_attachment_conn(conn,&record)?; cockpit_db::Db::insert_media_attachment_component_conn(conn,&component)?;
            conn.execute("INSERT INTO media_retained_https_evidence(attachment_id,source_evidence_digest,redirect_classes_json,path_segment_count,safe_basename,fetched_at_unix_ms,reservation_id,reservation_digest) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",params![attachment_id.to_string(),source_evidence_digest,serde_json::to_string(&redirect_classes)?,path_segment_count,safe_basename,now_unix_ms,reservation_id,reservation_digest])?;
            conn.execute("INSERT INTO media_attachment_processing_jobs(job_id,attachment_id,expected_attachment_version,expected_availability_generation,source_evidence_digest,state,created_at_unix_ms) VALUES(?1,?2,'1','1',?3,'pending',?4)",params![Uuid::now_v7().to_string(),attachment_id.to_string(),source_evidence_digest,now_unix_ms])?;
            conn.execute("INSERT INTO media_retained_https_operations(local_operation_id,authoritative_operation_id,session_id,canonical_project_digest,client_draft_id,request_binding_digest,operation_request_digest,semantic_command_digest,receipt_json,committed_at_unix_ms,is_alias) VALUES(?1,?1,?2,?3,?4,?5,?6,?7,?8,?9,0)",params![request_for_tx.local_operation_id.to_string(),request_for_tx.session_id.to_string(),request_for_tx.canonical_project_digest,request_for_tx.client_draft_id.to_string(),binding,request_digest,semantic_digest,receipt_json,now_unix_ms])?;
            conn.execute("INSERT INTO media_retained_https_audit(local_operation_id,outcome,committed_at_unix_ms) VALUES(?1,'retained',?2)",params![request_for_tx.local_operation_id.to_string(),now_unix_ms])?; conn.execute("DELETE FROM media_retained_https_publication_intents WHERE local_operation_id=?1",[request_for_tx.local_operation_id.to_string()])?; Ok(receipt)
        }).await;
        if result.as_ref().is_err() || result.as_ref().is_ok_and(|r| r.receipt_id != receipt_id) {
            if result.is_ok() {
                self.finish_retained_https_orphan(
                    request.local_operation_id,
                    &storage_name,
                    now_unix_ms,
                )
                .await?;
            }
        }
        result
    }
    pub(crate) async fn discard_media_attachment(
        &self,
        mutation: cockpit_db::media_attachments::LocalMediaMutationV1,
        now_unix_ms: i64,
    ) -> Result<cockpit_db::media_attachments::LocalMediaMutationReceiptV1> {
        use cockpit_db::media_attachments::*;
        let LocalMediaMutationPayloadV1::Discard {
            session_id,
            canonical_project_digest,
            attachment_id,
            attachment_version,
            availability_generation,
            reference_generation,
            origin_upload,
        } = &mutation.payload
        else {
            anyhow::bail!("local media action mismatch")
        };
        let request = DiscardUnreferencedMediaAttachmentV1 {
            schema_version: 1,
            kind: "discardUnreferencedMediaAttachment".into(),
            attachment_id: *attachment_id,
            attachment_version: *attachment_version,
            availability_generation: *availability_generation,
            reference_generation: *reference_generation,
            origin_upload: origin_upload.clone(),
        };
        let domain = format!(
            "discard:{session_id}:{canonical_project_digest}:{attachment_id}:{attachment_version}:{availability_generation}:{reference_generation}"
        );
        let (request_digest, semantic_digest) =
            cockpit_db::Db::local_media_mutation_digests(&mutation)?;
        let mutation_for_tx = mutation.clone();
        let project = canonical_project_digest.clone();
        let session = *session_id;
        self.db
            .transaction(move |conn| {
                cockpit_db::Db::media_attachment_for_owner_conn(
                    conn,
                    request.attachment_id,
                    session,
                    &project,
                )?
                .context("media_attachment_unavailable")?;
                if let Some(receipt) = preflight_local_operation(
                    conn,
                    mutation_for_tx.local_operation_id,
                    "discard",
                    &domain,
                    &request_digest,
                    &semantic_digest,
                    now_unix_ms,
                )? {
                    return Ok(receipt);
                }
                let decision = cockpit_db::Db::discard_unreferenced_media_attachment_conn(
                    conn,
                    &request,
                    now_unix_ms,
                )?;
                let result = MediaDiscardResultV1::Local {
                    schema_version: 1,
                    kind: "mediaDiscardResult".into(),
                    result_id: Uuid::now_v7(),
                    local_operation_id: mutation_for_tx.local_operation_id,
                    operation_request_digest: request_digest.clone(),
                    semantic_command_digest: semantic_digest.clone(),
                    attachment_id: decision.attachment_id,
                    requested_attachment_version: request.attachment_version,
                    attachment_version_before: decision.attachment_version_before,
                    requested_availability_generation: request.availability_generation,
                    availability_generation_before: decision.availability_generation_before,
                    availability_generation_after: decision.availability_generation_after,
                    requested_reference_generation: request.reference_generation,
                    reference_generation_before: decision.reference_generation_before,
                    reference_generation_after: decision.reference_generation_after,
                    outcome: decision.outcome,
                    reason: decision.reason,
                };
                let result_digest = crate::intel::hex_lower(&Sha256::digest(result.encode_fcdr()?));
                let receipt = LocalMediaMutationReceiptV1 {
                    schema_version: 1,
                    kind: "localMediaMutationReceipt".into(),
                    receipt_id: Uuid::now_v7(),
                    local_operation_id: mutation_for_tx.local_operation_id,
                    actor_principal_digest: mutation_for_tx.actor_principal_digest,
                    action: "discard".into(),
                    subject_kind: LocalMediaSubjectKindV1::Attachment,
                    subject_id: request.attachment_id,
                    operation_request_digest: request_digest.clone(),
                    semantic_command_digest: semantic_digest.clone(),
                    outcome: if decision.outcome == MediaDiscardOutcomeV1::Applied {
                        LocalMediaMutationOutcomeV1::Applied
                    } else {
                        LocalMediaMutationOutcomeV1::Rejected
                    },
                    transition: LocalMediaMutationTransitionV1::Attachment {
                        generation_before: decision.availability_generation_before,
                        generation_after: decision.availability_generation_after,
                        reference_generation_before: decision.reference_generation_before,
                        reference_generation_after: decision.reference_generation_after,
                    },
                    discard_result: Some(result),
                    discard_result_digest: Some(result_digest),
                    committed_at_unix_ms: now_unix_ms,
                };
                commit_local_operation(
                    conn,
                    &receipt,
                    "discard",
                    &domain,
                    &request_digest,
                    &semantic_digest,
                    now_unix_ms,
                )?;
                Ok(receipt)
            })
            .await
    }
    pub(crate) async fn acquire_message_images_bound(
        &self,
        attachment_ids: Vec<Uuid>,
        session_id: Uuid,
        project_digest: String,
        consumer_id: String,
        ledger: &crate::media_reservation::MediaReservationLedger,
        max_total_bytes: u64,
        now_unix_ms: i64,
    ) -> Result<Vec<Vec<u8>>> {
        use cockpit_db::media_attachments::{
            AcquiredMediaReference, MediaComponentLeaseKind, MediaKind, MediaReferenceConsumerKind,
        };
        ensure!(!attachment_ids.is_empty(), "media_attachment_unavailable");
        let db_consumer_id = consumer_id.clone();
        let acquired = self
            .db
            .transaction(move |conn| {
                let mut rows = Vec::with_capacity(attachment_ids.len());
                let mut total_bytes = 0u64;
                for attachment_id in attachment_ids {
                    let record = cockpit_db::Db::media_attachment_for_owner_conn(
                        conn,
                        attachment_id,
                        session_id,
                        &project_digest,
                    )?
                    .context("media_attachment_unavailable")?;
                    ensure!(
                        record.media_kind == MediaKind::Image && record.availability.is_ready(),
                        "media_attachment_unavailable"
                    );
                    let reference = cockpit_db::Db::acquire_media_reference_conn(
                        conn,
                        cockpit_db::media_attachments::AcquireMediaReferenceInput {
                            reference_id: Uuid::now_v7(),
                            attachment_id,
                            expected_version: record.attachment_version,
                            session_id,
                            project_digest: &project_digest,
                            consumer_kind: MediaReferenceConsumerKind::Message,
                            consumer_id: &db_consumer_id,
                            now_unix_ms,
                        },
                    )?;
                    let authority = cockpit_db::Db::acquire_media_component_lease_conn(
                        conn,
                        cockpit_db::media_attachments::AcquireMediaComponentLeaseInput {
                            lease_id: Uuid::now_v7(),
                            attachment_id,
                            expected_version: record.attachment_version,
                            expected_availability_generation: record.availability_generation,
                            expected_capability_generation: record.captured_capability_generation,
                            kind: MediaComponentLeaseKind::Model,
                            now_unix_ms,
                        },
                    )?;
                    total_bytes = total_bytes
                        .checked_add(authority.component.byte_length)
                        .context("media_attachment_unavailable")?;
                    ensure!(
                        total_bytes <= max_total_bytes,
                        "media_attachment_unavailable"
                    );
                    rows.push((reference, authority));
                }
                Ok(rows)
            })
            .await?;
        let reservations = acquired
            .iter()
            .map(|(_, authority)| authority.component.reservation_id.clone())
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        if let Err(error) = ledger
            .bind_downstream_ownership(reservations, &consumer_id, u64::try_from(now_unix_ms)?)
            .await
        {
            let compensation = acquired
                .iter()
                .map(|(reference, authority)| (reference.clone(), authority.lease_id))
                .collect::<Vec<(AcquiredMediaReference, Uuid)>>();
            self.db.transaction(move |conn| {
                for (reference, lease_id) in compensation {
                    conn.execute("UPDATE media_attachment_component_leases SET released_at_unix_ms=?1 WHERE lease_id=?2 AND released_at_unix_ms IS NULL", params![now_unix_ms, lease_id.to_string()])?;
                    if reference.inserted {
                        conn.execute("DELETE FROM media_attachment_references WHERE reference_id=?1 AND released_at_unix_ms IS NULL", [reference.reference_id.to_string()])?;
                    }
                }
                Ok(())
            }).await?;
            return Err(anyhow::anyhow!(error.to_string()).context("media_attachment_unavailable"));
        }
        let inserted_references = acquired
            .iter()
            .filter_map(|(reference, _)| reference.inserted.then_some(reference.clone()))
            .collect::<Vec<_>>();
        let mut pending = std::collections::VecDeque::from(acquired);
        let mut images = Vec::with_capacity(pending.len());
        while let Some((_, authority)) = pending.pop_front() {
            let opened = (|| -> Result<File> {
                let mut file = self
                    .owned_root
                    .open_file_verified(&authority.component.storage_id.to_string())
                    .map_err(anyhow::Error::new)?;
                let before = stable_identity_digest(&file)?;
                let (length, checksum) = read_full_digest(&mut file)?;
                ensure!(
                    before == authority.component.stable_identity_digest
                        && length == authority.component.byte_length
                        && checksum == authority.component.sha256
                        && stable_identity_digest(&file)? == before,
                    "storage_security_violation"
                );
                file.seek(SeekFrom::Start(0))?;
                Ok(file)
            })();
            let file = match opened {
                Ok(file) => file,
                Err(error) => {
                    block_component_lease_after_failed_proof(&self.db, authority, now_unix_ms)
                        .await?;
                    self.compensate_failed_message_claim(
                        ledger,
                        &consumer_id,
                        &inserted_references,
                        pending
                            .iter()
                            .map(|(_, authority)| authority.lease_id)
                            .collect(),
                        now_unix_ms,
                    )
                    .await?;
                    return Err(error);
                }
            };
            let read = HeldMediaComponentLease {
                db: self.db.clone(),
                authority,
                file,
            }
            .read_verified(now_unix_ms)
            .await;
            match read {
                Ok(bytes) => images.push(bytes),
                Err(error) => {
                    self.compensate_failed_message_claim(
                        ledger,
                        &consumer_id,
                        &inserted_references,
                        pending
                            .iter()
                            .map(|(_, authority)| authority.lease_id)
                            .collect(),
                        now_unix_ms,
                    )
                    .await?;
                    return Err(error);
                }
            }
        }
        Ok(images)
    }

    async fn compensate_failed_message_claim(
        &self,
        ledger: &crate::media_reservation::MediaReservationLedger,
        consumer_id: &str,
        references: &[cockpit_db::media_attachments::AcquiredMediaReference],
        unread_leases: Vec<Uuid>,
        now_unix_ms: i64,
    ) -> Result<()> {
        ledger.return_downstream_ownership(consumer_id).await?;
        let references = references.to_vec();
        self.db.transaction(move |conn| {
            for lease in unread_leases {
                conn.execute("UPDATE media_attachment_component_leases SET released_at_unix_ms=?1 WHERE lease_id=?2 AND released_at_unix_ms IS NULL",params![now_unix_ms,lease.to_string()])?;
            }
            for reference in references {
                cockpit_db::Db::release_media_reference_conn(conn,reference.reference_id,reference.reference_generation,now_unix_ms)?;
            }
            Ok(())
        }).await
    }
    pub(crate) async fn ingest_message_image(
        &self,
        actor_principal_digest: String,
        session_id: Uuid,
        project_digest: String,
        bytes: Vec<u8>,
        policy: &cockpit_config::config::media_budget::MediaResourcePolicy,
        now_unix_ms: i64,
        now_monotonic_ms: u64,
    ) -> Result<Uuid> {
        use base64::Engine as _;
        use cockpit_db::media_attachments::{
            AppendMediaUploadChunkV1, LocalMediaActorRoleV1, LocalMediaMutationPayloadV1,
            LocalMediaMutationV1,
        };
        ensure!(
            !bytes.is_empty() && bytes.len() <= u32::MAX as usize,
            "media_attachment_unavailable"
        );
        let draft = Uuid::now_v7();
        let length = bytes.len() as u64;
        let checksum = crate::intel::hex_lower(&Sha256::digest(&bytes));
        let begin = LocalMediaMutationV1 {
            schema_version: 1,
            kind: "localMediaMutation".into(),
            local_operation_id: Uuid::now_v7(),
            actor_principal_digest: actor_principal_digest.clone(),
            actor_role: LocalMediaActorRoleV1::Owner,
            payload: LocalMediaMutationPayloadV1::Begin {
                session_id,
                canonical_project_digest: project_digest.clone(),
                client_draft_id: draft,
                media_kind: RequestedLocalPathMediaKind::Image,
                declared_total_bytes: length,
                reservation_digest: digest_json(
                    b"media-upload-reservation-v1",
                    &local_path_plans(policy, length)?,
                )?,
            },
        };
        let upload = self
            .begin_media_upload(begin, policy, now_monotonic_ms, now_unix_ms)
            .await?
            .subject_id;
        self.append_media_upload_chunk(
            AppendMediaUploadChunkV1 {
                mutation: LocalMediaMutationV1 {
                    schema_version: 1,
                    kind: "localMediaMutation".into(),
                    local_operation_id: Uuid::now_v7(),
                    actor_principal_digest: actor_principal_digest.clone(),
                    actor_role: LocalMediaActorRoleV1::Owner,
                    payload: LocalMediaMutationPayloadV1::Append {
                        session_id,
                        canonical_project_digest: project_digest.clone(),
                        client_draft_id: draft,
                        upload_id: upload,
                        upload_generation: 1,
                        chunk_index: 0,
                        chunk_length: bytes.len() as u32,
                        chunk_sha256: checksum.clone(),
                    },
                },
                data_base64: base64::engine::general_purpose::STANDARD.encode(bytes),
            },
            now_unix_ms,
        )
        .await?;
        self.finalize_media_upload(
            LocalMediaMutationV1 {
                schema_version: 1,
                kind: "localMediaMutation".into(),
                local_operation_id: Uuid::now_v7(),
                actor_principal_digest,
                actor_role: LocalMediaActorRoleV1::Owner,
                payload: LocalMediaMutationPayloadV1::Finalize {
                    session_id,
                    canonical_project_digest: project_digest,
                    client_draft_id: draft,
                    upload_id: upload,
                    upload_generation: 2,
                    chunk_count: 1,
                    total_bytes: length,
                    object_sha256: checksum,
                },
            },
            now_unix_ms,
        )
        .await?;
        self.db.read(move |conn| {
            let id: String = conn.query_row("SELECT attachment_id FROM media_uploads WHERE upload_id=?1 AND state='materialized'", [upload.to_string()], |row| row.get(0))?;
            Uuid::parse_str(&id).context("invalid materialized attachment id")
        }).await
    }
    async fn block_cleanup_security_ambiguity(
        &self,
        attachment_id: String,
        component_id: String,
        now_unix_ms: i64,
    ) -> Result<()> {
        self.db.transaction(move|conn|{let (availability,generation):(String,String)=conn.query_row("SELECT availability,availability_generation FROM media_attachments WHERE attachment_id=?1",[&attachment_id],|row|Ok((row.get(0)?,row.get(1)?)))?;if availability=="security_blocked"{return Ok(());}ensure!(matches!(availability.as_str(),"owned_cleanup_pending"|"borrowed_cleanup_pending"),"cleanup security transition requires pending state");let next=generation.parse::<u64>()?.checked_add(1).context("availability generation overflow")?.to_string();ensure!(conn.execute("UPDATE media_attachments SET availability='security_blocked',availability_generation=?1,updated_at_unix_ms=?2 WHERE attachment_id=?3 AND availability_generation=?4",params![next,now_unix_ms,attachment_id,generation])?==1,"cleanup security aggregate CAS failed");let component_generation:String=conn.query_row("SELECT component_generation FROM media_attachment_components WHERE component_id=?1",[&component_id],|row|row.get(0))?;let component_next=component_generation.parse::<u64>()?.checked_add(1).context("component generation overflow")?.to_string();ensure!(conn.execute("UPDATE media_attachment_components SET lifecycle_state='security_blocked',component_generation=?1,updated_at_unix_ms=?2 WHERE component_id=?3 AND component_generation=?4 AND lifecycle_state='cleanup_pending'",params![component_next,now_unix_ms,component_id,component_generation])?==1,"cleanup security component CAS failed");conn.execute("INSERT INTO media_cleanup_security_evidence(component_id,attachment_id,reason,recorded_at_unix_ms) VALUES(?1,?2,'storage_security_violation',?3)",params![component_id,attachment_id,now_unix_ms])?;conn.execute("INSERT INTO media_attachment_transition_evidence(attachment_id,availability_generation,from_state,to_state,operation_id,committed_at_unix_ms) VALUES(?1,?2,?3,'security_blocked',?4,?5)",params![attachment_id,next,availability,Uuid::now_v7().to_string(),now_unix_ms])?;Ok(())}).await
    }

    /// Starts every due 24-hour orphan-draft or 30-day completed-session
    /// cleanup with one writer CAS. Files are untouched until the exact
    /// component-set intent is durable.
    pub(crate) async fn begin_due_retention(&self, now_unix_ms: i64) -> Result<usize> {
        const COMPLETED_SESSION_RETENTION_MS: i64 = 30 * 24 * 60 * 60 * 1_000;
        self.db.transaction(move |conn| {
            let candidates={let mut statement=conn.prepare("SELECT a.attachment_id,a.attachment_version,a.availability_generation,a.reference_generation,a.source_kind,a.availability,CASE WHEN a.draft_expires_at_unix_ms IS NOT NULL AND a.first_referenced_at_unix_ms IS NULL AND a.draft_expires_at_unix_ms<=?1 THEN 'draft_expired' ELSE 'session_retention' END FROM media_attachments a JOIN sessions s ON s.session_id=a.session_id WHERE a.availability IN ('registered','quarantined','probing','decoding','normalizing','ready','model_derivative_unavailable','source_changed','failed') AND NOT EXISTS(SELECT 1 FROM media_attachment_cleanup_intents i WHERE i.attachment_id=a.attachment_id) AND NOT EXISTS(SELECT 1 FROM media_attachment_references r WHERE r.attachment_id=a.attachment_id AND r.released_at_unix_ms IS NULL) AND NOT EXISTS(SELECT 1 FROM media_attachment_component_leases l WHERE l.attachment_id=a.attachment_id AND l.released_at_unix_ms IS NULL) AND ((a.draft_expires_at_unix_ms IS NOT NULL AND a.first_referenced_at_unix_ms IS NULL AND a.draft_expires_at_unix_ms<=?1) OR (s.ended_at IS NOT NULL AND ?1>=s.ended_at*1000+?2)) ORDER BY a.attachment_id")?;statement.query_map(params![now_unix_ms,COMPLETED_SESSION_RETENTION_MS],|row|Ok((row.get::<_,String>(0)?,row.get::<_,String>(1)?,row.get::<_,String>(2)?,row.get::<_,String>(3)?,row.get::<_,String>(4)?,row.get::<_,String>(5)?,row.get::<_,String>(6)?)))?.collect::<std::result::Result<Vec<_>,_>>()?};
            let mut started=0;
            for (attachment,version,generation,reference_generation,source_kind,from_state,reason) in candidates {
                let components={let mut statement=conn.prepare("SELECT component_id,component_kind,component_generation FROM media_attachment_components WHERE attachment_id=?1 AND lifecycle_state<>'deleted' ORDER BY component_id")?;statement.query_map([&attachment],|row|Ok((row.get::<_,String>(0)?,row.get::<_,String>(1)?,row.get::<_,String>(2)?)))?.collect::<std::result::Result<Vec<_>,_>>()?};
                let mut hasher=Sha256::new();hasher.update(b"media-cleanup-component-set-v1\0");for (id,kind,component_generation) in &components {hasher.update(id.as_bytes());hasher.update([0]);hasher.update(kind.as_bytes());hasher.update([0]);hasher.update(component_generation.as_bytes());hasher.update([0]);}let set_digest=crate::intel::hex_lower(&hasher.finalize());
                let generation_number=generation.parse::<u64>()?;let next=generation_number.checked_add(1).context("availability generation overflow")?.to_string();
                let pending=if source_kind=="local_path"{"borrowed_cleanup_pending"}else{"owned_cleanup_pending"};
                let changed=conn.execute("UPDATE media_attachments SET availability=?1,availability_generation=?2,updated_at_unix_ms=?3 WHERE attachment_id=?4 AND availability_generation=?5 AND availability NOT IN ('security_blocked','owned_cleanup_pending','borrowed_cleanup_pending')",params![pending,next,now_unix_ms,attachment,generation])?;
                ensure!(changed==1,"retention cleanup lost compare-and-swap");
                for (component_id,_,component_generation) in &components {let component_next=component_generation.parse::<u64>()?.checked_add(1).context("component generation overflow")?.to_string();ensure!(conn.execute("UPDATE media_attachment_components SET lifecycle_state='cleanup_pending',component_generation=?1,updated_at_unix_ms=?2 WHERE component_id=?3 AND component_generation=?4 AND lifecycle_state<>'deleted'",params![component_next,now_unix_ms,component_id,component_generation])?==1,"retention component cleanup lost compare-and-swap");}
                conn.execute("INSERT INTO media_attachment_cleanup_intents(intent_id,attachment_id,attachment_version,expected_availability_generation,expected_reference_generation,component_set_digest,reason,created_at_unix_ms) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",params![Uuid::now_v7().to_string(),attachment,version,next,reference_generation,set_digest,reason,now_unix_ms])?;
                conn.execute("INSERT INTO media_attachment_transition_evidence(attachment_id,availability_generation,from_state,to_state,operation_id,committed_at_unix_ms) VALUES(?1,?2,?3,?4,?5,?6)",params![attachment,next,from_state,pending,Uuid::now_v7().to_string(),now_unix_ms])?;
                started+=1;
            }
            Ok(started)
        }).await
    }

    pub(crate) async fn begin_session_deletion_cleanup(
        &self,
        session_id: Uuid,
        now_unix_ms: i64,
    ) -> Result<usize> {
        self.db.transaction(move|conn|{let candidates={let mut statement=conn.prepare("WITH RECURSIVE subtree(session_id) AS (SELECT ?1 UNION ALL SELECT s.session_id FROM sessions s JOIN subtree p ON s.parent_session_id=p.session_id) SELECT a.attachment_id,a.attachment_version,a.availability_generation,a.reference_generation,a.source_kind,a.availability FROM media_attachments a JOIN subtree t ON t.session_id=a.session_id WHERE a.availability IN ('registered','quarantined','probing','decoding','normalizing','ready','model_derivative_unavailable','source_changed','failed') AND NOT EXISTS(SELECT 1 FROM media_attachment_cleanup_intents i WHERE i.attachment_id=a.attachment_id) AND NOT EXISTS(SELECT 1 FROM media_attachment_references r WHERE r.attachment_id=a.attachment_id AND r.released_at_unix_ms IS NULL) AND NOT EXISTS(SELECT 1 FROM media_attachment_component_leases l WHERE l.attachment_id=a.attachment_id AND l.released_at_unix_ms IS NULL) ORDER BY a.attachment_id")?;statement.query_map([session_id.to_string()],|row|Ok((row.get::<_,String>(0)?,row.get::<_,String>(1)?,row.get::<_,String>(2)?,row.get::<_,String>(3)?,row.get::<_,String>(4)?,row.get::<_,String>(5)?)))?.collect::<std::result::Result<Vec<_>,_>>()?};let mut started=0;for(attachment,version,generation,reference_generation,source_kind,from_state)in candidates{let components={let mut statement=conn.prepare("SELECT component_id,component_kind,component_generation FROM media_attachment_components WHERE attachment_id=?1 AND lifecycle_state<>'deleted' ORDER BY component_id")?;statement.query_map([&attachment],|row|Ok((row.get::<_,String>(0)?,row.get::<_,String>(1)?,row.get::<_,String>(2)?)))?.collect::<std::result::Result<Vec<_>,_>>()?};let mut hasher=Sha256::new();hasher.update(b"media-cleanup-component-set-v1\0");for(id,kind,component_generation)in&components{hasher.update(id.as_bytes());hasher.update([0]);hasher.update(kind.as_bytes());hasher.update([0]);hasher.update(component_generation.as_bytes());hasher.update([0]);}let set_digest=crate::intel::hex_lower(&hasher.finalize());let next=generation.parse::<u64>()?.checked_add(1).context("availability generation overflow")?.to_string();let pending=if source_kind=="local_path"{"borrowed_cleanup_pending"}else{"owned_cleanup_pending"};ensure!(conn.execute("UPDATE media_attachments SET availability=?1,availability_generation=?2,updated_at_unix_ms=?3 WHERE attachment_id=?4 AND availability_generation=?5",params![pending,next,now_unix_ms,attachment,generation])?==1,"session deletion cleanup lost compare-and-swap");for(component_id,_,component_generation)in&components{let component_next=component_generation.parse::<u64>()?.checked_add(1).context("component generation overflow")?.to_string();ensure!(conn.execute("UPDATE media_attachment_components SET lifecycle_state='cleanup_pending',component_generation=?1,updated_at_unix_ms=?2 WHERE component_id=?3 AND component_generation=?4 AND lifecycle_state<>'deleted'",params![component_next,now_unix_ms,component_id,component_generation])?==1,"session deletion component cleanup lost compare-and-swap");}conn.execute("INSERT INTO media_attachment_cleanup_intents(intent_id,attachment_id,attachment_version,expected_availability_generation,expected_reference_generation,component_set_digest,reason,created_at_unix_ms) VALUES(?1,?2,?3,?4,?5,?6,'session_deleted',?7)",params![Uuid::now_v7().to_string(),attachment,version,next,reference_generation,set_digest,now_unix_ms])?;conn.execute("INSERT INTO media_attachment_transition_evidence(attachment_id,availability_generation,from_state,to_state,operation_id,committed_at_unix_ms) VALUES(?1,?2,?3,?4,?5,?6)",params![attachment,next,from_state,pending,Uuid::now_v7().to_string(),now_unix_ms])?;started+=1;}Ok(started)}).await
    }

    /// Resume every durable cleanup intent component-by-component. Capacity is
    /// intentionally not released here unless the central reservation ledger
    /// can consume the committed deletion evidence in the same transaction.
    pub(crate) async fn reconcile_media_cleanup_intents(&self, now_unix_ms: i64) -> Result<usize> {
        let rows=self.db.read(|conn|{let mut statement=conn.prepare("SELECT c.component_id,c.attachment_id,c.storage_id,c.stable_identity_digest,c.byte_length,c.sha256 FROM media_attachment_components c JOIN media_attachment_cleanup_intents i ON i.attachment_id=c.attachment_id WHERE i.completed_at_unix_ms IS NULL AND c.lifecycle_state='cleanup_pending' ORDER BY c.attachment_id,c.component_id")?;statement.query_map([],|row|Ok((row.get::<_,String>(0)?,row.get::<_,String>(1)?,row.get::<_,String>(2)?,row.get::<_,String>(3)?,row.get::<_,String>(4)?,row.get::<_,String>(5)?)))?.collect::<std::result::Result<Vec<_>,_>>().map_err(Into::into)}).await?;
        let mut completed = 0usize;
        for (component_id, attachment_id, storage_id, identity, length, checksum) in rows {
            let length = length.parse::<u64>()?;
            let mut intent_hasher = Sha256::new();
            intent_hasher.update(b"media-component-delete-intent-v1\0");
            for value in [
                &component_id,
                &attachment_id,
                &storage_id,
                &identity,
                &length.to_string(),
                &checksum,
            ] {
                intent_hasher.update(value.as_bytes());
                intent_hasher.update([0]);
            }
            let intent_digest = crate::intel::hex_lower(&intent_hasher.finalize());
            let existing_intent=self.db.read({let component_id=component_id.clone();move|conn|conn.query_row("SELECT intent_digest FROM media_component_deletion_intents WHERE component_id=?1",[component_id],|row|row.get::<_,String>(0)).optional().map_err(Into::into)}).await?;
            if !existing_intent
                .as_ref()
                .is_none_or(|stored| stored == &intent_digest)
            {
                self.block_cleanup_security_ambiguity(
                    attachment_id.clone(),
                    component_id.clone(),
                    now_unix_ms,
                )
                .await?;
                anyhow::bail!("storage_security_violation");
            }
            let opened = self.owned_root.open_file_verified(&storage_id);
            let deletion_kind = match opened {
                Ok(mut file) => {
                    let proof = (|| -> Result<()> {
                        let before = stable_identity_digest(&file)?;
                        let (actual_length, actual_checksum) = read_full_digest(&mut file)?;
                        ensure!(
                            before == identity
                                && actual_length == length
                                && actual_checksum == checksum
                                && stable_identity_digest(&file)? == before,
                            "storage_security_violation"
                        );
                        Ok(())
                    })();
                    if let Err(error) = proof {
                        self.block_cleanup_security_ambiguity(
                            attachment_id.clone(),
                            component_id.clone(),
                            now_unix_ms,
                        )
                        .await?;
                        return Err(error);
                    }
                    if existing_intent.is_none() {
                        let component = component_id.clone();
                        let attachment = attachment_id.clone();
                        let storage = storage_id.clone();
                        let identity = identity.clone();
                        let checksum = checksum.clone();
                        let digest = intent_digest.clone();
                        self.db.transaction(move|conn|{conn.execute("INSERT INTO media_component_deletion_intents(component_id,attachment_id,storage_id,stable_identity_digest,byte_length,sha256,intent_digest,created_at_unix_ms) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",params![component,attachment,storage,identity,length.to_string(),checksum,digest,now_unix_ms])?;Ok(())}).await?;
                    }
                    if let Err(error) = self.owned_root.remove_file(&storage_id) {
                        self.block_cleanup_security_ambiguity(
                            attachment_id.clone(),
                            component_id.clone(),
                            now_unix_ms,
                        )
                        .await?;
                        return Err(anyhow::Error::new(error)
                            .context("storage_security_violation during media cleanup"));
                    }
                    if let Err(error) = self.owned_root.sync() {
                        self.block_cleanup_security_ambiguity(
                            attachment_id.clone(),
                            component_id.clone(),
                            now_unix_ms,
                        )
                        .await?;
                        return Err(anyhow::Error::new(error)
                            .context("storage_security_violation during media cleanup"));
                    }
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::MetadataExt as _;
                        if file.metadata()?.nlink() != 0 {
                            self.block_cleanup_security_ambiguity(
                                attachment_id.clone(),
                                component_id.clone(),
                                now_unix_ms,
                            )
                            .await?;
                            anyhow::bail!("storage_security_violation");
                        }
                    }
                    "verified_unlink"
                }
                Err(ExternalJournalError::CapsuleMissing(_))
                    if existing_intent.as_deref() == Some(intent_digest.as_str()) =>
                {
                    "interrupted_unlink_reconciled"
                }
                Err(error) => {
                    self.block_cleanup_security_ambiguity(
                        attachment_id.clone(),
                        component_id.clone(),
                        now_unix_ms,
                    )
                    .await?;
                    return Err(anyhow::Error::new(error)
                        .context("storage_security_violation during media cleanup"));
                }
            };
            let mut evidence_hasher = Sha256::new();
            evidence_hasher.update(b"media-component-deletion-evidence-v1\0");
            evidence_hasher.update(intent_digest.as_bytes());
            evidence_hasher.update([0]);
            evidence_hasher.update(deletion_kind.as_bytes());
            let evidence = crate::intel::hex_lower(&evidence_hasher.finalize());
            let component = component_id.clone();
            let attachment = attachment_id.clone();
            let intent = intent_digest.clone();
            self.db.transaction(move|conn|{conn.execute("INSERT INTO media_component_deletion_evidence(component_id,attachment_id,intent_digest,deletion_evidence_digest,deletion_kind,committed_at_unix_ms) VALUES(?1,?2,?3,?4,?5,?6) ON CONFLICT(component_id) DO NOTHING",params![component,attachment,intent,evidence,deletion_kind,now_unix_ms])?;ensure!(conn.execute("UPDATE media_attachment_components SET lifecycle_state='deleted',deletion_evidence_digest=?1,updated_at_unix_ms=?2 WHERE component_id=?3 AND lifecycle_state='cleanup_pending'",params![evidence,now_unix_ms,component_id])?==1,"cleanup component tombstone lost compare-and-swap");Ok(())}).await?;
            completed += 1;
        }
        let attachments=self.db.read(|conn|{let mut statement=conn.prepare("SELECT a.attachment_id,a.source_kind,a.availability_generation FROM media_attachments a JOIN media_attachment_cleanup_intents i ON i.attachment_id=a.attachment_id WHERE i.completed_at_unix_ms IS NULL AND a.availability IN ('owned_cleanup_pending','borrowed_cleanup_pending') AND NOT EXISTS(SELECT 1 FROM media_attachment_components c WHERE c.attachment_id=a.attachment_id AND c.lifecycle_state<>'deleted') ORDER BY a.attachment_id")?;statement.query_map([],|row|Ok((row.get::<_,String>(0)?,row.get::<_,String>(1)?,row.get::<_,String>(2)?)))?.collect::<std::result::Result<Vec<_>,_>>().map_err(Into::into)}).await?;
        for (attachment, source, generation) in attachments {
            self.db.transaction(move|conn|{let evidence={let mut statement=conn.prepare("SELECT c.reservation_id,e.deletion_evidence_digest FROM media_attachment_components c LEFT JOIN media_component_deletion_evidence e ON e.component_id=c.component_id WHERE c.attachment_id=?1 ORDER BY c.component_id")?;statement.query_map([&attachment],|row|Ok((row.get::<_,String>(0)?,row.get::<_,Option<String>>(1)?)))?.collect::<std::result::Result<Vec<_>,_>>()?};ensure!(evidence.iter().all(|(_,digest)|digest.is_some()),"verified component deletion evidence missing");let mut hasher=Sha256::new();hasher.update(b"media-attachment-cleanup-evidence-v1\0");for (_,digest) in &evidence{hasher.update(digest.as_deref().unwrap_or_default().as_bytes());hasher.update([0]);}let cleanup_digest=crate::intel::hex_lower(&hasher.finalize());let reservations=evidence.iter().map(|(id,_)|id).collect::<std::collections::BTreeSet<_>>();for reservation in reservations{crate::media_reservation::destroy_verified_media_artifacts_conn(conn,reservation,&cleanup_digest,u64::try_from(now_unix_ms)?)?;}let next=generation.parse::<u64>()?.checked_add(1).context("availability generation overflow")?.to_string();let terminal=if source=="local_path"{"borrowed_derivatives_deleted"}else{"retained_copy_deleted"};ensure!(conn.execute("UPDATE media_attachments SET availability=?1,availability_generation=?2,updated_at_unix_ms=?3,draft_expires_at_unix_ms=NULL WHERE attachment_id=?4 AND availability_generation=?5",params![terminal,next,now_unix_ms,attachment,generation])?==1,"cleanup terminal lost compare-and-swap");conn.execute("UPDATE media_attachment_cleanup_intents SET completed_at_unix_ms=?1 WHERE attachment_id=?2 AND completed_at_unix_ms IS NULL",params![now_unix_ms,attachment])?;Ok(())}).await?;
        }
        Ok(completed)
    }

    /// Process-local handles cannot survive daemon restart. Boot records that
    /// fact before releasing every leftover durable lease, and must call this
    /// before exposing any media request handler.
    pub(crate) async fn reconcile_abandoned_component_leases(
        &self,
        now_unix_ms: i64,
    ) -> Result<usize> {
        self.db
            .transaction(move |conn| {
                let lease_ids = {
                    let mut statement = conn.prepare(
                        "SELECT lease_id FROM media_attachment_component_leases WHERE released_at_unix_ms IS NULL ORDER BY lease_id",
                    )?;
                    statement
                        .query_map([], |row| row.get::<_, String>(0))?
                        .collect::<std::result::Result<Vec<_>, _>>()?
                };
                for lease_id in &lease_ids {
                    conn.execute(
                        "INSERT INTO media_component_lease_reconciliation_evidence(lease_id,reason,released_at_unix_ms) VALUES(?1,'daemon_restart',?2)",
                        params![lease_id, now_unix_ms],
                    )?;
                    conn.execute(
                        "UPDATE media_attachment_component_leases SET released_at_unix_ms=?1 WHERE lease_id=?2 AND released_at_unix_ms IS NULL",
                        params![now_unix_ms, lease_id],
                    )?;
                }
                Ok(lease_ids.len())
            })
            .await
    }

    pub(crate) async fn acquire_component_lease(
        &self,
        lease_id: Uuid,
        attachment_id: Uuid,
        attachment_version: u64,
        availability_generation: u64,
        capability_generation: u64,
        kind: MediaComponentLeaseKind,
        now_unix_ms: i64,
    ) -> Result<HeldMediaComponentLease> {
        let authority = self
            .db
            .transaction(move |conn| {
                cockpit_db::Db::acquire_media_component_lease_conn(
                    conn,
                    cockpit_db::media_attachments::AcquireMediaComponentLeaseInput {
                        lease_id,
                        attachment_id,
                        expected_version: attachment_version,
                        expected_availability_generation: availability_generation,
                        expected_capability_generation: capability_generation,
                        kind,
                        now_unix_ms,
                    },
                )
            })
            .await?;
        let opened = (|| -> Result<File> {
            let name = authority.component.storage_id.to_string();
            let mut file = self
                .owned_root
                .open_file_verified(&name)
                .map_err(anyhow::Error::new)?;
            let before = stable_identity_digest(&file)?;
            let (length, checksum) = read_full_digest(&mut file)?;
            ensure!(
                before == authority.component.stable_identity_digest
                    && length == authority.component.byte_length
                    && checksum == authority.component.sha256
                    && stable_identity_digest(&file)? == before,
                "storage_security_violation"
            );
            file.seek(SeekFrom::Start(0))?;
            Ok(file)
        })();
        let file = match opened {
            Ok(file) => file,
            Err(error) => {
                block_component_lease_after_failed_proof(&self.db, authority, now_unix_ms).await?;
                return Err(error);
            }
        };
        Ok(HeldMediaComponentLease {
            db: self.db.clone(),
            authority,
            file,
        })
    }

    /// Reconcile durable upload rows against the held storage root before the
    /// daemon accepts upload traffic. Appends may have reached the file but
    /// not SQLite, so a longer temporary is safely truncated to the durable
    /// offset. Missing/short temporaries fail closed; expired drafts are
    /// securely removed and release their reservation in the same commit.
    pub(crate) async fn reconcile_media_uploads(&self, now_unix_ms: i64) -> Result<usize> {
        use cockpit_db::media_attachments::{
            MediaUploadLastTransitionV1, MediaUploadSystemActionV1, RemoteMediaOperationOutcomeV1,
        };
        let mut repaired = 0usize;
        let processing_intents=self.db.read(|conn|{let mut statement=conn.prepare("SELECT job_id,output_ids_json FROM media_attachment_processing_publication_intents ORDER BY created_at_unix_ms,job_id")?;statement.query_map([],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?)))?.collect::<std::result::Result<Vec<_>,_>>().map_err(Into::into)}).await?;
        for (job, outputs_json) in processing_intents {
            let outputs: Vec<String> = serde_json::from_str(&outputs_json)?;
            let mut hasher = Sha256::new();
            hasher.update(b"media-processing-orphan-cleanup-v1\0");
            for output in &outputs {
                if let Some(file) = open_optional_verified(&self.owned_root, output)? {
                    self.owned_root
                        .remove_file(output)
                        .map_err(anyhow::Error::new)?;
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::MetadataExt as _;
                        ensure!(
                            file.metadata()?.nlink() == 0,
                            "processing orphan was not deleted"
                        );
                    }
                }
                hasher.update(output.as_bytes());
                hasher.update([0]);
            }
            self.owned_root.sync().map_err(anyhow::Error::new)?;
            let evidence = crate::intel::hex_lower(&hasher.finalize());
            self.db.transaction(move|conn|{conn.execute("INSERT OR IGNORE INTO media_attachment_processing_cleanup_evidence(job_id,evidence_digest,completed_at_unix_ms) VALUES(?1,?2,?3)",params![job,evidence,now_unix_ms])?;conn.execute("DELETE FROM media_attachment_processing_publication_intents WHERE job_id=?1",[job])?;Ok(())}).await?;
            repaired += 1;
        }
        let https_intents = self.db.read(|conn| {
            let mut statement=conn.prepare("SELECT local_operation_id,storage_id FROM media_retained_https_publication_intents ORDER BY created_at_unix_ms,local_operation_id")?;
            statement.query_map([],|row|Ok((row.get::<_,String>(0)?,row.get::<_,String>(1)?)))?.collect::<std::result::Result<Vec<_>,_>>().map_err(Into::into)
        }).await?;
        for (operation_id, storage_id) in https_intents {
            self.finish_retained_https_orphan(
                Uuid::parse_str(&operation_id)?,
                &storage_id,
                now_unix_ms,
            )
            .await?;
            repaired += 1;
        }
        let publication_intents=self.db.read(|conn|{let mut statement=conn.prepare("SELECT upload_id,temporary_storage_id,quarantine_storage_id,derivative_storage_ids_json FROM media_storage_publication_intents ORDER BY created_at_unix_ms,upload_id")?;let rows=statement.query_map([],|row|Ok((row.get::<_,String>(0)?,row.get::<_,String>(1)?,row.get::<_,String>(2)?,row.get::<_,String>(3)?)))?;rows.collect::<std::result::Result<Vec<_>,_>>().map_err(Into::into)}).await?;
        for (upload_id, temporary, quarantine, derivative_json) in publication_intents {
            let derivatives: Vec<String> = serde_json::from_str(&derivative_json)?;
            for derivative in derivatives {
                if let Some(file) = open_optional_verified(&self.owned_root, &derivative)? {
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
            let temporary_exists = open_optional_verified(&self.owned_root, &temporary)?.is_some();
            if open_optional_verified(&self.owned_root, &quarantine)?.is_some() {
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
                if let Some(file) = open_optional_verified(&self.owned_root, &storage_id)? {
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

    async fn prepare_av_normalization(
        &self,
        input: AvNormalizationInput,
    ) -> PreparedAvNormalization {
        let mut canonical_container = input.initial_container;
        let mut canonical_mime = input.initial_mime;
        let media_kind = MediaKind::Audio;
        let mut held = std::io::Cursor::new(input.bytes);
        let mut selected_video_stream = None;
        let mut selected_audio_stream = None;
        let mut av_terminal = None;
        let mut av_normalization_evidence = None;
        let av_derivatives = if media_kind != MediaKind::Image {
            let prepared: Result<(
                Vec<(&'static str, Uuid, Vec<u8>, Option<(u32, u32)>)>,
                Option<SelectedMediaStream>,
                Option<SelectedMediaStream>,
                AvNormalizationEvidence,
            )> = async {
                held.seek(SeekFrom::Start(0))?;
                let mut bytes = Vec::new();
                held.read_to_end(&mut bytes)?;
                let runtime = self.resolve_av_runtime()?;
                let (document, probe_digest) =
                    run_bounded_ffprobe(&runtime, self.av_runner.as_ref(), bytes.clone()).await?;
                let streams = document
                    .streams
                    .iter()
                    .map(|stream| AvProbeStream {
                        index: stream.index,
                        kind: if stream.codec_type == "audio" {
                            "audio"
                        } else if stream.codec_type == "video" {
                            "video"
                        } else {
                            "other"
                        },
                        codec: stream.codec_name.clone(),
                        default_disposition: stream
                            .disposition
                            .as_ref()
                            .is_some_and(|value| value.default == 1),
                    })
                    .collect::<Vec<_>>();
                if canonical_container == "iso_bmff" {
                    canonical_container = classify_iso_bmff(
                        &bytes,
                        streams.iter().any(|stream| stream.kind == "video"),
                        usize::from(streams.iter().any(|stream| stream.kind == "audio")),
                    )?
                    .into();
                    canonical_mime = match canonical_container.as_str() {
                        "m4a" => "audio/mp4",
                        "mov" => "video/quicktime",
                        _ => "video/mp4",
                    }
                    .into();
                }
                let (video, audio) = select_av_streams(&canonical_container, &streams)?;
                let decode_digest = decode_selected_streams(
                    &runtime,
                    self.av_runner.as_ref(),
                    bytes.clone(),
                    video.as_ref().map(|value| value.index),
                    audio.as_ref().map(|value| value.index),
                )
                .await?;
                let selected_audio = audio.as_ref().map(|value| SelectedMediaStream {
                    index: value.index,
                    codec: value.codec.clone(),
                });
                let selected_video = video.as_ref().map(|value| SelectedMediaStream {
                    index: value.index,
                    codec: value.codec.clone(),
                });
                if let Some(video) = video {
                    let probe = document
                        .streams
                        .iter()
                        .find(|stream| stream.index == video.index)
                        .context("invalid_media")?;
                    let (sar_num, sar_den) = probe
                        .sample_aspect_ratio
                        .as_deref()
                        .map(parse_positive_ratio)
                        .transpose()?
                        .unwrap_or((1, 1));
                    let (oriented_width, oriented_height) = oriented_video_dimensions(probe)?;
                    let rotated = (oriented_width, oriented_height)
                        != (
                            probe.width.context("invalid_media")?,
                            probe.height.context("invalid_media")?,
                        );
                    let (sar_num, sar_den) = if rotated {
                        (sar_den, sar_num)
                    } else {
                        (sar_num, sar_den)
                    };
                    let (width, height) =
                        select_video_dimensions(oriented_width, oriented_height, sar_num, sar_den)?;
                    let timestamps = selected_video_timestamps(&document, probe)?;
                    let source_frame_count = timestamps.len();
                    let (fps_num, fps_den, gop, min_keyint) = select_video_rate(&timestamps)?;
                    let audio_settings = audio
                        .as_ref()
                        .map(|selected| {
                            let stream = document
                                .streams
                                .iter()
                                .find(|stream| stream.index == selected.index)
                                .context("invalid_media")?;
                            Ok::<(u32, u32), anyhow::Error>((
                                stream
                                    .sample_rate
                                    .as_deref()
                                    .context("invalid_media")?
                                    .parse::<u32>()?,
                                stream.channels.context("invalid_media")?,
                            ))
                        })
                        .transpose()?;
                    verify_required_video_encoders(
                        &runtime,
                        self.av_runner.as_ref(),
                        audio.is_some(),
                    )
                    .await?;
                    let argv = video_normalization_argv(
                        video.index,
                        audio.as_ref().map(|value| value.index),
                        audio_settings,
                        width,
                        height,
                        fps_num,
                        fps_den,
                        gop,
                        min_keyint,
                    )?;
                    let plan_digest = av_plan_digest(&runtime.fingerprint, &argv);
                    let mp4 =
                        run_video_normalization(&runtime, self.av_runner.as_ref(), argv, bytes)
                            .await?;
                    verify_canonical_video_mp4(&mp4)?;
                    let (encoded, _) =
                        run_bounded_ffprobe(&runtime, self.av_runner.as_ref(), mp4.clone()).await?;
                    verify_encoded_video_provenance(
                        &encoded,
                        width,
                        height,
                        (fps_num, fps_den),
                        source_frame_count,
                        gop,
                        audio.is_some(),
                    )?;
                    let derivative_checksum = crate::intel::hex_lower(&Sha256::digest(&mp4));
                    Ok((
                        vec![("video_model", Uuid::now_v7(), mp4, Some((width, height)))],
                        selected_video,
                        selected_audio,
                        AvNormalizationEvidence {
                            runtime_fingerprint: runtime.fingerprint,
                            probe_digest,
                            decode_digest,
                            plan_digest,
                            derivative_checksum,
                        },
                    ))
                } else {
                    let audio = audio.context("invalid_media")?;
                    let probe = document
                        .streams
                        .iter()
                        .find(|stream| stream.index == audio.index)
                        .context("invalid_media")?;
                    let rate = probe
                        .sample_rate
                        .as_deref()
                        .context("invalid_media")?
                        .parse::<u32>()?;
                    let channels = probe.channels.context("invalid_media")?;
                    let argv = audio_normalization_argv(audio.index, rate, channels)?;
                    let plan_digest = av_plan_digest(&runtime.fingerprint, &argv);
                    let output = self
                        .av_runner
                        .run(
                            &runtime.ffmpeg,
                            &argv,
                            bytes,
                            100 * 1024 * 1024,
                            std::time::Duration::from_secs(120),
                        )
                        .await?;
                    let wav = canonicalize_pcm_wav(&output.stdout)?;
                    let derivative_checksum = crate::intel::hex_lower(&Sha256::digest(&wav));
                    Ok((
                        vec![("audio_model", Uuid::now_v7(), wav, None)],
                        None,
                        selected_audio,
                        AvNormalizationEvidence {
                            runtime_fingerprint: runtime.fingerprint,
                            probe_digest,
                            decode_digest,
                            plan_digest,
                            derivative_checksum,
                        },
                    ))
                }
            }
            .await;
            match prepared {
                Ok((derivatives, video, audio, evidence)) => {
                    selected_video_stream = video;
                    selected_audio_stream = audio;
                    av_normalization_evidence = Some(evidence);
                    Some(derivatives)
                }
                Err(error) => {
                    av_terminal = Some(if error.to_string().contains("model_runtime") {
                        MediaAvailability::ModelDerivativeUnavailable
                    } else {
                        MediaAvailability::Failed
                    });
                    None
                }
            }
        } else {
            None
        };
        PreparedAvNormalization {
            canonical_container,
            canonical_mime,
            selected_video_stream,
            selected_audio_stream,
            derivatives: av_derivatives.unwrap_or_default(),
            terminal_availability: av_terminal,
            evidence: av_normalization_evidence,
        }
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
        let (container_signature, mime_signature) =
            probe_upload_container(&mut held, media_kind_from_text(&snapshot.6)?)?;
        let canonical_container = container_signature.to_owned();
        let canonical_mime = mime_signature.to_owned();
        let media_kind = media_kind_from_text(&snapshot.6)?;
        let normalized = if media_kind == MediaKind::Image {
            held.seek(SeekFrom::Start(0))?;
            let mut bytes = Vec::new();
            Read::by_ref(&mut held)
                .take(10 * 1024 * 1024 + 1)
                .read_to_end(&mut bytes)?;
            ensure!(bytes.len() <= 10 * 1024 * 1024, "resource_limit");
            Some(normalize_image(&bytes, &canonical_container)?)
        } else {
            None
        };
        let prepared_av = if media_kind != MediaKind::Image {
            held.seek(SeekFrom::Start(0))?;
            let mut bytes = Vec::new();
            held.read_to_end(&mut bytes)?;
            Some(
                self.prepare_av_normalization(AvNormalizationInput {
                    bytes,
                    initial_container: canonical_container.clone(),
                    initial_mime: canonical_mime.clone(),
                })
                .await,
            )
        } else {
            None
        };
        let (
            canonical_container,
            canonical_mime,
            selected_video_stream,
            selected_audio_stream,
            av_derivatives,
            av_terminal,
            av_normalization_evidence,
        ) = match prepared_av {
            Some(prepared) => (
                prepared.canonical_container,
                prepared.canonical_mime,
                prepared.selected_video_stream,
                prepared.selected_audio_stream,
                Some(prepared.derivatives),
                prepared.terminal_availability,
                prepared.evidence,
            ),
            None => (
                canonical_container,
                canonical_mime,
                None,
                None,
                None,
                None,
                None,
            ),
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
                        Some((normalized.width, normalized.height)),
                    ),
                    (
                        "browser_thumbnail",
                        Uuid::now_v7(),
                        normalized.thumbnail_png,
                        Some((normalized.thumbnail_width, normalized.thumbnail_height)),
                    ),
                ]
            })
            .map_or_else(|| av_derivatives.unwrap_or_default(), |value| value);
        let intent_upload = upload.to_string();
        let intent_temporary = snapshot.0.clone();
        let intent_target = target.clone();
        let intent_derivatives = serde_json::to_string(
            &planned_derivatives
                .iter()
                .map(|(_, id, _, _)| id.to_string())
                .collect::<Vec<_>>(),
        )?;
        self.db.transaction(move|conn|{conn.execute("INSERT INTO media_storage_publication_intents(upload_id,temporary_storage_id,quarantine_storage_id,derivative_storage_ids_json,created_at_unix_ms) VALUES(?1,?2,?3,?4,?5)",params![intent_upload,intent_temporary,intent_target,intent_derivatives,now_unix_ms])?;Ok(())}).await?;
        if let Err(error) =
            self.owned_root
                .rename_into_noreplace(&snapshot.0, &self.owned_root, &target)
        {
            self.reconcile_media_uploads(now_unix_ms).await?;
            return Err(anyhow::Error::new(error));
        }
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
                for (kind, derivative_storage, bytes, dimensions) in planned_derivatives {
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
                        dimensions,
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
            canonical_container,
            canonical_mime,
            availability: MediaAvailability::Quarantined,
            attachment_version: 1,
            availability_generation: 1,
            reference_generation: 1,
            captured_capability_generation: 1,
            source_identity_digest: before.clone(),
            source_byte_length: total,
            source_sha256: actual_sha.clone(),
            selected_video_stream,
            selected_audio_stream,
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
        let processed = ready || av_terminal.is_some();
        let final_availability = av_terminal.unwrap_or(MediaAvailability::Ready);
        let reservation_id = snapshot.5.clone();
        let transition_operation_id = mutation.local_operation_id;
        let result=self.db.transaction(move|conn|{if let Some(receipt)=preflight_local_operation(conn,mutation.local_operation_id,"finalize",&domain,&request_digest,&semantic_digest,now_unix_ms)?{return Ok((receipt,false))}cockpit_db::Db::insert_media_attachment_conn(conn,&record)?;cockpit_db::Db::insert_media_attachment_component_conn(conn,&component_record)?;if ready {for (kind,storage,identity,length,checksum,dimensions) in derivative_components {let id=Uuid::now_v7();let component=MediaAttachmentComponent{component_id:id,attachment_id:attachment,attachment_version:1,component_kind:kind,storage_id:storage,lifecycle_state:"ready".into(),component_generation:1,stable_identity_digest:identity,byte_length:length,sha256:checksum,reservation_id:reservation_id.clone(),created_at_unix_ms:now_unix_ms,updated_at_unix_ms:now_unix_ms};cockpit_db::Db::insert_media_attachment_component_conn(conn,&component)?;if let Some((width,height))=dimensions{conn.execute("INSERT INTO media_image_component_dimensions(component_id,width,height) VALUES(?1,?2,?3)",params![id.to_string(),width,height])?;}}}

        if let Some(evidence)=av_normalization_evidence{conn.execute("INSERT INTO media_av_normalization_evidence(attachment_id,runtime_fingerprint,probe_digest,decode_digest,plan_digest,derivative_checksum) VALUES(?1,?2,?3,?4,?5,?6)",params![attachment.to_string(),evidence.runtime_fingerprint,evidence.probe_digest,evidence.decode_digest,evidence.plan_digest,evidence.derivative_checksum])?;}

        if final_availability==MediaAvailability::Failed{conn.execute("INSERT INTO media_attachment_failure_reasons(attachment_id,reason,recorded_at_unix_ms) VALUES(?1,'normalization_failed',?2)",params![attachment.to_string(),now_unix_ms])?;}

        if processed{let mut availability=MediaAvailability::Quarantined;let mut available_generation=1;for next_state in [MediaAvailability::Probing,MediaAvailability::Decoding,MediaAvailability::Normalizing,final_availability]{cockpit_db::Db::transition_media_attachment_conn(conn,attachment,1,available_generation,next_state,now_unix_ms)?;let next_generation=available_generation.checked_add(1).context("availability generation overflow")?;conn.execute("INSERT INTO media_attachment_transition_evidence(attachment_id,availability_generation,from_state,to_state,operation_id,committed_at_unix_ms) VALUES(?1,?2,?3,?4,?5,?6)",params![attachment.to_string(),next_generation.to_string(),availability.as_str(),next_state.as_str(),transition_operation_id.to_string(),now_unix_ms])?;availability=next_state;available_generation=next_generation;}ensure!(availability==final_availability,"media terminal transition failed");}conn.execute("INSERT INTO media_attachment_upload_origins(attachment_id,client_draft_id,upload_id,upload_generation) VALUES(?1,?2,?3,?4)",params![attachment.to_string(),draft.to_string(),upload.to_string(),next.to_string()])?;let changed=conn.execute("UPDATE media_uploads SET state='materialized',upload_generation=?1,next_chunk_index=NULL,attachment_id=?2,attachment_version='1',last_transition_json=?3,updated_at_unix_ms=?4 WHERE upload_id=?5 AND upload_generation=?6 AND state='open'",params![next.to_string(),attachment.to_string(),serde_json::to_string(&transition)?,now_unix_ms,upload.to_string(),generation.to_string()])?;ensure!(changed==1,"upload finalize lost compare-and-swap");let receipt=LocalMediaMutationReceiptV1{schema_version:1,kind:"localMediaMutationReceipt".into(),receipt_id:Uuid::now_v7(),local_operation_id:mutation.local_operation_id,actor_principal_digest:mutation.actor_principal_digest,action:"finalize".into(),subject_kind:LocalMediaSubjectKindV1::Upload,subject_id:upload,operation_request_digest:request_digest.clone(),semantic_command_digest:semantic_digest.clone(),outcome:LocalMediaMutationOutcomeV1::Applied,transition:LocalMediaMutationTransitionV1::UploadToAttachment{upload_generation_before:generation,upload_generation_after:next,attachment_version:1,availability_generation:if processed{5}else{1},reference_generation:1},discard_result:None,discard_result_digest:None,committed_at_unix_ms:now_unix_ms};commit_local_operation(conn,&receipt,"finalize",&domain,&request_digest,&semantic_digest,now_unix_ms)?;Ok((receipt,true))}).await;
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
        if let Some(receipt)=self.db.transaction(move|conn|{if let Some((stored,json))=conn.query_row("SELECT operation_request_digest,receipt_json FROM local_media_operations WHERE local_operation_id=?1",[operation_id],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?))).optional()?{ensure!(stored==binding,"local_operation_conflict");return Ok(Some(serde_json::from_str(&json)?))}

        if let Some((authoritative,stored_semantic,json))=conn.query_row("SELECT authoritative_operation_id,semantic_command_digest,receipt_json FROM local_media_operations WHERE action='begin' AND domain_key=?1 AND is_alias=0",[&domain_preflight],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?))).optional()?{ensure!(stored_semantic==semantic_preflight,"local_domain_conflict");conn.execute("INSERT INTO local_media_operations(local_operation_id,authoritative_operation_id,action,domain_key,operation_request_digest,semantic_command_digest,receipt_json,is_alias,committed_at_unix_ms) VALUES(?1,?2,'begin',?3,?4,?5,?6,1,?7)",params![alias_id.to_string(),authoritative,domain_preflight,binding,semantic_preflight,json,now_unix_ms])?;return Ok(Some(serde_json::from_str(&json)?))}Ok(None)}).await?{return Ok(receipt)}
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
        let (_, sha256) = read_full_digest(&mut source)?;
        source.seek(SeekFrom::Start(0))?;
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
            av_runner: std::sync::Arc::new(SystemAvRuntimeRunner),
            https_fetcher: std::sync::Arc::new(crate::media_https::SystemHttpsMediaFetcher),
            #[cfg(test)]
            av_runtime_override: None,
            #[cfg(test)]
            fail_processing_output_proof: false,
        })
    }

    #[cfg(test)]
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
            av_runner: std::sync::Arc::new(SystemAvRuntimeRunner),
            https_fetcher: std::sync::Arc::new(crate::media_https::SystemHttpsMediaFetcher),
            #[cfg(test)]
            av_runtime_override: None,
            #[cfg(test)]
            fail_processing_output_proof: false,
        })
    }

    #[cfg(test)]
    fn with_av_runner(mut self, runner: std::sync::Arc<dyn AvRuntimeRunner>) -> Self {
        self.av_runner = runner;
        self
    }

    #[cfg(test)]
    pub(crate) fn with_https_fetcher(
        mut self,
        fetcher: std::sync::Arc<dyn crate::media_https::HttpsMediaFetcher>,
    ) -> Self {
        self.https_fetcher = fetcher;
        self
    }

    #[cfg(test)]
    fn with_processing_output_proof_failure(mut self) -> Self {
        self.fail_processing_output_proof = true;
        self
    }

    fn resolve_av_runtime(&self) -> Result<ApprovedAvRuntime> {
        #[cfg(test)]
        if let Some(runtime) = &self.av_runtime_override {
            return Ok(runtime.clone());
        }
        let health = crate::external_runtime::global_health_store()
            .current()
            .context("model_runtime_unavailable")?;
        approved_av_runtime(&health)
    }

    #[cfg(test)]
    fn with_av_runtime(mut self, runtime: ApprovedAvRuntime) -> Self {
        self.av_runtime_override = Some(runtime);
        self
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

#[cfg(test)]
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
    let mut header = [0u8; 4096];
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
    } else if bytes.len() >= 12 && &bytes[..4] == b"RIFF" && &bytes[8..12] == b"WAVE" {
        Some((MediaKind::Audio, "wav", "audio/wav"))
    } else if bytes.starts_with(b"fLaC") {
        Some((MediaKind::Audio, "flac", "audio/flac"))
    } else if bytes.starts_with(b"OggS") {
        Some((MediaKind::Audio, "ogg", "audio/ogg"))
    } else if valid_mpeg_audio_prefix(bytes) {
        Some((MediaKind::Audio, "mp3", "audio/mpeg"))
    } else if declared != MediaKind::Image && bytes.len() >= 16 && &bytes[4..8] == b"ftyp" {
        Some((declared, "iso_bmff", "application/octet-stream"))
    } else if ebml_doctype_is_webm(bytes)? {
        Some((MediaKind::Video, "webm", "video/webm"))
    } else {
        None
    };
    let (kind, container, mime) = classified.context("ambiguous_or_unsupported_container")?;
    ensure!(kind == declared, "ambiguous_or_unsupported_container");
    Ok((container, mime))
}

fn closed_media_failure_reason(error: &anyhow::Error) -> &'static str {
    let text = error.to_string();
    if error.downcast_ref::<std::io::Error>().is_some() {
        "storage_failure"
    } else if text.contains("ambiguous_or_unsupported_container") {
        "ambiguous_or_unsupported_container"
    } else if text.contains("unsupported_codec") {
        "unsupported_codec"
    } else if text.contains("unsupported_color_profile") {
        "unsupported_color_profile"
    } else if text.contains("resource_limit") {
        "resource_limit"
    } else if text.contains("decode") {
        "decode_failed"
    } else if text.contains("invalid_media") {
        "invalid_media"
    } else {
        "normalization_failed"
    }
}

fn valid_mpeg_audio_prefix(bytes: &[u8]) -> bool {
    let mut offset = 0usize;
    if bytes.starts_with(b"ID3") {
        if bytes.len() < 10
            || bytes[3] == 0xff
            || bytes[4] == 0xff
            || bytes[6..10].iter().any(|byte| byte & 0x80 != 0)
        {
            return false;
        }
        let size = ((bytes[6] as usize) << 21)
            | ((bytes[7] as usize) << 14)
            | ((bytes[8] as usize) << 7)
            | (bytes[9] as usize);
        offset = match 10usize
            .checked_add(size)
            .and_then(|value| value.checked_add(if bytes[5] & 0x10 != 0 { 10 } else { 0 }))
        {
            Some(value) => value,
            None => return false,
        };
    }
    let Some(frame) = bytes.get(offset..offset.saturating_add(4)) else {
        return false;
    };
    frame[0] == 0xff
        && frame[1] & 0xe0 == 0xe0
        && frame[1] & 0x18 != 0x08
        && frame[1] & 0x06 != 0
        && frame[2] & 0xf0 != 0xf0
        && frame[2] & 0x0c != 0x0c
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AvProbeStream {
    index: u32,
    kind: &'static str,
    codec: String,
    default_disposition: bool,
}

fn select_av_streams(
    container: &str,
    streams: &[AvProbeStream],
) -> Result<(Option<AvProbeStream>, Option<AvProbeStream>)> {
    ensure!(!streams.is_empty() && streams.len() <= 64, "invalid_media");
    let allowed_audio = |codec: &str| match container {
        "wav" => matches!(codec, "pcm_s16le" | "pcm_s24le" | "pcm_s32le" | "pcm_f32le"),
        "mp3" => codec == "mp3",
        "m4a" => matches!(codec, "aac" | "alac"),
        "flac" => codec == "flac",
        "ogg" => matches!(codec, "vorbis" | "opus" | "flac"),
        "mp4" => matches!(codec, "aac" | "alac" | "mp3"),
        "webm" => matches!(codec, "opus" | "vorbis"),
        "mov" => matches!(
            codec,
            "aac" | "alac" | "pcm_s16le" | "pcm_s24le" | "pcm_s32le"
        ),
        _ => false,
    };
    let allowed_video = |codec: &str| match container {
        "mp4" => matches!(codec, "h264" | "hevc" | "av1"),
        "webm" => matches!(codec, "vp8" | "vp9" | "av1"),
        "mov" => matches!(codec, "h264" | "hevc" | "prores"),
        _ => false,
    };
    let choose = |kind: &str, allowed: &dyn Fn(&str) -> bool| {
        streams
            .iter()
            .filter(|stream| stream.kind == kind && allowed(&stream.codec))
            .min_by_key(|stream| (!stream.default_disposition, stream.index))
            .cloned()
    };
    let audio = choose("audio", &allowed_audio);
    let video = choose("video", &allowed_video);
    if matches!(container, "wav" | "mp3" | "m4a" | "flac" | "ogg") {
        ensure!(
            audio.is_some() && streams.iter().all(|stream| stream.kind != "video"),
            "ambiguous_or_unsupported_container"
        );
        Ok((None, audio))
    } else if matches!(container, "mp4" | "webm" | "mov") {
        ensure!(video.is_some(), "ambiguous_or_unsupported_container");
        Ok((video, audio))
    } else {
        anyhow::bail!("ambiguous_or_unsupported_container")
    }
}

fn select_video_dimensions(
    width: u32,
    height: u32,
    sar_num: u32,
    sar_den: u32,
) -> Result<(u32, u32)> {
    ensure!(
        width > 0 && height > 0 && sar_num > 0 && sar_den > 0,
        "invalid_media"
    );
    let max_w = width.min(1280);
    let max_h = height.min(720);
    ensure!(max_w >= 2 && max_h >= 2, "video_dimensions_too_small");
    let mut best: Option<(u32, u32, u128)> = None;
    for w in (2..=max_w).step_by(2) {
        for h in (2..=max_h).step_by(2) {
            let left = u128::from(w) * u128::from(height) * u128::from(sar_den);
            let right = u128::from(h) * u128::from(width) * u128::from(sar_num);
            let error = left.abs_diff(right);
            let replace = best.is_none_or(|(best_w, best_h, best_error)| {
                let order = (error * u128::from(best_h)).cmp(&(best_error * u128::from(h)));
                let area = u64::from(w) * u64::from(h);
                let best_area = u64::from(best_w) * u64::from(best_h);
                order.is_lt()
                    || (order.is_eq() && (area > best_area || (area == best_area && w > best_w)))
            });
            if replace {
                best = Some((w, h, error));
            }
        }
    }
    best.map(|(w, h, _)| (w, h))
        .context("video_dimensions_too_small")
}

fn classify_iso_bmff(bytes: &[u8], has_video: bool, audio_streams: usize) -> Result<&'static str> {
    ensure!(bytes.len() >= 16, "ambiguous_or_unsupported_container");
    let size = u32::from_be_bytes(bytes[..4].try_into()?) as usize;
    ensure!(
        size >= 16 && size <= bytes.len() && &bytes[4..8] == b"ftyp" && (size - 16) % 4 == 0,
        "ambiguous_or_unsupported_container"
    );
    let major: [u8; 4] = bytes[8..12].try_into()?;
    let mut brands = Vec::new();
    for chunk in bytes[16..size].chunks_exact(4) {
        let brand: [u8; 4] = chunk.try_into()?;
        ensure!(
            !brands.contains(&brand),
            "ambiguous_or_unsupported_container"
        );
        brands.push(brand);
    }
    ensure!(!brands.is_empty(), "ambiguous_or_unsupported_container");
    let all = |allowed: &[[u8; 4]]| {
        allowed.contains(&major) && brands.iter().all(|brand| allowed.contains(brand))
    };
    let mov = all(&[*b"qt  "]) && has_video && !brands.contains(b"M4A ");
    let m4a = major == *b"M4A "
        && all(&[*b"M4A ", *b"isom", *b"iso2", *b"mp41", *b"mp42"])
        && !has_video
        && audio_streams == 1
        && !brands.contains(b"qt  ");
    let mp4 = all(&[
        *b"isom", *b"iso2", *b"iso4", *b"iso5", *b"iso6", *b"mp41", *b"mp42", *b"avc1", *b"M4V ",
    ]) && has_video
        && !brands.contains(b"qt  ")
        && !brands.contains(b"M4A ");
    match (mov, m4a, mp4) {
        (true, false, false) => Ok("mov"),
        (false, true, false) => Ok("m4a"),
        (false, false, true) => Ok("mp4"),
        _ => anyhow::bail!("ambiguous_or_unsupported_container"),
    }
}

fn ebml_doctype_is_webm(bytes: &[u8]) -> Result<bool> {
    ensure!(
        bytes.starts_with(&[0x1a, 0x45, 0xdf, 0xa3]),
        "ambiguous_or_unsupported_container"
    );
    let mut found = None;
    let mut index = 4usize;
    while index + 3 <= bytes.len().min(4096) {
        if bytes[index] == 0x42 && bytes[index + 1] == 0x82 {
            let first = bytes[index + 2];
            let width = first.leading_zeros() as usize + 1;
            ensure!(
                width <= 8 && index + 2 + width <= bytes.len(),
                "ambiguous_or_unsupported_container"
            );
            let mask = if width == 8 {
                0
            } else {
                (1u8 << (8 - width)) - 1
            };
            let mut length = usize::from(first & mask);
            for byte in &bytes[index + 3..index + 2 + width] {
                length = length
                    .checked_mul(256)
                    .and_then(|value| value.checked_add(usize::from(*byte)))
                    .context("ambiguous_or_unsupported_container")?;
            }
            let start = index + 2 + width;
            let end = start
                .checked_add(length)
                .context("ambiguous_or_unsupported_container")?;
            ensure!(
                end <= bytes.len() && found.is_none(),
                "ambiguous_or_unsupported_container"
            );
            found = Some(&bytes[start..end]);
            index = end;
        } else {
            index += 1;
        }
    }
    Ok(found == Some(b"webm".as_slice()))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BoundedRuntimeOutput {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

#[async_trait::async_trait]
trait AvRuntimeRunner: Send + Sync {
    async fn run(
        &self,
        program: &Path,
        args: &[String],
        input: Vec<u8>,
        stdout_limit: u64,
        deadline: std::time::Duration,
    ) -> Result<BoundedRuntimeOutput>;
}

struct SystemAvRuntimeRunner;

#[async_trait::async_trait]
impl AvRuntimeRunner for SystemAvRuntimeRunner {
    async fn run(
        &self,
        program: &Path,
        args: &[String],
        input: Vec<u8>,
        stdout_limit: u64,
        deadline: std::time::Duration,
    ) -> Result<BoundedRuntimeOutput> {
        run_bounded_runtime(program, args, input, stdout_limit, deadline).await
    }
}

struct AvNormalizationEvidence {
    runtime_fingerprint: String,
    probe_digest: String,
    decode_digest: String,
    plan_digest: String,
    derivative_checksum: String,
}

/// Owned input boundary shared by authenticated-upload Finalize and retained
/// HTTPS processing. Bytes have already passed the caller-specific held-file
/// identity/length/full-checksum proof; the helper never accepts a path.
struct AvNormalizationInput {
    bytes: Vec<u8>,
    initial_container: String,
    initial_mime: String,
}

type AvDerivativePlan = (&'static str, Uuid, Vec<u8>, Option<(u32, u32)>);

/// Complete, transport-independent outcome of A/V preparation. Publication,
/// reservation ownership and attachment-generation CAS remain with callers.
struct PreparedAvNormalization {
    canonical_container: String,
    canonical_mime: String,
    selected_video_stream: Option<SelectedMediaStream>,
    selected_audio_stream: Option<SelectedMediaStream>,
    derivatives: Vec<AvDerivativePlan>,
    terminal_availability: Option<MediaAvailability>,
    evidence: Option<AvNormalizationEvidence>,
}

fn av_plan_digest(runtime_fingerprint: &str, argv: &[String]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"media-av-derivative-plan-v1\0");
    hasher.update(runtime_fingerprint.as_bytes());
    hasher.update([0]);
    for argument in argv {
        hasher.update(argument.as_bytes());
        hasher.update([0]);
    }
    crate::intel::hex_lower(&hasher.finalize())
}

async fn run_bounded_runtime(
    program: &Path,
    args: &[String],
    input: Vec<u8>,
    stdout_limit: u64,
    deadline: std::time::Duration,
) -> Result<BoundedRuntimeOutput> {
    use std::process::Stdio;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    ensure!(
        program.is_absolute() && stdout_limit > 0,
        "model_runtime_unavailable"
    );
    let end = tokio::time::Instant::now() + deadline;
    let mut command = tokio::process::Command::new(program);
    command
        .args(args)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = command.spawn().context("model_runtime_unavailable")?;
    let mut stdin = child.stdin.take().context("model_runtime_unavailable")?;
    let stdout = child.stdout.take().context("model_runtime_unavailable")?;
    let stderr = child.stderr.take().context("model_runtime_unavailable")?;
    let work = async move {
        let writer = async move {
            stdin.write_all(&input).await?;
            stdin.shutdown().await
        };
        let reader = async move {
            let mut bytes = Vec::new();
            stdout
                .take(stdout_limit + 1)
                .read_to_end(&mut bytes)
                .await?;
            Ok::<_, std::io::Error>(bytes)
        };
        let error_reader = async move {
            let mut bytes = Vec::new();
            stderr.take(65_537).read_to_end(&mut bytes).await?;
            Ok::<_, std::io::Error>(bytes)
        };
        let (write, stdout, stderr) = tokio::join!(writer, reader, error_reader);
        write?;
        Ok::<_, anyhow::Error>((stdout?, stderr?))
    };
    let (stdout, stderr) = tokio::time::timeout_at(end, work)
        .await
        .context("model_runtime_timeout")??;
    let status = tokio::time::timeout_at(end, child.wait())
        .await
        .context("model_runtime_timeout")??;
    ensure!(
        stdout.len() as u64 <= stdout_limit && stderr.len() <= 65_536,
        "resource_limit"
    );
    ensure!(status.success(), "invalid_media");
    Ok(BoundedRuntimeOutput { stdout, stderr })
}

#[derive(Debug, serde::Deserialize)]
struct FfprobeDisposition {
    #[serde(default)]
    default: i32,
}
#[derive(Debug, serde::Deserialize)]
struct FfprobeStream {
    index: u32,
    codec_type: String,
    codec_name: String,
    #[serde(default)]
    disposition: Option<FfprobeDisposition>,
    sample_rate: Option<String>,
    channels: Option<u32>,
    width: Option<u32>,
    height: Option<u32>,
    sample_aspect_ratio: Option<String>,
    time_base: Option<String>,
    profile: Option<String>,
    pix_fmt: Option<String>,
    #[serde(default)]
    side_data_list: Vec<FfprobeSideData>,
}
#[derive(Debug, serde::Deserialize)]
struct FfprobeSideData {
    #[serde(default)]
    rotation: Option<i32>,
    #[serde(default)]
    displaymatrix: Option<String>,
}
#[derive(Debug, serde::Deserialize)]
struct FfprobeFrame {
    media_type: String,
    stream_index: u32,
    #[serde(default)]
    best_effort_timestamp: Option<String>,
    #[serde(default)]
    key_frame: i32,
}
#[derive(Debug, serde::Deserialize)]
struct FfprobeDocument {
    streams: Vec<FfprobeStream>,
    #[serde(default)]
    frames: Vec<FfprobeFrame>,
}

async fn run_bounded_ffprobe(
    runtime: &ApprovedAvRuntime,
    runner: &dyn AvRuntimeRunner,
    input: Vec<u8>,
) -> Result<(FfprobeDocument, String)> {
    let argv = [
        "-v",
        "error",
        "-nostdin",
        "-print_format",
        "json",
        "-show_streams",
        "-show_format",
        "-show_frames",
        "pipe:0",
    ]
    .map(str::to_owned);
    let output = runner
        .run(
            &runtime.ffprobe,
            &argv,
            input,
            16 * 1_048_576,
            std::time::Duration::from_secs(30),
        )
        .await?;
    ensure!(output.stderr.is_empty(), "invalid_media");
    let digest = crate::intel::hex_lower(&Sha256::digest(&output.stdout));
    let document: FfprobeDocument =
        serde_json::from_slice(&output.stdout).context("invalid_media")?;
    ensure!(
        !document.streams.is_empty()
            && document.streams.len() <= 64
            && document.frames.len() <= 250_000,
        "invalid_media"
    );
    Ok((document, digest))
}

fn decode_to_null_argv(video: Option<u32>, audio: Option<u32>) -> Result<Vec<String>> {
    ensure!(video.is_some() || audio.is_some(), "invalid_media");
    let mut argv = [
        "-nostdin",
        "-hide_banner",
        "-loglevel",
        "error",
        "-threads",
        "1",
        "-i",
        "pipe:0",
    ]
    .map(str::to_owned)
    .to_vec();
    for index in [video, audio].into_iter().flatten() {
        argv.extend(["-map".into(), format!("0:{index}")]);
    }
    argv.extend(
        [
            "-map_metadata",
            "-1",
            "-map_chapters",
            "-1",
            "-f",
            "null",
            "-",
        ]
        .map(str::to_owned),
    );
    Ok(argv)
}

async fn decode_selected_streams(
    runtime: &ApprovedAvRuntime,
    runner: &dyn AvRuntimeRunner,
    input: Vec<u8>,
    video: Option<u32>,
    audio: Option<u32>,
) -> Result<String> {
    let argv = decode_to_null_argv(video, audio)?;
    let output = runner
        .run(
            &runtime.ffmpeg,
            &argv,
            input,
            1,
            std::time::Duration::from_secs(120),
        )
        .await?;
    ensure!(output.stdout.is_empty(), "invalid_media");
    let mut hasher = Sha256::new();
    hasher.update(b"media-full-decode-v1\0");
    hasher.update(runtime.fingerprint.as_bytes());
    for arg in argv {
        hasher.update(arg.as_bytes());
        hasher.update([0]);
    }
    Ok(crate::intel::hex_lower(&hasher.finalize()))
}

fn parse_positive_ratio(value: &str) -> Result<(u32, u32)> {
    let (num, den) = value.split_once([':', '/']).context("invalid_media")?;
    let num = num.parse::<u32>().context("invalid_media")?;
    let den = den.parse::<u32>().context("invalid_media")?;
    ensure!(num > 0 && den > 0, "invalid_media");
    Ok((num, den))
}

fn selected_video_timestamps(
    document: &FfprobeDocument,
    stream: &FfprobeStream,
) -> Result<Vec<(u64, u64)>> {
    let (time_num, time_den) =
        parse_positive_ratio(stream.time_base.as_deref().context("invalid_media")?)?;
    let timestamps = document
        .frames
        .iter()
        .filter(|frame| frame.media_type == "video" && frame.stream_index == stream.index)
        .map(|frame| {
            let pts = frame
                .best_effort_timestamp
                .as_deref()
                .context("invalid_media")?
                .parse::<u64>()
                .context("invalid_media")?;
            let num = pts
                .checked_mul(u64::from(time_num))
                .context("resource_limit")?;
            Ok((num, u64::from(time_den)))
        })
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        !timestamps.is_empty() && timestamps.len() <= 250_000,
        "invalid_media"
    );
    ensure!(
        !timestamps.is_empty()
            && timestamps.windows(2).all(|pair| {
                u128::from(pair[0].0) * u128::from(pair[1].1)
                    < u128::from(pair[1].0) * u128::from(pair[0].1)
            }),
        "invalid_media"
    );
    Ok(timestamps)
}

fn oriented_video_dimensions(stream: &FfprobeStream) -> Result<(u32, u32)> {
    let width = stream.width.context("invalid_media")?;
    let height = stream.height.context("invalid_media")?;
    let transforms = stream
        .side_data_list
        .iter()
        .filter(|data| data.rotation.is_some() || data.displaymatrix.is_some())
        .collect::<Vec<_>>();
    ensure!(transforms.len() <= 1, "invalid_media");
    let Some(transform) = transforms.first() else {
        return Ok((width, height));
    };
    let rotation = transform.rotation.unwrap_or(0).rem_euclid(360);
    ensure!(matches!(rotation, 0 | 90 | 180 | 270), "invalid_media");
    let matrix = transform
        .displaymatrix
        .as_deref()
        .map(parse_display_matrix)
        .transpose()?
        .context("invalid_media")?;
    let [a, b, _, c, d, _, x, y, scale] = matrix;
    ensure!(
        [a, b, c, d]
            .iter()
            .all(|value| matches!(*value, -65_536 | 0 | 65_536))
            && [a, b].iter().filter(|value| **value != 0).count() == 1
            && [c, d].iter().filter(|value| **value != 0).count() == 1
            && [a, c].iter().filter(|value| **value != 0).count() == 1
            && [b, d].iter().filter(|value| **value != 0).count() == 1
            && x == 0
            && y == 0
            && scale == 1_073_741_824,
        "invalid_media"
    );
    let matrix_rotation = match (a, b, c, d) {
        (65_536, 0, 0, 65_536) | (-65_536, 0, 0, 65_536) => 0,
        (0, -65_536, 65_536, 0) | (0, 65_536, 65_536, 0) => 90,
        (-65_536, 0, 0, -65_536) | (65_536, 0, 0, -65_536) => 180,
        (0, 65_536, -65_536, 0) | (0, -65_536, -65_536, 0) => 270,
        _ => anyhow::bail!("invalid_media"),
    };
    ensure!(rotation == matrix_rotation, "invalid_media");
    Ok(if a == 0 {
        (height, width)
    } else {
        (width, height)
    })
}

fn parse_display_matrix(value: &str) -> Result<[i64; 9]> {
    let values = value
        .lines()
        .flat_map(|line| line.split_once(':').map(|(_, values)| values).into_iter())
        .flat_map(str::split_ascii_whitespace)
        .map(|value| value.parse::<i64>().context("invalid_media"))
        .collect::<Result<Vec<_>>>()?;
    ensure!(values.len() == 9, "invalid_media");
    values
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid_media"))
}

fn verify_encoded_video_provenance(
    document: &FfprobeDocument,
    width: u32,
    height: u32,
    expected_rate: (u32, u32),
    source_frames: usize,
    gop: u32,
    expect_audio: bool,
) -> Result<()> {
    let video = document
        .streams
        .iter()
        .filter(|stream| stream.codec_type == "video")
        .collect::<Vec<_>>();
    let audio = document
        .streams
        .iter()
        .filter(|stream| stream.codec_type == "audio")
        .collect::<Vec<_>>();
    ensure!(
        video.len() == 1 && audio.len() == usize::from(expect_audio),
        "invalid_media"
    );
    let video = video[0];
    ensure!(
        video.codec_name == "h264"
            && video.profile.as_deref() == Some("High")
            && video.pix_fmt.as_deref() == Some("yuv420p")
            && video.width == Some(width)
            && video.height == Some(height)
            && video
                .side_data_list
                .iter()
                .all(|data| { data.rotation.is_none() && data.displaymatrix.is_none() }),
        "invalid_media"
    );
    if let Some(audio) = audio.first() {
        ensure!(
            audio.codec_name == "aac"
                && audio.profile.as_deref() == Some("LC")
                && matches!(audio.channels, Some(1 | 2))
                && audio
                    .sample_rate
                    .as_deref()
                    .and_then(|value| value.parse::<u32>().ok())
                    .is_some_and(|rate| rate <= 48_000),
            "invalid_media"
        );
    }
    let frames = document
        .frames
        .iter()
        .filter(|frame| frame.media_type == "video" && frame.stream_index == video.index)
        .collect::<Vec<_>>();
    ensure!(
        !frames.is_empty() && frames.len() <= source_frames,
        "invalid_media"
    );
    let timestamps = selected_video_timestamps(document, video)?;
    if timestamps.len() > 1 {
        let first_num = u128::from(timestamps[1].0)
            .checked_mul(u128::from(timestamps[0].1))
            .context("invalid_media")?
            .checked_sub(
                u128::from(timestamps[0].0)
                    .checked_mul(u128::from(timestamps[1].1))
                    .context("invalid_media")?,
            )
            .context("invalid_media")?;
        let first_den = u128::from(timestamps[0].1)
            .checked_mul(u128::from(timestamps[1].1))
            .context("invalid_media")?;
        ensure!(first_num > 0, "invalid_media");
        for pair in timestamps.windows(2) {
            let num = u128::from(pair[1].0) * u128::from(pair[0].1)
                - u128::from(pair[0].0) * u128::from(pair[1].1);
            let den = u128::from(pair[0].1) * u128::from(pair[1].1);
            ensure!(num * first_den == first_num * den, "invalid_media");
        }
        ensure!(
            first_den * u128::from(expected_rate.1) == first_num * u128::from(expected_rate.0),
            "invalid_media"
        );
    } else {
        ensure!(expected_rate == (1, 1), "invalid_media");
    }
    ensure!(frames[0].key_frame == 1, "invalid_media");
    let mut last_keyframe = None;
    for (index, frame) in frames.iter().enumerate() {
        if frame.key_frame == 1 {
            if let Some(previous) = last_keyframe {
                ensure!(index - previous <= gop as usize, "invalid_media");
            }
            last_keyframe = Some(index);
        }
    }
    ensure!(last_keyframe.is_some(), "invalid_media");
    Ok(())
}

async fn run_video_normalization(
    runtime: &ApprovedAvRuntime,
    runner: &dyn AvRuntimeRunner,
    mut argv: Vec<String>,
    input: Vec<u8>,
) -> Result<Vec<u8>> {
    use std::io::{Read as _, Seek as _};
    let mut output = tempfile::Builder::new()
        .prefix("flycockpit-video-")
        .tempfile()?;
    let before = stable_identity_digest(output.as_file())?;
    let output_path = output
        .path()
        .to_str()
        .context("invalid output path")?
        .to_owned();
    let destination = argv.last_mut().context("invalid_media")?;
    ensure!(destination == "pipe:1", "invalid_media");
    *destination = output_path;
    argv.insert(1, "-y".into());
    let result = runner
        .run(
            &runtime.ffmpeg,
            &argv,
            input,
            1,
            std::time::Duration::from_secs(300),
        )
        .await?;
    ensure!(result.stdout.is_empty(), "invalid_media");
    ensure!(
        before == stable_identity_digest(output.as_file())?,
        "invalid_media"
    );
    output.as_file_mut().sync_all()?;
    output.as_file_mut().seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::new();
    output
        .as_file_mut()
        .take(500 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 500 * 1024 * 1024, "resource_limit");
    Ok(bytes)
}

async fn verify_required_video_encoders(
    runtime: &ApprovedAvRuntime,
    runner: &dyn AvRuntimeRunner,
    require_aac: bool,
) -> Result<()> {
    let argv = [
        "-nostdin".to_owned(),
        "-hide_banner".to_owned(),
        "-encoders".to_owned(),
    ];
    let output = runner
        .run(
            &runtime.ffmpeg,
            &argv,
            Vec::new(),
            2 * 1_048_576,
            std::time::Duration::from_secs(10),
        )
        .await
        .context("model_runtime_unavailable")?;
    let encoders = std::str::from_utf8(&output.stdout).context("model_runtime_unavailable")?;
    let has = |name: &str| {
        encoders.lines().any(|line| {
            line.split_ascii_whitespace()
                .nth(1)
                .is_some_and(|value| value == name)
        })
    };
    ensure!(has("libx264"), "model_runtime_unavailable");
    ensure!(!require_aac || has("aac"), "model_runtime_unavailable");
    Ok(())
}

#[derive(Clone)]
struct ApprovedAvRuntime {
    ffmpeg: std::path::PathBuf,
    ffprobe: std::path::PathBuf,
    fingerprint: String,
}

fn approved_av_runtime(
    snapshot: &crate::external_runtime::ExternalRuntimeSnapshot,
) -> Result<ApprovedAvRuntime> {
    use crate::external_runtime::{
        HealthState, ID_MEDIA_FFMPEG, ID_MEDIA_FFPROBE, select_media_runtime_pair,
    };
    let (ffmpeg, ffprobe) = select_media_runtime_pair(snapshot)
        .map_err(anyhow::Error::msg)
        .context("model_runtime_unavailable")?;
    let evidence = |id| match &snapshot.get(id).context("model_runtime_unavailable")?.state {
        HealthState::Available {
            version_evidence: Some(value),
            ..
        } => Ok(value.as_str()),
        _ => anyhow::bail!("model_runtime_unavailable"),
    };
    let mut hasher = Sha256::new();
    hasher.update(b"media-av-runtime-v1\0");
    hasher.update(snapshot.generation.to_be_bytes());
    for value in [
        ffmpeg.as_os_str().as_encoded_bytes(),
        ffprobe.as_os_str().as_encoded_bytes(),
        evidence(ID_MEDIA_FFMPEG)?.as_bytes(),
        evidence(ID_MEDIA_FFPROBE)?.as_bytes(),
    ] {
        hasher.update(value);
        hasher.update([0]);
    }
    Ok(ApprovedAvRuntime {
        ffmpeg: ffmpeg.to_owned(),
        ffprobe: ffprobe.to_owned(),
        fingerprint: crate::intel::hex_lower(&hasher.finalize()),
    })
}

fn audio_normalization_argv(stream: u32, source_rate: u32, channels: u32) -> Result<Vec<String>> {
    ensure!(source_rate > 0 && channels > 0, "invalid_media");
    let rate = source_rate.min(48_000);
    let output_channels = if channels == 1 { 1 } else { 2 };
    let mut argv = [
        "-nostdin",
        "-hide_banner",
        "-loglevel",
        "error",
        "-threads",
        "1",
        "-i",
        "pipe:0",
        "-map",
    ]
    .map(str::to_owned)
    .to_vec();
    argv.push(format!("0:{stream}"));
    argv.extend(["-vn","-map_metadata","-1","-map_chapters","-1","-af","aresample=resampler=swr:filter_size=32:phase_shift=10:linear_interp=0:exact_rational=1:dither_method=none","-ac"].map(str::to_owned));
    argv.push(output_channels.to_string());
    argv.push("-ar".into());
    argv.push(rate.to_string());
    argv.extend(["-c:a", "pcm_s16le", "-f", "wav", "pipe:1"].map(str::to_owned));
    Ok(argv)
}

#[allow(clippy::too_many_arguments)]
fn video_normalization_argv(
    video_stream: u32,
    audio_stream: Option<u32>,
    audio_settings: Option<(u32, u32)>,
    width: u32,
    height: u32,
    fps_num: u32,
    fps_den: u32,
    gop: u32,
    min_keyint: u32,
) -> Result<Vec<String>> {
    ensure!(
        width >= 2
            && height >= 2
            && width % 2 == 0
            && height % 2 == 0
            && fps_num > 0
            && fps_den > 0
            && gop > 0
            && min_keyint > 0
            && min_keyint <= gop,
        "invalid_media"
    );
    let mut argv = [
        "-nostdin",
        "-hide_banner",
        "-loglevel",
        "error",
        "-threads",
        "1",
        "-i",
        "pipe:0",
        "-map",
    ]
    .map(str::to_owned)
    .to_vec();
    argv.push(format!("0:{video_stream}"));
    if let Some(audio) = audio_stream {
        let (source_rate, channels) = audio_settings.context("invalid_media")?;
        ensure!(source_rate > 0 && channels > 0, "invalid_media");
        argv.extend(["-map".into(), format!("0:{audio}")]);
    } else {
        ensure!(audio_settings.is_none(), "invalid_media");
    }
    argv.extend(
        [
            "-map_metadata",
            "-1",
            "-map_chapters",
            "-1",
            "-fflags",
            "+bitexact",
            "-vf",
        ]
        .map(str::to_owned),
    );
    argv.push(format!("scale={width}:{height}:flags=lanczos,fps={fps_num}/{fps_den}:start_time=0:round=down,format=yuv420p"));
    argv.extend(
        [
            "-c:v",
            "libx264",
            "-profile:v",
            "high",
            "-preset",
            "medium",
            "-crf",
            "23",
            "-x264-params",
        ]
        .map(str::to_owned),
    );
    argv.push(format!(
        "threads=1:scenecut=0:keyint={gop}:min-keyint={min_keyint}:bframes=3:ref=3"
    ));
    if let Some((source_rate, channels)) = audio_settings {
        argv.extend(["-af", "aresample=resampler=swr:filter_size=32:phase_shift=10:linear_interp=0:exact_rational=1:dither_method=none", "-ac"].map(str::to_owned));
        argv.push(if channels == 1 { "1" } else { "2" }.into());
        argv.push("-ar".into());
        argv.push(source_rate.min(48_000).to_string());
    }
    argv.extend(
        [
            "-c:a",
            "aac",
            "-b:a",
            "128k",
            "-movflags",
            "+faststart",
            "-brand",
            "isom",
            "-f",
            "mp4",
            "pipe:1",
        ]
        .map(str::to_owned),
    );
    Ok(argv)
}

fn gcd_u128(mut a: u128, mut b: u128) -> u128 {
    while b != 0 {
        let remainder = a % b;
        a = b;
        b = remainder;
    }
    a
}

fn select_video_rate(timestamps: &[(u64, u64)]) -> Result<(u32, u32, u32, u32)> {
    ensure!(!timestamps.is_empty(), "invalid_media");
    for &(_, den) in timestamps {
        ensure!(den > 0, "invalid_media");
    }
    if timestamps.len() == 1 {
        return Ok((1, 1, 10, 1));
    }
    let delta = |left: (u64, u64), right: (u64, u64)| -> Result<(u128, u128)> {
        let lhs = u128::from(right.0)
            .checked_mul(u128::from(left.1))
            .context("invalid_media")?;
        let rhs = u128::from(left.0)
            .checked_mul(u128::from(right.1))
            .context("invalid_media")?;
        ensure!(lhs > rhs, "invalid_media");
        let num = lhs - rhs;
        let den = u128::from(left.1)
            .checked_mul(u128::from(right.1))
            .context("invalid_media")?;
        let gcd = gcd_u128(num, den);
        Ok((num / gcd, den / gcd))
    };
    let deltas = timestamps
        .windows(2)
        .map(|pair| delta(pair[0], pair[1]))
        .collect::<Result<Vec<_>>>()?;
    let cfr = deltas.iter().all(|value| *value == deltas[0]);
    let (mut num, mut den) = if cfr {
        (deltas[0].1, deltas[0].0)
    } else {
        let total = delta(timestamps[0], *timestamps.last().unwrap())?;
        (
            u128::try_from(timestamps.len() - 1)?
                .checked_mul(total.1)
                .context("invalid_media")?,
            total.0,
        )
    };
    let gcd = gcd_u128(num, den);
    num /= gcd;
    den /= gcd;
    if num > 24 * den {
        num = 24;
        den = 1;
    }
    let num = u32::try_from(num).context("invalid_media")?;
    let den = u32::try_from(den).context("invalid_media")?;
    let ceil = |a: u64, b: u64| {
        a.checked_add(b - 1)
            .context("invalid_media")
            .map(|value| value / b)
    };
    let gop = u32::try_from(ceil(10 * u64::from(num), u64::from(den))?.clamp(1, 240))?;
    let min_keyint = u32::try_from(ceil(u64::from(num), u64::from(den))?.clamp(1, u64::from(gop)))?;
    Ok((num, den, gop, min_keyint))
}

fn canonicalize_pcm_wav(bytes: &[u8]) -> Result<Vec<u8>> {
    ensure!(
        bytes.len() >= 12 && &bytes[..4] == b"RIFF" && &bytes[8..12] == b"WAVE",
        "invalid_media"
    );
    let declared = u32::from_le_bytes(bytes[4..8].try_into()?) as usize;
    ensure!(
        declared.checked_add(8) == Some(bytes.len()),
        "invalid_media"
    );
    let mut offset = 12usize;
    let (mut format, mut data) = (None, None);
    while offset + 8 <= bytes.len() {
        let kind = &bytes[offset..offset + 4];
        let length = u32::from_le_bytes(bytes[offset + 4..offset + 8].try_into()?) as usize;
        let start = offset + 8;
        let end = start.checked_add(length).context("invalid_media")?;
        ensure!(end <= bytes.len(), "invalid_media");
        match kind {
            b"fmt " => {
                ensure!(format.is_none() && length >= 16, "invalid_media");
                format = Some(&bytes[start..end]);
            }
            b"data" => {
                ensure!(data.is_none(), "invalid_media");
                data = Some(&bytes[start..end]);
            }
            _ => {}
        }
        offset = end.checked_add(length & 1).context("invalid_media")?;
    }
    ensure!(offset == bytes.len(), "invalid_media");
    let format = format.context("invalid_media")?;
    let data = data.context("invalid_media")?;
    let encoding = u16::from_le_bytes(format[0..2].try_into()?);
    let channels = u16::from_le_bytes(format[2..4].try_into()?);
    let rate = u32::from_le_bytes(format[4..8].try_into()?);
    let byte_rate = u32::from_le_bytes(format[8..12].try_into()?);
    let align = u16::from_le_bytes(format[12..14].try_into()?);
    let bits = u16::from_le_bytes(format[14..16].try_into()?);
    ensure!(
        encoding == 1
            && matches!(channels, 1 | 2)
            && rate > 0
            && rate <= 48_000
            && bits == 16
            && align == channels * 2
            && byte_rate == rate * u32::from(align)
            && data.len() % usize::from(align) == 0,
        "invalid_media"
    );
    let riff_size = 4usize + 8 + 16 + 8 + data.len() + (data.len() & 1);
    ensure!(riff_size <= u32::MAX as usize, "resource_limit");
    let mut output = Vec::with_capacity(riff_size + 8);
    output.extend_from_slice(b"RIFF");
    output.extend_from_slice(&(riff_size as u32).to_le_bytes());
    output.extend_from_slice(b"WAVEfmt \x10\0\0\0");
    output.extend_from_slice(&format[..16]);
    output.extend_from_slice(b"data");
    output.extend_from_slice(&(data.len() as u32).to_le_bytes());
    output.extend_from_slice(data);
    if data.len() & 1 != 0 {
        output.push(0);
    }
    Ok(output)
}

fn verify_canonical_video_mp4(bytes: &[u8]) -> Result<()> {
    ensure!(bytes.len() >= 24, "invalid_media");
    let mut offset = 0usize;
    let mut kinds = Vec::new();
    let mut ftyp = None;
    let mut moov = None;
    while offset < bytes.len() {
        ensure!(offset + 8 <= bytes.len(), "invalid_media");
        let short = u32::from_be_bytes(bytes[offset..offset + 4].try_into()?) as u64;
        let kind: [u8; 4] = bytes[offset + 4..offset + 8].try_into()?;
        let (header, size) = if short == 1 {
            ensure!(offset + 16 <= bytes.len(), "invalid_media");
            (
                16usize,
                u64::from_be_bytes(bytes[offset + 8..offset + 16].try_into()?),
            )
        } else {
            (8usize, short)
        };
        ensure!(size >= header as u64, "invalid_media");
        let end = offset
            .checked_add(usize::try_from(size)?)
            .context("invalid_media")?;
        ensure!(end <= bytes.len(), "invalid_media");
        ensure!(
            !kinds.contains(&kind) || !matches!(&kind, b"ftyp" | b"moov" | b"mdat"),
            "invalid_media"
        );
        if &kind == b"ftyp" {
            ftyp = Some(&bytes[offset..end]);
        }
        if &kind == b"moov" {
            moov = Some(&bytes[offset + header..end]);
        }
        kinds.push(kind);
        offset = end;
    }
    ensure!(
        offset == bytes.len()
            && kinds.first() == Some(b"ftyp")
            && kinds.iter().position(|kind| kind == b"moov")
                < kinds.iter().position(|kind| kind == b"mdat"),
        "invalid_media"
    );
    let ftyp = ftyp.context("invalid_media")?;
    ensure!(
        ftyp.len() == 32
            && &ftyp[8..12] == b"isom"
            && u32::from_be_bytes(ftyp[12..16].try_into()?) == 512
            && &ftyp[16..] == b"isomiso2avc1mp41",
        "invalid_media"
    );
    let moov = moov.context("invalid_media")?;
    let mut proof = Mp4StructuralProof::default();
    walk_mp4_atoms(moov, &mut proof)?;
    ensure!(
        proof.avc1_entries == 1
            && proof.mp4a_entries <= 1
            && proof.data_references >= 1
            && proof.data_references == proof.self_contained_data_references,
        "invalid_media"
    );
    Ok(())
}

#[derive(Default)]
struct Mp4StructuralProof {
    avc1_entries: usize,
    mp4a_entries: usize,
    data_references: usize,
    self_contained_data_references: usize,
}

fn walk_mp4_atoms(bytes: &[u8], proof: &mut Mp4StructuralProof) -> Result<()> {
    let mut offset = 0usize;
    while offset < bytes.len() {
        ensure!(offset + 8 <= bytes.len(), "invalid_media");
        let short = u32::from_be_bytes(bytes[offset..offset + 4].try_into()?) as u64;
        let kind: [u8; 4] = bytes[offset + 4..offset + 8].try_into()?;
        let (header, size) = if short == 1 {
            ensure!(offset + 16 <= bytes.len(), "invalid_media");
            (
                16usize,
                u64::from_be_bytes(bytes[offset + 8..offset + 16].try_into()?),
            )
        } else {
            (8usize, short)
        };
        ensure!(size >= header as u64, "invalid_media");
        let end = offset
            .checked_add(usize::try_from(size)?)
            .context("invalid_media")?;
        ensure!(end <= bytes.len(), "invalid_media");
        let payload = &bytes[offset + header..end];
        ensure!(
            !matches!(&kind, b"edts" | b"udta" | b"meta" | b"chap"),
            "invalid_media"
        );
        if matches!(&kind, b"trak" | b"mdia" | b"minf" | b"stbl" | b"dinf") {
            walk_mp4_atoms(payload, proof)?;
        } else if &kind == b"dref" {
            ensure!(payload.len() >= 8, "invalid_media");
            let count = u32::from_be_bytes(payload[4..8].try_into()?) as usize;
            let mut child = 8usize;
            for _ in 0..count {
                ensure!(child + 12 <= payload.len(), "invalid_media");
                let size = u32::from_be_bytes(payload[child..child + 4].try_into()?) as usize;
                ensure!(
                    size >= 12
                        && child
                            .checked_add(size)
                            .is_some_and(|end| end <= payload.len()),
                    "invalid_media"
                );
                ensure!(&payload[child + 4..child + 8] == b"url ", "invalid_media");
                let flags =
                    u32::from_be_bytes(payload[child + 8..child + 12].try_into()?) & 0x00ff_ffff;
                proof.data_references += 1;
                if flags == 1 && size == 12 {
                    proof.self_contained_data_references += 1;
                }
                child += size;
            }
            ensure!(child == payload.len(), "invalid_media");
        } else if &kind == b"stsd" {
            ensure!(payload.len() >= 8, "invalid_media");
            let count = u32::from_be_bytes(payload[4..8].try_into()?) as usize;
            let mut entry = 8usize;
            for _ in 0..count {
                ensure!(entry + 8 <= payload.len(), "invalid_media");
                let size = u32::from_be_bytes(payload[entry..entry + 4].try_into()?) as usize;
                ensure!(
                    size >= 8
                        && entry
                            .checked_add(size)
                            .is_some_and(|end| end <= payload.len()),
                    "invalid_media"
                );
                match &payload[entry + 4..entry + 8] {
                    b"avc1" => {
                        verify_avc1_sample_entry(&payload[entry..entry + size])?;
                        proof.avc1_entries += 1;
                    }
                    b"mp4a" => {
                        verify_mp4a_sample_entry(&payload[entry..entry + size])?;
                        proof.mp4a_entries += 1;
                    }
                    _ => anyhow::bail!("invalid_media"),
                }
                entry += size;
            }
            ensure!(entry == payload.len(), "invalid_media");
        }
        offset = end;
    }
    ensure!(offset == bytes.len(), "invalid_media");
    Ok(())
}

fn sample_entry_child<'a>(
    entry: &'a [u8],
    child_offset: usize,
    wanted: &[u8; 4],
) -> Result<&'a [u8]> {
    ensure!(entry.len() >= child_offset, "invalid_media");
    let mut offset = child_offset;
    let mut found = None;
    while offset < entry.len() {
        ensure!(offset + 8 <= entry.len(), "invalid_media");
        let size = u32::from_be_bytes(entry[offset..offset + 4].try_into()?) as usize;
        ensure!(
            size >= 8
                && offset
                    .checked_add(size)
                    .is_some_and(|end| end <= entry.len()),
            "invalid_media"
        );
        if &entry[offset + 4..offset + 8] == wanted {
            ensure!(found.is_none(), "invalid_media");
            found = Some(&entry[offset + 8..offset + size]);
        }
        offset += size;
    }
    found.context("invalid_media")
}

fn verify_avc1_sample_entry(entry: &[u8]) -> Result<()> {
    ensure!(
        entry.len() >= 86 && &entry[4..8] == b"avc1",
        "invalid_media"
    );
    let avcc = sample_entry_child(entry, 86, b"avcC")?;
    ensure!(
        avcc.len() >= 7
            && avcc[0] == 1
            && avcc[1] == 100
            && avcc[4] & 0xfc == 0xfc
            && avcc[4] & 3 == 3
            && avcc[5] & 0xe0 == 0xe0
            && avcc[5] & 0x1f > 0,
        "invalid_media"
    );
    Ok(())
}

fn descriptor_length(bytes: &[u8], offset: &mut usize) -> Result<usize> {
    let mut length = 0usize;
    for index in 0..4 {
        let value = *bytes.get(*offset).context("invalid_media")?;
        *offset += 1;
        length = length.checked_mul(128).context("invalid_media")? + usize::from(value & 0x7f);
        if value & 0x80 == 0 {
            return Ok(length);
        }
        ensure!(index < 3, "invalid_media");
    }
    anyhow::bail!("invalid_media")
}

fn verify_mp4a_sample_entry(entry: &[u8]) -> Result<()> {
    ensure!(
        entry.len() >= 36 && &entry[4..8] == b"mp4a",
        "invalid_media"
    );
    let esds = sample_entry_child(entry, 36, b"esds")?;
    ensure!(esds.len() >= 8, "invalid_media");
    let descriptors = &esds[4..];
    let decoder = descriptors
        .iter()
        .position(|value| *value == 0x04)
        .context("invalid_media")?;
    let mut offset = decoder + 1;
    let decoder_length = descriptor_length(descriptors, &mut offset)?;
    ensure!(
        decoder_length >= 13
            && offset + decoder_length <= descriptors.len()
            && descriptors[offset] == 0x40,
        "invalid_media"
    );
    let decoder_end = offset + decoder_length;
    let asc = descriptors[offset + 13..decoder_end]
        .iter()
        .position(|value| *value == 0x05)
        .context("invalid_media")?
        + offset
        + 13;
    let mut asc_offset = asc + 1;
    let asc_length = descriptor_length(descriptors, &mut asc_offset)?;
    ensure!(
        asc_length >= 2
            && asc_offset + asc_length <= decoder_end
            && descriptors[asc_offset] >> 3 == 2,
        "invalid_media"
    );
    Ok(())
}

struct NormalizedImageDerivatives {
    model_png: Vec<u8>,
    thumbnail_png: Vec<u8>,
    width: u32,
    height: u32,
    thumbnail_width: u32,
    thumbnail_height: u32,
}

fn normalize_image(bytes: &[u8], container: &str) -> Result<NormalizedImageDerivatives> {
    use image::{DynamicImage, ImageDecoder as _, ImageFormat, ImageReader, Limits};
    let (format, exif_orientation) = match container {
        "png" => {
            reject_png_color_metadata(bytes)?;
            (ImageFormat::Png, None)
        }
        "jpeg" => (ImageFormat::Jpeg, reject_jpeg_metadata(bytes)?),
        "gif" => {
            reject_gif_structure(bytes)?;
            (ImageFormat::Gif, None)
        }
        "webp" => (ImageFormat::WebP, reject_webp_metadata(bytes)?),
        _ => anyhow::bail!("ambiguous_or_unsupported_container"),
    };
    let mut reader = ImageReader::with_format(std::io::Cursor::new(bytes), format);
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
    let mut decoded = DynamicImage::from_decoder(decoder).context("decode_failed")?;
    if let Some(value) = exif_orientation {
        decoded.apply_orientation(
            image::metadata::Orientation::from_exif(value).context("invalid_media")?,
        );
    }
    let mut rgba = decoded.into_rgba8();
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

fn reject_jpeg_metadata(bytes: &[u8]) -> Result<Option<u8>> {
    ensure!(bytes.starts_with(b"\xff\xd8"), "invalid_media");
    let mut offset = 2usize;
    let mut exif = None;
    while offset + 4 <= bytes.len() {
        ensure!(bytes[offset] == 0xff, "invalid_media");
        let marker = bytes[offset + 1];
        offset += 2;
        if marker == 0xd9 || marker == 0xda {
            break;
        }
        if matches!(marker, 0x01 | 0xd0..=0xd7) {
            continue;
        }
        let length = u16::from_be_bytes(bytes[offset..offset + 2].try_into()?) as usize;
        ensure!(
            length >= 2 && offset + length <= bytes.len(),
            "invalid_media"
        );
        let payload = &bytes[offset + 2..offset + length];
        if marker == 0xe2 && payload.starts_with(b"ICC_PROFILE\0") {
            anyhow::bail!("unsupported_color_profile");
        }
        if marker == 0xee && payload.starts_with(b"Adobe") {
            anyhow::bail!("unsupported_color_profile");
        }
        if marker == 0xe1 && payload.starts_with(b"Exif\0\0") {
            ensure!(exif.is_none(), "invalid_media");
            let parsed = parse_tiff_exif(&payload[6..])?;
            if let Some(color) = parsed.1 {
                ensure!(color == 1, "unsupported_color_profile");
            }
            exif = parsed.0;
        }
        if matches!(
            marker,
            0xc0 | 0xc1
                | 0xc2
                | 0xc3
                | 0xc5
                | 0xc6
                | 0xc7
                | 0xc9
                | 0xca
                | 0xcb
                | 0xcd
                | 0xce
                | 0xcf
        ) {
            ensure!(
                payload.len() >= 6 && payload[5] == 3,
                "unsupported_color_profile"
            );
        }
        offset += length;
    }
    Ok(exif)
}

fn reject_gif_structure(bytes: &[u8]) -> Result<()> {
    ensure!(
        bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a"),
        "invalid_media"
    );
    ensure!(bytes.len() >= 14, "invalid_media");
    let screen_width = u16::from_le_bytes(bytes[6..8].try_into()?) as u64;
    let screen_height = u16::from_le_bytes(bytes[8..10].try_into()?) as u64;
    ensure!(
        screen_width > 0 && screen_height > 0 && screen_width * screen_height <= 40_000_000,
        "resource_limit"
    );
    let packed = bytes[10];
    let mut offset = 13usize;
    if packed & 0x80 != 0 {
        offset = offset
            .checked_add(3usize << (usize::from(packed & 7) + 1))
            .context("invalid_media")?;
    }
    ensure!(offset <= bytes.len(), "invalid_media");
    let mut frames = 0u64;
    let mut aggregate = 0u64;
    while offset < bytes.len() {
        match bytes[offset] {
            0x3b => {
                ensure!(frames > 0 && offset + 1 == bytes.len(), "invalid_media");
                return Ok(());
            }
            0x21 => {
                offset += 2;
                ensure!(offset <= bytes.len(), "invalid_media");
                skip_gif_sub_blocks(bytes, &mut offset)?;
            }
            0x2c => {
                ensure!(offset + 10 <= bytes.len(), "invalid_media");
                let left = u16::from_le_bytes(bytes[offset + 1..offset + 3].try_into()?) as u64;
                let top = u16::from_le_bytes(bytes[offset + 3..offset + 5].try_into()?) as u64;
                let width = u16::from_le_bytes(bytes[offset + 5..offset + 7].try_into()?) as u64;
                let height = u16::from_le_bytes(bytes[offset + 7..offset + 9].try_into()?) as u64;
                ensure!(
                    width > 0
                        && height > 0
                        && left + width <= screen_width
                        && top + height <= screen_height,
                    "invalid_media"
                );
                frames = frames.checked_add(1).context("resource_limit")?;
                aggregate = aggregate
                    .checked_add(width.checked_mul(height).context("resource_limit")?)
                    .context("resource_limit")?;
                ensure!(
                    frames <= 65_536 && aggregate <= 80_000_000,
                    "resource_limit"
                );
                let local = bytes[offset + 9];
                offset += 10;
                if local & 0x80 != 0 {
                    offset = offset
                        .checked_add(3usize << (usize::from(local & 7) + 1))
                        .context("invalid_media")?;
                }
                ensure!(
                    offset < bytes.len() && bytes[offset] >= 2 && bytes[offset] <= 8,
                    "invalid_media"
                );
                offset += 1;
                skip_gif_sub_blocks(bytes, &mut offset)?;
            }
            _ => anyhow::bail!("invalid_media"),
        }
    }
    anyhow::bail!("invalid_media")
}

fn skip_gif_sub_blocks(bytes: &[u8], offset: &mut usize) -> Result<()> {
    loop {
        ensure!(*offset < bytes.len(), "invalid_media");
        let length = usize::from(bytes[*offset]);
        *offset += 1;
        if length == 0 {
            return Ok(());
        }
        *offset = offset.checked_add(length).context("invalid_media")?;
        ensure!(*offset <= bytes.len(), "invalid_media");
    }
}

fn reject_webp_metadata(bytes: &[u8]) -> Result<Option<u8>> {
    ensure!(
        bytes.len() >= 16 && &bytes[..4] == b"RIFF" && &bytes[8..12] == b"WEBP",
        "invalid_media"
    );
    let declared = u32::from_le_bytes(bytes[4..8].try_into()?) as usize;
    ensure!(
        declared.checked_add(8) == Some(bytes.len()),
        "invalid_media"
    );
    let mut offset = 12usize;
    let mut orientation = None;
    let mut exif_seen = false;
    while offset + 8 <= bytes.len() {
        let kind = &bytes[offset..offset + 4];
        let length = u32::from_le_bytes(bytes[offset + 4..offset + 8].try_into()?) as usize;
        let start = offset + 8;
        let end = start.checked_add(length).context("invalid_media")?;
        ensure!(end <= bytes.len(), "invalid_media");
        if kind == b"ICCP" {
            anyhow::bail!("unsupported_color_profile");
        }
        if kind == b"ANIM" || kind == b"ANMF" {
            anyhow::bail!("invalid_media");
        }
        if kind == b"EXIF" {
            ensure!(!exif_seen, "invalid_media");
            exif_seen = true;
            let payload = &bytes[start..end];
            let tiff = payload.strip_prefix(b"Exif\0\0").unwrap_or(payload);
            let parsed = parse_tiff_exif(tiff)?;
            ensure!(parsed.1 == Some(1), "unsupported_color_profile");
            orientation = parsed.0;
        }
        offset = end + (length & 1);
    }
    ensure!(offset == bytes.len(), "invalid_media");
    Ok(orientation)
}

fn parse_tiff_exif(bytes: &[u8]) -> Result<(Option<u8>, Option<u16>)> {
    ensure!(bytes.len() >= 8, "invalid_media");
    let little = match &bytes[..2] {
        b"II" => true,
        b"MM" => false,
        _ => anyhow::bail!("invalid_media"),
    };
    let u16_at = |o: usize| -> Result<u16> {
        let b: [u8; 2] = bytes.get(o..o + 2).context("invalid_media")?.try_into()?;
        Ok(if little {
            u16::from_le_bytes(b)
        } else {
            u16::from_be_bytes(b)
        })
    };
    let u32_at = |o: usize| -> Result<u32> {
        let b: [u8; 4] = bytes.get(o..o + 4).context("invalid_media")?.try_into()?;
        Ok(if little {
            u32::from_le_bytes(b)
        } else {
            u32::from_be_bytes(b)
        })
    };
    ensure!(u16_at(2)? == 42, "invalid_media");
    let ifd = usize::try_from(u32_at(4)?)?;
    let count = usize::from(u16_at(ifd)?);
    ensure!(count <= 256, "resource_limit");
    let mut orientation = None;
    let mut color = None;
    let mut exif_ifd = None;
    for index in 0..count {
        let entry = ifd + 2 + index * 12;
        let tag = u16_at(entry)?;
        if tag == 0x8769 {
            ensure!(
                u16_at(entry + 2)? == 4 && u32_at(entry + 4)? == 1,
                "invalid_media"
            );
            ensure!(
                exif_ifd
                    .replace(usize::try_from(u32_at(entry + 8)?)?)
                    .is_none(),
                "invalid_media"
            );
        }
        if tag == 0x0112 || tag == 0xa001 {
            ensure!(
                u16_at(entry + 2)? == 3 && u32_at(entry + 4)? == 1,
                "invalid_media"
            );
            let value = u16_at(entry + 8)?;
            if tag == 0x0112 {
                ensure!(
                    orientation.replace(u8::try_from(value)?).is_none() && (1..=8).contains(&value),
                    "invalid_media"
                );
            } else {
                ensure!(color.replace(value).is_none(), "invalid_media");
            }
        }
    }
    if let Some(exif_ifd) = exif_ifd {
        let count = usize::from(u16_at(exif_ifd)?);
        ensure!(count <= 256, "resource_limit");
        for index in 0..count {
            let entry = exif_ifd + 2 + index * 12;
            if u16_at(entry)? == 0xa001 {
                ensure!(
                    u16_at(entry + 2)? == 3 && u32_at(entry + 4)? == 1,
                    "invalid_media"
                );
                ensure!(color.replace(u16_at(entry + 8)?).is_none(), "invalid_media");
            }
        }
    }
    Ok((orientation, color))
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

#[cfg(test)]
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
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use cockpit_db::media_attachments::{
        MediaAttachmentComponent, MediaAttachmentRecord, MediaAvailability, MediaKind,
        MediaSecurityRecoveryOutcome, MediaSourceKind, RecoverSecurityBlockedComponentV1,
    };
    use uuid::Uuid;

    use super::*;

    struct FixedMediaClock;
    impl crate::media_reservation::MonotonicClock for FixedMediaClock {
        fn now_ms(&self) -> u64 {
            1
        }
    }

    #[test]
    fn retained_failure_reason_classifier_is_closed_and_redacted() {
        assert_eq!(
            closed_media_failure_reason(&anyhow::anyhow!("ambiguous_or_unsupported_container")),
            "ambiguous_or_unsupported_container"
        );
        assert_eq!(
            closed_media_failure_reason(&anyhow::anyhow!("decode worker rejected bytes")),
            "decode_failed"
        );
        assert_eq!(
            closed_media_failure_reason(&anyhow::anyhow!("encoder returned private detail")),
            "normalization_failed"
        );
        assert_eq!(
            closed_media_failure_reason(&anyhow::Error::new(std::io::Error::other("secret path"))),
            "storage_failure"
        );
    }

    struct ScriptedVideoRunner {
        fail_encode: AtomicBool,
        calls: AtomicUsize,
    }

    struct ScriptedAudioRunner {
        calls: AtomicUsize,
    }

    struct ScriptedHttpsFetcher {
        calls: AtomicUsize,
        bytes: Vec<u8>,
    }

    #[async_trait::async_trait]
    impl crate::media_https::HttpsMediaFetcher for ScriptedHttpsFetcher {
        async fn fetch(
            &self,
            _raw_url: &str,
            sink: &mut tokio::fs::File,
            _limits: &crate::media_https::HttpsFetchLimits,
        ) -> Result<crate::media_https::RetainedHttpsFetchEvidence> {
            use tokio::io::AsyncWriteExt as _;
            self.calls.fetch_add(1, Ordering::SeqCst);
            sink.write_all(&self.bytes).await?;
            Ok(crate::media_https::RetainedHttpsFetchEvidence {
                byte_length: self.bytes.len() as u64,
                sha256: crate::intel::hex_lower(&Sha256::digest(&self.bytes)),
                provenance: crate::media_https::RedactedHttpsProvenance {
                    redirect_classes: vec![crate::media_https::RedirectLocationClass::CrossOrigin],
                    path_segment_count: 2,
                    safe_basename: Some("media.png".into()),
                },
            })
        }
    }

    struct RejectingHttpsFetcher(AtomicUsize);

    #[async_trait::async_trait]
    impl crate::media_https::HttpsMediaFetcher for RejectingHttpsFetcher {
        async fn fetch(
            &self,
            _raw_url: &str,
            _sink: &mut tokio::fs::File,
            _limits: &crate::media_https::HttpsFetchLimits,
        ) -> Result<crate::media_https::RetainedHttpsFetchEvidence> {
            self.0.fetch_add(1, Ordering::SeqCst);
            anyhow::bail!("retained media exceeds byte limit")
        }
    }

    #[async_trait::async_trait]
    impl AvRuntimeRunner for ScriptedVideoRunner {
        async fn run(
            &self,
            _program: &Path,
            args: &[String],
            _input: Vec<u8>,
            _stdout_limit: u64,
            _deadline: std::time::Duration,
        ) -> Result<BoundedRuntimeOutput> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if args.iter().any(|arg| arg == "-show_frames") {
                return Ok(BoundedRuntimeOutput {
                    stdout: br#"{"streams":[{"index":0,"codec_type":"video","codec_name":"h264","disposition":{"default":1},"width":640,"height":360,"sample_aspect_ratio":"1:1","time_base":"1/24000","profile":"High","pix_fmt":"yuv420p"}],"frames":[{"media_type":"video","stream_index":0,"best_effort_timestamp":"0","key_frame":1},{"media_type":"video","stream_index":0,"best_effort_timestamp":"1001","key_frame":0},{"media_type":"video","stream_index":0,"best_effort_timestamp":"2002","key_frame":0}]}"#.to_vec(),
                    stderr: Vec::new(),
                });
            }
            if args.iter().any(|arg| arg == "-encoders") {
                return Ok(BoundedRuntimeOutput {
                    stdout: b" V..... libx264 H.264\n A..... aac AAC\n".to_vec(),
                    stderr: Vec::new(),
                });
            }
            if args.windows(2).any(|pair| pair == ["-f", "null"]) {
                return Ok(BoundedRuntimeOutput {
                    stdout: Vec::new(),
                    stderr: Vec::new(),
                });
            }
            if self.fail_encode.load(Ordering::SeqCst) {
                anyhow::bail!("injected semantic encoder failure")
            }
            let output = args.last().context("missing encoded output")?;
            std::fs::write(output, canonical_video_fixture())?;
            Ok(BoundedRuntimeOutput {
                stdout: Vec::new(),
                stderr: Vec::new(),
            })
        }
    }

    #[async_trait::async_trait]
    impl AvRuntimeRunner for ScriptedAudioRunner {
        async fn run(
            &self,
            _program: &Path,
            args: &[String],
            _input: Vec<u8>,
            _stdout_limit: u64,
            _deadline: std::time::Duration,
        ) -> Result<BoundedRuntimeOutput> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if args.iter().any(|arg| arg == "-show_frames") {
                return Ok(BoundedRuntimeOutput {
                    stdout: br#"{"streams":[{"index":0,"codec_type":"audio","codec_name":"pcm_s16le","disposition":{"default":1},"sample_rate":"48000","channels":1}],"frames":[]}"#.to_vec(),
                    stderr: Vec::new(),
                });
            }
            if args.windows(2).any(|pair| pair == ["-f", "null"]) {
                return Ok(BoundedRuntimeOutput {
                    stdout: Vec::new(),
                    stderr: Vec::new(),
                });
            }
            let mut wav = b"RIFF".to_vec();
            wav.extend_from_slice(&36u32.to_le_bytes());
            wav.extend_from_slice(b"WAVEfmt ");
            wav.extend_from_slice(&16u32.to_le_bytes());
            wav.extend_from_slice(&[1, 0, 1, 0]);
            wav.extend_from_slice(&48_000u32.to_le_bytes());
            wav.extend_from_slice(&96_000u32.to_le_bytes());
            wav.extend_from_slice(&[2, 0, 16, 0]);
            wav.extend_from_slice(b"data");
            wav.extend_from_slice(&0u32.to_le_bytes());
            Ok(BoundedRuntimeOutput {
                stdout: wav,
                stderr: Vec::new(),
            })
        }
    }

    fn mp4_atom(kind: &[u8; 4], payload: &[u8]) -> Vec<u8> {
        let mut atom = Vec::new();
        atom.extend_from_slice(&u32::try_from(payload.len() + 8).unwrap().to_be_bytes());
        atom.extend_from_slice(kind);
        atom.extend_from_slice(payload);
        atom
    }

    fn canonical_video_fixture() -> Vec<u8> {
        let mut dref = vec![0, 0, 0, 0];
        dref.extend_from_slice(&1u32.to_be_bytes());
        dref.extend_from_slice(&12u32.to_be_bytes());
        dref.extend_from_slice(b"url \0\0\0\x01");
        let dinf = mp4_atom(b"dinf", &mp4_atom(b"dref", &dref));
        let avcc = mp4_atom(b"avcC", &[1, 100, 0, 31, 0xff, 0xe1, 0]);
        let mut avc1 = vec![0; 86];
        avc1[0..4].copy_from_slice(&u32::try_from(86 + avcc.len()).unwrap().to_be_bytes());
        avc1[4..8].copy_from_slice(b"avc1");
        avc1.extend_from_slice(&avcc);
        let mut stsd = vec![0, 0, 0, 0];
        stsd.extend_from_slice(&1u32.to_be_bytes());
        stsd.extend_from_slice(&avc1);
        let stbl = mp4_atom(b"stbl", &mp4_atom(b"stsd", &stsd));
        let mut minf = dinf;
        minf.extend_from_slice(&stbl);
        let moov = mp4_atom(
            b"moov",
            &mp4_atom(b"trak", &mp4_atom(b"mdia", &mp4_atom(b"minf", &minf))),
        );
        let mut output = Vec::new();
        output.extend_from_slice(&32u32.to_be_bytes());
        output.extend_from_slice(b"ftypisom");
        output.extend_from_slice(&512u32.to_be_bytes());
        output.extend_from_slice(b"isomiso2avc1mp41");
        output.extend_from_slice(&moov);
        output.extend_from_slice(&8u32.to_be_bytes());
        output.extend_from_slice(b"mdat");
        output
    }

    #[test]
    fn av_byte_classification_rejects_spoofed_mp3_and_normalizes_audio_signatures() {
        assert!(valid_mpeg_audio_prefix(&[0xff, 0xfb, 0x90, 0x64]));
        let mut id3 = vec![
            b'I', b'D', b'3', 4, 0, 0, 0, 0, 0, 1, 0, 0xff, 0xfb, 0x90, 0x64,
        ];
        assert!(valid_mpeg_audio_prefix(&id3));
        id3[6] = 0x80;
        assert!(!valid_mpeg_audio_prefix(&id3));
        for (bytes, kind, container) in [
            (b"RIFF\x04\0\0\0WAVE".as_slice(), MediaKind::Audio, "wav"),
            (b"fLaC\0\0\0\0".as_slice(), MediaKind::Audio, "flac"),
            (b"OggS\0\0\0\0".as_slice(), MediaKind::Audio, "ogg"),
        ] {
            let temp = tempfile::NamedTempFile::new().unwrap();
            std::fs::write(temp.path(), bytes).unwrap();
            let mut file = File::open(temp.path()).unwrap();
            assert_eq!(
                probe_upload_container(&mut file, kind).unwrap().0,
                container
            );
        }
    }

    #[test]
    fn av_stream_selection_is_independent_default_then_index() {
        let streams = vec![
            AvProbeStream {
                index: 4,
                kind: "video",
                codec: "vp9".into(),
                default_disposition: false,
            },
            AvProbeStream {
                index: 2,
                kind: "video",
                codec: "vp8".into(),
                default_disposition: true,
            },
            AvProbeStream {
                index: 9,
                kind: "audio",
                codec: "opus".into(),
                default_disposition: true,
            },
            AvProbeStream {
                index: 1,
                kind: "audio",
                codec: "vorbis".into(),
                default_disposition: false,
            },
        ];
        let (video, audio) = select_av_streams("webm", &streams).unwrap();
        assert_eq!(video.unwrap().index, 2);
        assert_eq!(audio.unwrap().index, 9);
        let unsupported_default = vec![
            AvProbeStream {
                index: 0,
                kind: "audio",
                codec: "ac3".into(),
                default_disposition: true,
            },
            AvProbeStream {
                index: 3,
                kind: "audio",
                codec: "aac".into(),
                default_disposition: false,
            },
        ];
        assert_eq!(
            select_av_streams("m4a", &unsupported_default)
                .unwrap()
                .1
                .unwrap()
                .index,
            3
        );
        assert!(select_av_streams("mp4", &unsupported_default).is_err());
        assert!(
            select_av_streams(
                "wav",
                &[
                    AvProbeStream {
                        index: 0,
                        kind: "audio",
                        codec: "pcm_s16le".into(),
                        default_disposition: false
                    },
                    AvProbeStream {
                        index: 1,
                        kind: "video",
                        codec: "h264".into(),
                        default_disposition: false
                    }
                ]
            )
            .is_err()
        );
    }

    #[test]
    fn video_dimension_rational_search_matches_exact_vectors() {
        for (input, sar, output) in [
            ((1920, 1080), (1, 1), (1280, 720)),
            ((640, 360), (1, 1), (640, 360)),
            ((1440, 1080), (4, 3), (1280, 720)),
            ((720, 480), (8, 9), (640, 480)),
            ((3, 3), (1, 1), (2, 2)),
        ] {
            assert_eq!(
                select_video_dimensions(input.0, input.1, sar.0, sar.1).unwrap(),
                output
            );
        }
        assert!(
            select_video_dimensions(1, 1080, 1, 1)
                .unwrap_err()
                .to_string()
                .contains("video_dimensions_too_small")
        );
    }

    #[test]
    fn display_matrix_accepts_exact_rotation_and_mirror_only() {
        let matrix = |values: [i64; 9]| {
            format!(
                "00000000: {} {} {}\n00000001: {} {} {}\n00000002: {} {} {}",
                values[0],
                values[1],
                values[2],
                values[3],
                values[4],
                values[5],
                values[6],
                values[7],
                values[8]
            )
        };
        let stream = |rotation, values| FfprobeStream {
            index: 0,
            codec_type: "video".into(),
            codec_name: "h264".into(),
            disposition: None,
            sample_rate: None,
            channels: None,
            width: Some(640),
            height: Some(360),
            sample_aspect_ratio: Some("1:1".into()),
            time_base: Some("1/24".into()),
            profile: Some("High".into()),
            pix_fmt: Some("yuv420p".into()),
            side_data_list: vec![FfprobeSideData {
                rotation: Some(rotation),
                displaymatrix: Some(matrix(values)),
            }],
        };
        assert_eq!(
            oriented_video_dimensions(&stream(
                90,
                [0, -65_536, 0, 65_536, 0, 0, 0, 0, 1_073_741_824]
            ))
            .unwrap(),
            (360, 640)
        );
        assert_eq!(
            oriented_video_dimensions(&stream(
                0,
                [-65_536, 0, 0, 0, 65_536, 0, 0, 0, 1_073_741_824]
            ))
            .unwrap(),
            (640, 360)
        );
        assert!(
            oriented_video_dimensions(&stream(
                0,
                [32_768, 0, 0, 0, 65_536, 0, 0, 0, 1_073_741_824]
            ))
            .is_err()
        );
    }

    #[test]
    fn iso_brand_and_ebml_doctype_classification_is_closed() {
        let ftyp = |major: [u8; 4], brands: &[[u8; 4]]| {
            let size = 16 + brands.len() * 4;
            let mut bytes = Vec::new();
            bytes.extend_from_slice(&(size as u32).to_be_bytes());
            bytes.extend_from_slice(b"ftyp");
            bytes.extend_from_slice(&major);
            bytes.extend_from_slice(&512u32.to_be_bytes());
            for brand in brands {
                bytes.extend_from_slice(brand);
            }
            bytes
        };
        assert_eq!(
            classify_iso_bmff(&ftyp(*b"qt  ", &[*b"qt  "]), true, 1).unwrap(),
            "mov"
        );
        assert_eq!(
            classify_iso_bmff(&ftyp(*b"M4A ", &[*b"isom", *b"mp42"]), false, 1).unwrap(),
            "m4a"
        );
        assert_eq!(
            classify_iso_bmff(&ftyp(*b"isom", &[*b"iso2", *b"avc1"]), true, 1).unwrap(),
            "mp4"
        );
        assert!(classify_iso_bmff(&ftyp(*b"isom", &[*b"iso2", *b"iso2"]), true, 0).is_err());
        assert!(classify_iso_bmff(&ftyp(*b"M4A ", &[*b"isom"]), true, 1).is_err());
        assert!(
            ebml_doctype_is_webm(&[
                0x1a, 0x45, 0xdf, 0xa3, 0x42, 0x82, 0x84, b'w', b'e', b'b', b'm'
            ])
            .unwrap()
        );
        assert!(
            !ebml_doctype_is_webm(&[
                0x1a, 0x45, 0xdf, 0xa3, 0x42, 0x82, 0x88, b'm', b'a', b't', b'r', b'o', b's', b'k',
                b'a'
            ])
            .unwrap()
        );
    }

    #[test]
    fn av_normalization_argv_is_exact_and_shell_free() {
        let mono = audio_normalization_argv(3, 96_000, 1).unwrap();
        assert!(
            mono.windows(2)
                .any(|pair| pair[0] == "-map" && pair[1] == "0:3")
        );
        assert!(
            mono.windows(2)
                .any(|pair| pair[0] == "-ac" && pair[1] == "1")
        );
        assert!(
            mono.windows(2)
                .any(|pair| pair[0] == "-ar" && pair[1] == "48000")
        );
        assert!(mono.iter().any(|arg| arg.contains("dither_method=none")));
        let video =
            video_normalization_argv(2, Some(9), Some((96_000, 6)), 1280, 720, 24, 1, 240, 24)
                .unwrap();
        for exact in [
            "scale=1280:720:flags=lanczos,fps=24/1:start_time=0:round=down,format=yuv420p",
            "threads=1:scenecut=0:keyint=240:min-keyint=24:bframes=3:ref=3",
            "+faststart",
        ] {
            assert!(video.iter().any(|arg| arg == exact));
        }
        assert!(
            !video
                .iter()
                .any(|arg| matches!(arg.as_str(), "sh" | "-c" | "cmd.exe"))
        );
    }

    #[test]
    fn video_frame_rate_uses_exact_timestamp_rationals() {
        assert_eq!(select_video_rate(&[(0, 1)]).unwrap(), (1, 1, 10, 1));
        let rate = select_video_rate(&[(0, 1), (1001, 24000), (2002, 24000)]).unwrap();
        assert_eq!((rate.0, rate.1), (24000, 1001));
        let rate = select_video_rate(&[(0, 1), (1001, 30000), (2002, 30000)]).unwrap();
        assert_eq!((rate.0, rate.1), (24, 1));
        let rate = select_video_rate(&[(0, 1), (1, 10), (1, 2)]).unwrap();
        assert_eq!((rate.0, rate.1), (4, 1));
        assert!(select_video_rate(&[(0, 1), (0, 1)]).is_err());
        assert!(select_video_rate(&[(0, 1), (1, 0)]).is_err());
    }

    #[test]
    fn canonical_wav_strips_metadata_and_rejects_non_pcm() {
        let mut body = Vec::new();
        body.extend_from_slice(b"WAVEfmt \x10\0\0\0");
        body.extend_from_slice(&1u16.to_le_bytes());
        body.extend_from_slice(&1u16.to_le_bytes());
        body.extend_from_slice(&48_000u32.to_le_bytes());
        body.extend_from_slice(&96_000u32.to_le_bytes());
        body.extend_from_slice(&2u16.to_le_bytes());
        body.extend_from_slice(&16u16.to_le_bytes());
        body.extend_from_slice(b"JUNK\x02\0\0\0xxdata\x02\0\0\0\x01\0");
        let mut wav = b"RIFF".to_vec();
        wav.extend_from_slice(&u32::try_from(body.len()).unwrap().to_le_bytes());
        wav.extend_from_slice(&body);
        let canonical = canonicalize_pcm_wav(&wav).unwrap();
        assert_eq!(&canonical[12..20], b"fmt \x10\0\0\0");
        assert_eq!(&canonical[36..40], b"data");
        assert!(!canonical.windows(4).any(|chunk| chunk == b"JUNK"));
        let mut invalid = wav;
        invalid[20] = 3;
        assert!(canonicalize_pcm_wav(&invalid).is_err());
    }

    #[test]
    fn canonical_video_mp4_requires_exact_brands_and_moov_before_mdat() {
        let atom = |kind: &[u8; 4], payload: &[u8]| {
            let mut atom = Vec::new();
            atom.extend_from_slice(&u32::try_from(payload.len() + 8).unwrap().to_be_bytes());
            atom.extend_from_slice(kind);
            atom.extend_from_slice(payload);
            atom
        };
        let mut dref = vec![0, 0, 0, 0];
        dref.extend_from_slice(&1u32.to_be_bytes());
        dref.extend_from_slice(&12u32.to_be_bytes());
        dref.extend_from_slice(b"url \0\0\0\x01");
        let dinf = atom(b"dinf", &atom(b"dref", &dref));
        let mut stsd = vec![0, 0, 0, 0];
        stsd.extend_from_slice(&1u32.to_be_bytes());
        let avcc = atom(b"avcC", &[1, 100, 0, 31, 0xff, 0xe1, 0]);
        let mut avc1 = vec![0; 86];
        avc1[0..4].copy_from_slice(&u32::try_from(86 + avcc.len()).unwrap().to_be_bytes());
        avc1[4..8].copy_from_slice(b"avc1");
        avc1.extend_from_slice(&avcc);
        stsd.extend_from_slice(&avc1);
        let stbl = atom(b"stbl", &atom(b"stsd", &stsd));
        let mut minf_payload = dinf;
        minf_payload.extend_from_slice(&stbl);
        let minf = atom(b"minf", &minf_payload);
        let mdia = atom(b"mdia", &minf);
        let trak = atom(b"trak", &mdia);
        let moov = atom(b"moov", &trak);
        let mut output = Vec::new();
        output.extend_from_slice(&32u32.to_be_bytes());
        output.extend_from_slice(b"ftypisom");
        output.extend_from_slice(&512u32.to_be_bytes());
        output.extend_from_slice(b"isomiso2avc1mp41");
        output.extend_from_slice(&moov);
        output.extend_from_slice(&8u32.to_be_bytes());
        output.extend_from_slice(b"mdat");
        verify_canonical_video_mp4(&output).unwrap();
        let mut bad_brand = output.clone();
        bad_brand[20..24].copy_from_slice(b"mp42");
        assert!(verify_canonical_video_mp4(&bad_brand).is_err());
        let mut bad_order = output[..32].to_vec();
        bad_order.extend_from_slice(&output[32 + moov.len()..]);
        bad_order.extend_from_slice(&output[32..32 + moov.len()]);
        assert!(verify_canonical_video_mp4(&bad_order).is_err());
    }

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
        let first = normalize_image(input.get_ref(), "png").unwrap();
        let second = normalize_image(input.get_ref(), "png").unwrap();
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

    #[test]
    fn jpeg_gif_and_webp_decode_to_the_same_canonical_contract() {
        let source = image::DynamicImage::ImageRgba8(image::RgbaImage::from_pixel(
            3,
            2,
            image::Rgba([12, 34, 56, 255]),
        ));
        for (container, format) in [
            ("jpeg", image::ImageFormat::Jpeg),
            ("gif", image::ImageFormat::Gif),
            ("webp", image::ImageFormat::WebP),
        ] {
            let mut encoded = std::io::Cursor::new(Vec::new());
            source.write_to(&mut encoded, format).unwrap();
            let first = normalize_image(encoded.get_ref(), container).unwrap();
            let second = normalize_image(encoded.get_ref(), container).unwrap();
            assert_eq!(first.model_png, second.model_png);
            assert_eq!((first.width, first.height), (3, 2));
            assert_eq!(
                png_chunk_names(&first.model_png),
                vec![*b"IHDR", *b"sRGB", *b"IDAT", *b"IEND"]
            );
        }
    }

    #[test]
    fn exif_orientation_and_color_vectors_are_strict() {
        fn tiff(entries: &[(u16, u16)]) -> Vec<u8> {
            let mut out = b"II\x2a\0\x08\0\0\0".to_vec();
            out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
            for (tag, value) in entries {
                out.extend_from_slice(&tag.to_le_bytes());
                out.extend_from_slice(&3u16.to_le_bytes());
                out.extend_from_slice(&1u32.to_le_bytes());
                out.extend_from_slice(&value.to_le_bytes());
                out.extend_from_slice(&[0, 0]);
            }
            out.extend_from_slice(&0u32.to_le_bytes());
            out
        }
        for orientation in 1..=8 {
            assert_eq!(
                parse_tiff_exif(&tiff(&[(0x0112, orientation), (0xa001, 1)])).unwrap(),
                (Some(orientation as u8), Some(1))
            );
        }
        assert!(parse_tiff_exif(&tiff(&[(0x0112, 0)])).is_err());
        assert!(parse_tiff_exif(&tiff(&[(0x0112, 1), (0x0112, 1)])).is_err());
        assert!(parse_tiff_exif(&tiff(&[(0xa001, 2)])).is_ok());
        let exif = tiff(&[(0x0112, 6), (0xa001, 1)]);
        let mut webp = b"RIFF".to_vec();
        let size = 4 + 8 + exif.len() + (exif.len() & 1);
        webp.extend_from_slice(&(size as u32).to_le_bytes());
        webp.extend_from_slice(b"WEBPEXIF");
        webp.extend_from_slice(&(exif.len() as u32).to_le_bytes());
        webp.extend_from_slice(&exif);
        if exif.len() & 1 == 1 {
            webp.push(0);
        }
        assert_eq!(reject_webp_metadata(&webp).unwrap(), Some(6));
        let bad = tiff(&[(0xa001, 2)]);
        let mut bad_webp = b"RIFF".to_vec();
        let size = 4 + 8 + bad.len() + (bad.len() & 1);
        bad_webp.extend_from_slice(&(size as u32).to_le_bytes());
        bad_webp.extend_from_slice(b"WEBPEXIF");
        bad_webp.extend_from_slice(&(bad.len() as u32).to_le_bytes());
        bad_webp.extend_from_slice(&bad);
        if bad.len() & 1 == 1 {
            bad_webp.push(0);
        }
        assert!(reject_webp_metadata(&bad_webp).is_err());
    }

    #[test]
    fn gif_walker_rejects_missing_trailer_and_out_of_canvas_frame() {
        let mut missing = b"GIF89a\x01\0\x01\0\0\0\0".to_vec();
        missing.extend_from_slice(&[0x2c, 0, 0, 0, 0, 1, 0, 1, 0, 0, 2, 1, 0, 0]);
        assert!(reject_gif_structure(&missing).is_err());
        let mut outside = b"GIF89a\x01\0\x01\0\0\0\0".to_vec();
        outside.extend_from_slice(&[0x2c, 1, 0, 0, 0, 1, 0, 1, 0, 0, 2, 1, 0, 0, 0x3b]);
        assert!(reject_gif_structure(&outside).is_err());
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
            .read(move |conn| {
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
    async fn https_media_ingest_production_publication_replays_conflicts_and_reopens() {
        let temp = tempfile::TempDir::new().unwrap();
        let db = cockpit_db::Db::open_in_memory_async().await.unwrap();
        let session_id = Uuid::now_v7();
        db.transaction(move |conn| { conn.execute("INSERT INTO sessions(session_id,project_id,project_root,started_at,last_active_at) VALUES(?1,'project','/redacted',1,1)",[session_id.to_string()])?; Ok(()) }).await.unwrap();
        let mut png = std::io::Cursor::new(Vec::new());
        image::DynamicImage::ImageRgba8(image::RgbaImage::from_pixel(
            2,
            2,
            image::Rgba([12, 34, 56, 255]),
        ))
        .write_to(&mut png, image::ImageFormat::Png)
        .unwrap();
        let fetcher = std::sync::Arc::new(ScriptedHttpsFetcher {
            calls: AtomicUsize::new(0),
            bytes: png.into_inner(),
        });
        let recovery = MediaStorageRecovery::open_or_create(db.clone(), &temp.path().join("media"))
            .unwrap()
            .with_https_fetcher(fetcher.clone());
        let request = RetainHttpsMediaV1 {
            schema_version: 1,
            kind: "retainHttpsMedia".into(),
            local_operation_id: Uuid::now_v7(),
            owner_principal_digest: "22".repeat(32),
            session_id,
            canonical_project_digest: "11".repeat(32),
            client_draft_id: Uuid::now_v7(),
            requested_media_kind: RequestedLocalPathMediaKind::Image,
            url: "https://media.example.test/private/media.png?token=secret".into(),
        };
        let policy = cockpit_config::config::media_budget::MediaResourcePolicy::default();
        let first = recovery
            .retain_https_media(request.clone(), &policy, 1, 10)
            .await
            .unwrap();
        assert_eq!(
            db.read(|conn| Ok(conn.query_row(
                "SELECT COUNT(*) FROM media_attachment_processing_jobs WHERE state='pending'",
                [],
                |row| row.get::<_, i64>(0),
            )?))
            .await
            .unwrap(),
            1
        );
        assert_eq!(fetcher.calls.load(Ordering::SeqCst), 1);
        let attachment_id = match &first.result {
            HttpsRetentionResultV1::Retained { attachment_id, .. } => *attachment_id,
            _ => unreachable!(),
        };
        let job_id = db
            .read(move |conn| {
                Ok(conn.query_row(
                    "SELECT job_id FROM media_attachment_processing_jobs WHERE attachment_id=?1",
                    [attachment_id.to_string()],
                    |r| r.get::<_, String>(0),
                )?)
            })
            .await
            .unwrap();
        let orphan_ids = vec![Uuid::now_v7().to_string(), Uuid::now_v7().to_string()];
        for id in &orphan_ids {
            let mut file = recovery.owned_root.create_file_exclusive(id).unwrap();
            file.write_all(b"crashed derivative").unwrap();
            file.sync_all().unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                assert_eq!(file.metadata().unwrap().permissions().mode() & 0o777, 0o600);
            }
        }
        let orphan_json = serde_json::to_string(&orphan_ids).unwrap();
        let intent_job = job_id.clone();
        db.transaction(move|conn|{conn.execute("INSERT INTO media_attachment_processing_publication_intents(job_id,output_ids_json,created_at_unix_ms) VALUES(?1,?2,20)",params![intent_job,orphan_json])?;Ok(())}).await.unwrap();
        drop(recovery);
        let recovery = MediaStorageRecovery::open(db.clone(), &temp.path().join("media"))
            .unwrap()
            .with_https_fetcher(fetcher.clone());
        assert_eq!(recovery.reconcile_media_uploads(21).await.unwrap(), 1);
        for id in &orphan_ids {
            assert!(!temp.path().join("media").join(id).exists());
        }
        assert_eq!(
            db.read(move |conn| Ok(conn.query_row(
                "SELECT COUNT(*) FROM media_attachment_processing_cleanup_evidence WHERE job_id=?1",
                [job_id],
                |r| r.get::<_, i64>(0)
            )?))
            .await
            .unwrap(),
            1
        );
        db.transaction(move|conn|{conn.execute("UPDATE media_attachment_processing_jobs SET state='claimed',claimed_at_unix_ms=1,claim_attempt=1 WHERE attachment_id=?1",[attachment_id.to_string()])?;cockpit_db::Db::transition_media_attachment_conn(conn,attachment_id,1,1,MediaAvailability::Probing,2)?;Ok(())}).await.unwrap();
        assert_eq!(
            recovery.process_retained_https_jobs(300_002).await.unwrap(),
            1
        );
        let ready = db.read(move|conn|Ok(conn.query_row("SELECT availability,(SELECT COUNT(*) FROM media_attachment_components c WHERE c.attachment_id=a.attachment_id AND c.component_kind IN ('image_model','browser_thumbnail')) FROM media_attachments a WHERE attachment_id=?1",[attachment_id.to_string()],|r|Ok((r.get::<_,String>(0)?,r.get::<_,i64>(1)?)))?)).await.unwrap();
        assert_eq!(ready, ("ready".into(), 2));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let storage_ids = db
                .read(move |conn| {
                    let mut statement = conn.prepare(
                        "SELECT storage_id FROM media_attachment_components WHERE attachment_id=?1 ORDER BY component_kind",
                    )?;
                    Ok(statement
                        .query_map([attachment_id.to_string()], |row| row.get::<_, String>(0))?
                        .collect::<std::result::Result<Vec<_>, _>>()?)
                })
                .await
                .unwrap();
            assert_eq!(storage_ids.len(), 3);
            for storage_id in storage_ids {
                assert_eq!(
                    std::fs::metadata(temp.path().join("media").join(storage_id))
                        .unwrap()
                        .permissions()
                        .mode()
                        & 0o777,
                    0o600
                );
            }
        }
        assert_eq!(
            recovery
                .retain_https_media(request.clone(), &policy, 2, 11)
                .await
                .unwrap(),
            first
        );
        let mut alias = request.clone();
        alias.local_operation_id = Uuid::now_v7();
        assert_eq!(
            recovery
                .retain_https_media(alias, &policy, 3, 12)
                .await
                .unwrap(),
            first
        );
        assert_eq!(
            fetcher.calls.load(Ordering::SeqCst),
            1,
            "replays and aliases must precede DNS/fetch"
        );
        let mut conflict = request.clone();
        conflict.url = "https://other.example.test/changed".into();
        assert!(
            recovery
                .retain_https_media(conflict, &policy, 4, 13)
                .await
                .unwrap_err()
                .to_string()
                .contains("conflict")
        );
        assert_eq!(fetcher.calls.load(Ordering::SeqCst), 1);
        drop(recovery);
        let reopened = MediaStorageRecovery::open(db, &temp.path().join("media")).unwrap();
        assert_eq!(
            reopened
                .retain_https_media(request, &policy, 5, 14)
                .await
                .unwrap(),
            first
        );
    }

    #[tokio::test]
    async fn https_media_ingest_publication_fault_cuts_roll_back_and_reconcile_orphan() {
        for table in [
            "media_attachment_components",
            "media_retained_https_evidence",
            "media_attachment_processing_jobs",
            "media_retained_https_operations",
            "media_retained_https_audit",
        ] {
            let temp = tempfile::TempDir::new().unwrap();
            let db = cockpit_db::Db::open_in_memory_async().await.unwrap();
            let session_id = Uuid::now_v7();
            let trigger = format!(
                "CREATE TRIGGER fail_https_cut BEFORE INSERT ON {table} BEGIN SELECT RAISE(ABORT,'injected retained HTTPS fault'); END;"
            );
            db.transaction(move|conn|{conn.execute("INSERT INTO sessions(session_id,project_id,project_root,started_at,last_active_at) VALUES(?1,'project','/redacted',1,1)",[session_id.to_string()])?;conn.execute_batch(&trigger)?;Ok(())}).await.unwrap();
            let recovery =
                MediaStorageRecovery::open_or_create(db.clone(), &temp.path().join("media"))
                    .unwrap()
                    .with_https_fetcher(std::sync::Arc::new(ScriptedHttpsFetcher {
                        calls: AtomicUsize::new(0),
                        bytes: b"fault fixture".to_vec(),
                    }));
            let request = RetainHttpsMediaV1 {
                schema_version: 1,
                kind: "retainHttpsMedia".into(),
                local_operation_id: Uuid::now_v7(),
                owner_principal_digest: "22".repeat(32),
                session_id,
                canonical_project_digest: "11".repeat(32),
                client_draft_id: Uuid::now_v7(),
                requested_media_kind: RequestedLocalPathMediaKind::Image,
                url: "https://media.example.test/fault.bin".into(),
            };
            let error = recovery
                .retain_https_media(
                    request,
                    &cockpit_config::config::media_budget::MediaResourcePolicy::default(),
                    1,
                    10,
                )
                .await
                .unwrap_err();
            assert!(
                format!("{error:#}").contains("injected retained HTTPS fault"),
                "{table}: {error:#}"
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
                        conn.query_row(
                            "SELECT COUNT(*) FROM media_attachment_components",
                            [],
                            |r| r.get::<_, i64>(0),
                        )?,
                        conn.query_row(
                            "SELECT COUNT(*) FROM media_retained_https_evidence",
                            [],
                            |r| r.get::<_, i64>(0),
                        )?,
                        conn.query_row(
                            "SELECT COUNT(*) FROM media_attachment_processing_jobs",
                            [],
                            |r| r.get::<_, i64>(0),
                        )?,
                        conn.query_row(
                            "SELECT COUNT(*) FROM media_retained_https_operations",
                            [],
                            |r| r.get::<_, i64>(0),
                        )?,
                        conn.query_row(
                            "SELECT COUNT(*) FROM media_retained_https_audit",
                            [],
                            |r| r.get::<_, i64>(0),
                        )?,
                        conn.query_row(
                            "SELECT COUNT(*) FROM media_retained_https_publication_intents",
                            [],
                            |r| r.get::<_, i64>(0),
                        )?,
                    ))
                })
                .await
                .unwrap();
            assert_eq!(counts, (0, 0, 0, 0, 0, 0, 0, 1), "{table}");
            assert_eq!(recovery.reconcile_media_uploads(11).await.unwrap(), 1);
            assert_eq!(
                db.read(|conn| Ok(conn.query_row(
                    "SELECT COUNT(*) FROM media_retained_https_publication_intents",
                    [],
                    |r| r.get::<_, i64>(0),
                )?))
                .await
                .unwrap(),
                0,
                "{table}"
            );
        }
    }

    #[tokio::test]
    async fn https_media_ingest_rejection_is_stable_and_replays_before_fetch() {
        let temp = tempfile::TempDir::new().unwrap();
        let db = cockpit_db::Db::open_in_memory_async().await.unwrap();
        let session_id = Uuid::now_v7();
        db.transaction(move|conn|{conn.execute("INSERT INTO sessions(session_id,project_id,project_root,started_at,last_active_at) VALUES(?1,'project','/redacted',1,1)",[session_id.to_string()])?;Ok(())}).await.unwrap();
        let fetcher = std::sync::Arc::new(RejectingHttpsFetcher(AtomicUsize::new(0)));
        let recovery = MediaStorageRecovery::open_or_create(db.clone(), &temp.path().join("media"))
            .unwrap()
            .with_https_fetcher(fetcher.clone());
        let request = RetainHttpsMediaV1 {
            schema_version: 1,
            kind: "retainHttpsMedia".into(),
            local_operation_id: Uuid::now_v7(),
            owner_principal_digest: "22".repeat(32),
            session_id,
            canonical_project_digest: "11".repeat(32),
            client_draft_id: Uuid::now_v7(),
            requested_media_kind: RequestedLocalPathMediaKind::Image,
            url: "https://media.example.test/large".into(),
        };
        let policy = cockpit_config::config::media_budget::MediaResourcePolicy::default();
        let first = recovery
            .retain_https_media(request.clone(), &policy, 1, 10)
            .await
            .unwrap();
        assert!(matches!(
            first.result,
            HttpsRetentionResultV1::Rejected {
                reason: HttpsRetentionRejectionReasonV1::ResourceLimit
            }
        ));
        assert_eq!(
            recovery
                .retain_https_media(request, &policy, 2, 11)
                .await
                .unwrap(),
            first
        );
        assert_eq!(fetcher.0.load(Ordering::SeqCst), 1);
        let counts = db
            .read(|conn| {
                Ok((
                    conn.query_row("SELECT COUNT(*) FROM media_attachments", [], |r| {
                        r.get::<_, i64>(0)
                    })?,
                    conn.query_row(
                        "SELECT COUNT(*) FROM media_retained_https_publication_intents",
                        [],
                        |r| r.get::<_, i64>(0),
                    )?,
                    conn.query_row(
                        "SELECT COUNT(*) FROM media_retained_https_orphan_cleanup_evidence WHERE outcome='verified_unlink'",
                        [],
                        |r| r.get::<_, i64>(0),
                    )?,
                ))
            })
            .await
            .unwrap();
        assert_eq!(counts, (0, 0, 1));
    }

    #[tokio::test]
    async fn https_media_ingest_processing_proof_failure_blocks_with_evidence() {
        let temp = tempfile::TempDir::new().unwrap();
        let db = cockpit_db::Db::open_in_memory_async().await.unwrap();
        let session_id = Uuid::now_v7();
        db.transaction(move |conn| {
            conn.execute(
                "INSERT INTO sessions(session_id,project_id,project_root,started_at,last_active_at) VALUES(?1,'p','/redacted',1,1)",
                [session_id.to_string()],
            )?;
            Ok(())
        })
        .await
        .unwrap();
        let mut png = std::io::Cursor::new(Vec::new());
        image::DynamicImage::ImageRgba8(image::RgbaImage::from_pixel(
            2,
            2,
            image::Rgba([1, 2, 3, 255]),
        ))
        .write_to(&mut png, image::ImageFormat::Png)
        .unwrap();
        let recovery = MediaStorageRecovery::open_or_create(db.clone(), &temp.path().join("media"))
            .unwrap()
            .with_https_fetcher(std::sync::Arc::new(ScriptedHttpsFetcher {
                calls: AtomicUsize::new(0),
                bytes: png.into_inner(),
            }));
        let request = RetainHttpsMediaV1 {
            schema_version: 1,
            kind: "retainHttpsMedia".into(),
            local_operation_id: Uuid::now_v7(),
            owner_principal_digest: "22".repeat(32),
            session_id,
            canonical_project_digest: "11".repeat(32),
            client_draft_id: Uuid::now_v7(),
            requested_media_kind: RequestedLocalPathMediaKind::Image,
            url: "https://media.example.test/image.png".into(),
        };
        recovery
            .retain_https_media(
                request,
                &cockpit_config::config::media_budget::MediaResourcePolicy::default(),
                1,
                10,
            )
            .await
            .unwrap();
        let storage=db.read(|conn|Ok(conn.query_row("SELECT storage_id FROM media_attachment_components WHERE component_kind='quarantined_original'",[],|r|r.get::<_,String>(0))?)).await.unwrap();
        std::fs::write(
            temp.path().join("media").join(storage),
            b"tampered same path",
        )
        .unwrap();
        assert_eq!(recovery.process_retained_https_jobs(11).await.unwrap(), 1);
        let state=db.read(|conn|Ok((conn.query_row("SELECT availability FROM media_attachments",[],|r|r.get::<_,String>(0))?,conn.query_row("SELECT COUNT(*) FROM media_attachment_processing_security_evidence",[],|r|r.get::<_,i64>(0))?,conn.query_row("SELECT COUNT(*) FROM media_attachment_components WHERE component_kind IN ('image_model','browser_thumbnail')",[],|r|r.get::<_,i64>(0))?))).await.unwrap();
        assert_eq!(state, ("security_blocked".into(), 1, 0));
    }

    #[tokio::test]
    async fn https_media_ingest_semantic_failure_is_terminal_not_reclaimed() {
        let temp = tempfile::TempDir::new().unwrap();
        let db = cockpit_db::Db::open_in_memory_async().await.unwrap();
        let session_id = Uuid::now_v7();
        db.transaction(move|conn|{conn.execute("INSERT INTO sessions(session_id,project_id,project_root,started_at,last_active_at) VALUES(?1,'p','/redacted',1,1)",[session_id.to_string()])?;Ok(())}).await.unwrap();
        let recovery = MediaStorageRecovery::open_or_create(db.clone(), &temp.path().join("media"))
            .unwrap()
            .with_https_fetcher(std::sync::Arc::new(ScriptedHttpsFetcher {
                calls: AtomicUsize::new(0),
                bytes: b"not media".to_vec(),
            }));
        let request = RetainHttpsMediaV1 {
            schema_version: 1,
            kind: "retainHttpsMedia".into(),
            local_operation_id: Uuid::now_v7(),
            owner_principal_digest: "22".repeat(32),
            session_id,
            canonical_project_digest: "11".repeat(32),
            client_draft_id: Uuid::now_v7(),
            requested_media_kind: RequestedLocalPathMediaKind::Image,
            url: "https://media.example.test/bad".into(),
        };
        recovery
            .retain_https_media(
                request,
                &cockpit_config::config::media_budget::MediaResourcePolicy::default(),
                1,
                10,
            )
            .await
            .unwrap();
        assert_eq!(recovery.process_retained_https_jobs(11).await.unwrap(), 1);
        assert_eq!(
            recovery
                .process_retained_https_jobs(1_000_000)
                .await
                .unwrap(),
            0
        );
        let state = db
            .read(|conn| {
                Ok((
                    conn.query_row("SELECT availability FROM media_attachments", [], |r| {
                        r.get::<_, String>(0)
                    })?,
                    conn.query_row(
                        "SELECT COUNT(*) FROM media_attachment_processing_failure_evidence",
                        [],
                        |r| r.get::<_, i64>(0),
                    )?,
                    conn.query_row(
                        "SELECT reason FROM media_attachment_failure_reasons",
                        [],
                        |r| r.get::<_, String>(0),
                    )?,
                ))
            })
            .await
            .unwrap();
        assert_eq!(
            state,
            (
                "failed".into(),
                1,
                "ambiguous_or_unsupported_container".into()
            )
        );
        let attachment_id = db
            .read(|conn| {
                Ok(Uuid::parse_str(&conn.query_row(
                    "SELECT attachment_id FROM media_attachments",
                    [],
                    |r| r.get::<_, String>(0),
                )?)?)
            })
            .await
            .unwrap();
        let status = db
            .read(move |conn| {
                cockpit_db::Db::media_attachment_status_for_owner_conn(
                    conn,
                    &cockpit_db::media_attachments::GetMediaAttachmentStatusV1 {
                        schema_version: 1,
                        kind: "getMediaAttachmentStatus".into(),
                        session_id,
                        canonical_project_digest: "11".repeat(32),
                        attachment_id,
                    },
                )
            })
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            status.detail,
            cockpit_db::media_attachments::MediaAttachmentStatusDetailV1::Failed {
                reason: cockpit_db::media_attachments::MediaAttachmentReasonV1::AmbiguousOrUnsupportedContainer
            }
        ));
    }

    #[tokio::test]
    async fn retained_audio_runtime_unavailable_is_terminal_and_not_reclaimed() {
        let temp = tempfile::TempDir::new().unwrap();
        let db = cockpit_db::Db::open_in_memory_async().await.unwrap();
        let session_id = Uuid::now_v7();
        db.transaction(move |conn| {
            conn.execute("INSERT INTO sessions(session_id,project_id,project_root,started_at,last_active_at) VALUES(?1,'p','/redacted',1,1)",[session_id.to_string()])?;
            Ok(())
        }).await.unwrap();
        let mut wav = b"RIFF".to_vec();
        wav.extend_from_slice(&36u32.to_le_bytes());
        wav.extend_from_slice(b"WAVEfmt ");
        wav.extend_from_slice(&16u32.to_le_bytes());
        wav.extend_from_slice(&[1, 0, 1, 0]);
        wav.extend_from_slice(&48_000u32.to_le_bytes());
        wav.extend_from_slice(&96_000u32.to_le_bytes());
        wav.extend_from_slice(&[2, 0, 16, 0]);
        wav.extend_from_slice(b"data");
        wav.extend_from_slice(&0u32.to_le_bytes());
        let recovery = MediaStorageRecovery::open_or_create(db.clone(), &temp.path().join("media"))
            .unwrap()
            .with_https_fetcher(std::sync::Arc::new(ScriptedHttpsFetcher {
                calls: AtomicUsize::new(0),
                bytes: wav,
            }))
            .with_av_runtime(ApprovedAvRuntime {
                ffmpeg: "/definitely-missing/ffmpeg".into(),
                ffprobe: "/definitely-missing/ffprobe".into(),
                fingerprint: "ab".repeat(32),
            });
        recovery
            .retain_https_media(
                RetainHttpsMediaV1 {
                    schema_version: 1,
                    kind: "retainHttpsMedia".into(),
                    local_operation_id: Uuid::now_v7(),
                    owner_principal_digest: "22".repeat(32),
                    session_id,
                    canonical_project_digest: "11".repeat(32),
                    client_draft_id: Uuid::now_v7(),
                    requested_media_kind: RequestedLocalPathMediaKind::Audio,
                    url: "https://media.example.test/audio.wav".into(),
                },
                &cockpit_config::config::media_budget::MediaResourcePolicy::default(),
                1,
                10,
            )
            .await
            .unwrap();
        assert_eq!(recovery.process_retained_https_jobs(11).await.unwrap(), 1);
        assert_eq!(
            recovery
                .process_retained_https_jobs(1_000_000)
                .await
                .unwrap(),
            0
        );
        let state = db.read(|conn| Ok((conn.query_row("SELECT availability FROM media_attachments", [], |r| r.get::<_, String>(0))?, conn.query_row("SELECT availability_generation FROM media_attachments", [], |r| r.get::<_, String>(0))?, conn.query_row("SELECT COUNT(*) FROM media_attachment_processing_failure_evidence WHERE reason='model_runtime_unavailable'", [], |r| r.get::<_, i64>(0))?, conn.query_row("SELECT COUNT(*) FROM media_attachment_transition_evidence WHERE to_state IN ('decoding','normalizing','model_derivative_unavailable')", [], |r| r.get::<_, i64>(0))?))).await.unwrap();
        assert_eq!(
            state,
            ("model_derivative_unavailable".into(), "5".into(), 1, 3)
        );
        db.transaction(|conn| {
            let error = conn
                .execute(
                    "UPDATE media_attachment_processing_failure_evidence SET reason='unknown_runtime_reason'",
                    [],
                )
                .unwrap_err();
            assert!(
                error.to_string().contains("CHECK constraint failed"),
                "{error}"
            );
            assert_eq!(
                conn.query_row(
                    "SELECT reason FROM media_attachment_processing_failure_evidence",
                    [],
                    |row| row.get::<_, String>(0),
                )?,
                "model_runtime_unavailable"
            );
            Ok(())
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn retained_av_shared_consumer_success_failure_and_replay() {
        let temp = tempfile::TempDir::new().unwrap();
        let db = cockpit_db::Db::open_in_memory_async().await.unwrap();
        let session_id = Uuid::now_v7();
        db.transaction(move |conn| {
            conn.execute("INSERT INTO sessions(session_id,project_id,project_root,started_at,last_active_at) VALUES(?1,'p','/redacted',1,1)",[session_id.to_string()])?;
            Ok(())
        }).await.unwrap();
        let runtime = ApprovedAvRuntime {
            ffmpeg: "/approved/ffmpeg".into(),
            ffprobe: "/approved/ffprobe".into(),
            fingerprint: "ab".repeat(32),
        };
        async fn retain(
            recovery: &MediaStorageRecovery,
            session_id: Uuid,
            draft: Uuid,
            kind: RequestedLocalPathMediaKind,
            now: i64,
        ) {
            recovery
                .retain_https_media(
                    RetainHttpsMediaV1 {
                        schema_version: 1,
                        kind: "retainHttpsMedia".into(),
                        local_operation_id: Uuid::now_v7(),
                        owner_principal_digest: "22".repeat(32),
                        session_id,
                        canonical_project_digest: "11".repeat(32),
                        client_draft_id: draft,
                        requested_media_kind: kind,
                        url: "https://media.example.test/av".into(),
                    },
                    &cockpit_config::config::media_budget::MediaResourcePolicy::default(),
                    now as u64,
                    now,
                )
                .await
                .unwrap();
        }

        let mut wav = b"RIFF".to_vec();
        wav.extend_from_slice(&36u32.to_le_bytes());
        wav.extend_from_slice(b"WAVEfmt ");
        wav.extend_from_slice(&16u32.to_le_bytes());
        wav.extend_from_slice(&[1, 0, 1, 0]);
        wav.extend_from_slice(&48_000u32.to_le_bytes());
        wav.extend_from_slice(&96_000u32.to_le_bytes());
        wav.extend_from_slice(&[2, 0, 16, 0]);
        wav.extend_from_slice(b"data");
        wav.extend_from_slice(&0u32.to_le_bytes());
        let audio_runner = std::sync::Arc::new(ScriptedAudioRunner {
            calls: AtomicUsize::new(0),
        });
        let recovery = MediaStorageRecovery::open_or_create(db.clone(), &temp.path().join("media"))
            .unwrap()
            .with_https_fetcher(std::sync::Arc::new(ScriptedHttpsFetcher {
                calls: AtomicUsize::new(0),
                bytes: wav,
            }))
            .with_av_runtime(runtime.clone())
            .with_av_runner(audio_runner.clone());
        retain(
            &recovery,
            session_id,
            Uuid::now_v7(),
            RequestedLocalPathMediaKind::Audio,
            10,
        )
        .await;
        assert_eq!(recovery.process_retained_https_jobs(11).await.unwrap(), 1);
        assert_eq!(
            recovery
                .process_retained_https_jobs(1_000_000)
                .await
                .unwrap(),
            0
        );
        assert!(audio_runner.calls.load(Ordering::SeqCst) >= 3);

        let video_runner = std::sync::Arc::new(ScriptedVideoRunner {
            fail_encode: AtomicBool::new(false),
            calls: AtomicUsize::new(0),
        });
        let recovery = MediaStorageRecovery::open(db.clone(), &temp.path().join("media"))
            .unwrap()
            .with_https_fetcher(std::sync::Arc::new(ScriptedHttpsFetcher {
                calls: AtomicUsize::new(0),
                bytes: canonical_video_fixture(),
            }))
            .with_av_runtime(runtime.clone())
            .with_av_runner(video_runner.clone());
        retain(
            &recovery,
            session_id,
            Uuid::now_v7(),
            RequestedLocalPathMediaKind::Video,
            20,
        )
        .await;
        assert_eq!(recovery.process_retained_https_jobs(21).await.unwrap(), 1);
        assert_eq!(
            recovery
                .process_retained_https_jobs(1_000_000)
                .await
                .unwrap(),
            0
        );
        assert!(video_runner.calls.load(Ordering::SeqCst) >= 4);

        let failing_runner = std::sync::Arc::new(ScriptedVideoRunner {
            fail_encode: AtomicBool::new(true),
            calls: AtomicUsize::new(0),
        });
        let recovery = MediaStorageRecovery::open(db.clone(), &temp.path().join("media"))
            .unwrap()
            .with_https_fetcher(std::sync::Arc::new(ScriptedHttpsFetcher {
                calls: AtomicUsize::new(0),
                bytes: canonical_video_fixture(),
            }))
            .with_av_runtime(runtime)
            .with_av_runner(failing_runner);
        retain(
            &recovery,
            session_id,
            Uuid::now_v7(),
            RequestedLocalPathMediaKind::Video,
            30,
        )
        .await;
        assert_eq!(recovery.process_retained_https_jobs(31).await.unwrap(), 1);
        assert_eq!(
            recovery
                .process_retained_https_jobs(1_000_000)
                .await
                .unwrap(),
            0
        );
        let states = db.read(|conn| Ok((
            conn.query_row("SELECT COUNT(*) FROM media_attachments WHERE availability='ready' AND media_kind IN ('audio','video')", [], |r| r.get::<_, i64>(0))?,
            conn.query_row("SELECT COUNT(*) FROM media_attachments WHERE availability='failed' AND media_kind='video'", [], |r| r.get::<_, i64>(0))?,
            conn.query_row("SELECT COUNT(*) FROM media_av_normalization_evidence", [], |r| r.get::<_, i64>(0))?,
        ))).await.unwrap();
        assert_eq!(states, (2, 1, 2));
    }

    #[tokio::test]
    async fn https_media_ingest_output_proof_failure_blocks_cleans_and_never_reclaims() {
        let temp = tempfile::TempDir::new().unwrap();
        let db = cockpit_db::Db::open_in_memory_async().await.unwrap();
        let session_id = Uuid::now_v7();
        db.transaction(move|conn|{conn.execute("INSERT INTO sessions(session_id,project_id,project_root,started_at,last_active_at) VALUES(?1,'p','/redacted',1,1)",[session_id.to_string()])?;Ok(())}).await.unwrap();
        let mut png = std::io::Cursor::new(Vec::new());
        image::DynamicImage::ImageRgba8(image::RgbaImage::from_pixel(
            2,
            2,
            image::Rgba([1, 2, 3, 255]),
        ))
        .write_to(&mut png, image::ImageFormat::Png)
        .unwrap();
        let recovery = MediaStorageRecovery::open_or_create(db.clone(), &temp.path().join("media"))
            .unwrap()
            .with_https_fetcher(std::sync::Arc::new(ScriptedHttpsFetcher {
                calls: AtomicUsize::new(0),
                bytes: png.into_inner(),
            }))
            .with_processing_output_proof_failure();
        let request = RetainHttpsMediaV1 {
            schema_version: 1,
            kind: "retainHttpsMedia".into(),
            local_operation_id: Uuid::now_v7(),
            owner_principal_digest: "22".repeat(32),
            session_id,
            canonical_project_digest: "11".repeat(32),
            client_draft_id: Uuid::now_v7(),
            requested_media_kind: RequestedLocalPathMediaKind::Image,
            url: "https://media.example.test/image".into(),
        };
        recovery
            .retain_https_media(
                request,
                &cockpit_config::config::media_budget::MediaResourcePolicy::default(),
                1,
                10,
            )
            .await
            .unwrap();
        assert_eq!(recovery.process_retained_https_jobs(11).await.unwrap(), 1);
        assert_eq!(
            recovery
                .process_retained_https_jobs(1_000_000)
                .await
                .unwrap(),
            0
        );
        let state = db
            .read(|conn| {
                Ok((
                    conn.query_row("SELECT availability FROM media_attachments", [], |r| {
                        r.get::<_, String>(0)
                    })?,
                    conn.query_row(
                        "SELECT COUNT(*) FROM media_attachment_processing_output_security_evidence",
                        [],
                        |r| r.get::<_, i64>(0),
                    )?,
                    conn.query_row(
                        "SELECT COUNT(*) FROM media_attachment_processing_cleanup_evidence",
                        [],
                        |r| r.get::<_, i64>(0),
                    )?,
                    conn.query_row(
                        "SELECT COUNT(*) FROM media_attachment_components WHERE component_kind IN ('image_model','browser_thumbnail')",
                        [],
                        |r| r.get::<_, i64>(0),
                    )?,
                ))
            })
            .await
            .unwrap();
        assert_eq!(state, ("security_blocked".into(), 1, 1, 0));
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
        let https_operation = Uuid::now_v7().to_string();
        let https_orphan = Uuid::now_v7().to_string();
        std::fs::write(
            temp.path().join("media").join(&https_orphan),
            b"https-orphan",
        )
        .unwrap();
        std::fs::set_permissions(
            temp.path().join("media").join(&https_orphan),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        let https_orphan_for_db = https_orphan.clone();
        db.transaction(move|conn|{conn.execute("INSERT INTO media_retained_https_publication_intents(local_operation_id,storage_id,created_at_unix_ms) VALUES(?1,?2,14)",params![https_operation,https_orphan_for_db])?;Ok(())}).await.unwrap();
        drop(recovery);
        let recovery = MediaStorageRecovery::open(db.clone(), &temp.path().join("media")).unwrap();
        assert_eq!(recovery.reconcile_media_uploads(15).await.unwrap(), 2);
        assert!(temp.path().join("media").join(&temporary).exists());
        assert!(!temp.path().join("media").join(&quarantine).exists());
        assert!(!temp.path().join("media").join(&orphan).exists());
        assert!(!temp.path().join("media").join(&https_orphan).exists());
        assert_eq!(db.read(|conn|Ok(conn.query_row("SELECT COUNT(*) FROM media_retained_https_orphan_cleanup_evidence WHERE outcome='verified_unlink'",[],|r|r.get::<_,i64>(0))?)).await.unwrap(),1);
        let insecure = Uuid::now_v7().to_string();
        std::fs::write(temp.path().join("media").join(&insecure), b"insecure").unwrap();
        std::fs::set_permissions(
            temp.path().join("media").join(&insecure),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        let blocked_upload = upload_id.to_string();
        let blocked_temporary = temporary.clone();
        let blocked_quarantine = Uuid::now_v7().to_string();
        let blocked_derivatives = serde_json::to_string(&vec![insecure.clone()]).unwrap();
        db.transaction(move|conn|{conn.execute("INSERT INTO media_storage_publication_intents(upload_id,temporary_storage_id,quarantine_storage_id,derivative_storage_ids_json,created_at_unix_ms) VALUES(?1,?2,?3,?4,16)",params![blocked_upload,blocked_temporary,blocked_quarantine,blocked_derivatives])?;Ok(())}).await.unwrap();
        assert!(
            recovery
                .reconcile_media_uploads(17)
                .await
                .unwrap_err()
                .to_string()
                .contains("storage_security_violation")
        );
        let live_intent: i64 = db
            .read(|conn| {
                Ok(conn.query_row(
                    "SELECT COUNT(*) FROM media_storage_publication_intents",
                    [],
                    |row| row.get(0),
                )?)
            })
            .await
            .unwrap();
        assert_eq!(live_intent, 1);
        std::fs::set_permissions(
            temp.path().join("media").join(&insecure),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        std::fs::remove_file(temp.path().join("media").join(&insecure)).unwrap();
        db.transaction(|conn| {
            conn.execute("DELETE FROM media_storage_publication_intents", [])?;
            Ok(())
        })
        .await
        .unwrap();
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
            .read(move |conn| {
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
    async fn scripted_video_finalize_fault_success_replay_and_reopen_use_production_path() {
        use base64::Engine as _;
        use cockpit_db::media_attachments::{
            LocalMediaActorRoleV1, LocalMediaMutationPayloadV1, LocalMediaMutationV1,
        };
        let temp = tempfile::TempDir::new().unwrap();
        let database_path = temp.path().join("cockpit.db");
        let db = cockpit_db::Db::open(&database_path).unwrap();
        let session_id = Uuid::now_v7();
        db.transaction(move |conn| {
            conn.execute("INSERT INTO sessions(session_id,project_id,project_root,started_at,last_active_at) VALUES(?1,'project','/redacted',1,1)",[session_id.to_string()])?;
            Ok(())
        }).await.unwrap();
        let policy = cockpit_config::config::media_budget::MediaResourcePolicy::default();
        let runtime = ApprovedAvRuntime {
            ffmpeg: "/approved/ffmpeg".into(),
            ffprobe: "/approved/ffprobe".into(),
            fingerprint: "ab".repeat(32),
        };
        async fn stage(
            recovery: &MediaStorageRecovery,
            policy: &cockpit_config::config::media_budget::MediaResourcePolicy,
            session_id: Uuid,
            bytes: &[u8],
            now: i64,
        ) -> LocalMediaMutationV1 {
            let draft = Uuid::now_v7();
            let length = bytes.len() as u64;
            let begin = LocalMediaMutationV1 {
                schema_version: 1,
                kind: "localMediaMutation".into(),
                local_operation_id: Uuid::now_v7(),
                actor_principal_digest: "11".repeat(32),
                actor_role: LocalMediaActorRoleV1::Owner,
                payload: LocalMediaMutationPayloadV1::Begin {
                    session_id,
                    canonical_project_digest: "22".repeat(32),
                    client_draft_id: draft,
                    media_kind: RequestedLocalPathMediaKind::Video,
                    declared_total_bytes: length,
                    reservation_digest: digest_json(
                        b"media-upload-reservation-v1",
                        &local_path_plans(policy, length).unwrap(),
                    )
                    .unwrap(),
                },
            };
            let upload = recovery
                .begin_media_upload(begin, policy, now as u64, now)
                .await
                .unwrap()
                .subject_id;
            recovery
                .append_media_upload_chunk(
                    cockpit_db::media_attachments::AppendMediaUploadChunkV1 {
                        mutation: LocalMediaMutationV1 {
                            schema_version: 1,
                            kind: "localMediaMutation".into(),
                            local_operation_id: Uuid::now_v7(),
                            actor_principal_digest: "11".repeat(32),
                            actor_role: LocalMediaActorRoleV1::Owner,
                            payload: LocalMediaMutationPayloadV1::Append {
                                session_id,
                                canonical_project_digest: "22".repeat(32),
                                client_draft_id: draft,
                                upload_id: upload,
                                upload_generation: 1,
                                chunk_index: 0,
                                chunk_length: length as u32,
                                chunk_sha256: crate::intel::hex_lower(&Sha256::digest(bytes)),
                            },
                        },
                        data_base64: base64::engine::general_purpose::STANDARD.encode(bytes),
                    },
                    now + 1,
                )
                .await
                .unwrap();
            LocalMediaMutationV1 {
                schema_version: 1,
                kind: "localMediaMutation".into(),
                local_operation_id: Uuid::now_v7(),
                actor_principal_digest: "11".repeat(32),
                actor_role: LocalMediaActorRoleV1::Owner,
                payload: LocalMediaMutationPayloadV1::Finalize {
                    session_id,
                    canonical_project_digest: "22".repeat(32),
                    client_draft_id: draft,
                    upload_id: upload,
                    upload_generation: 2,
                    chunk_count: 1,
                    total_bytes: length,
                    object_sha256: crate::intel::hex_lower(&Sha256::digest(bytes)),
                },
            }
        }
        let bytes = canonical_video_fixture();
        let failing_runner = std::sync::Arc::new(ScriptedVideoRunner {
            fail_encode: AtomicBool::new(true),
            calls: AtomicUsize::new(0),
        });
        let recovery = MediaStorageRecovery::open_or_create(db.clone(), &temp.path().join("media"))
            .unwrap()
            .with_av_runtime(runtime.clone())
            .with_av_runner(failing_runner.clone());
        let failed_request = stage(&recovery, &policy, session_id, &bytes, 10).await;
        let failed = recovery
            .finalize_media_upload(failed_request, 12)
            .await
            .unwrap();
        assert!(failing_runner.calls.load(Ordering::SeqCst) >= 4);
        let failed_upload = failed.subject_id.to_string();
        assert_eq!(db.read(move |conn| Ok(conn.query_row("SELECT a.availability FROM media_attachments a JOIN media_uploads u ON u.attachment_id=a.attachment_id WHERE u.upload_id=?1",[failed_upload],|row|row.get::<_,String>(0))?)).await.unwrap(), "failed");

        let successful_runner = std::sync::Arc::new(ScriptedVideoRunner {
            fail_encode: AtomicBool::new(false),
            calls: AtomicUsize::new(0),
        });
        let recovery = MediaStorageRecovery::open(db.clone(), &temp.path().join("media"))
            .unwrap()
            .with_av_runtime(runtime.clone())
            .with_av_runner(successful_runner.clone());
        let request = stage(&recovery, &policy, session_id, &bytes, 20).await;
        let receipt = recovery
            .finalize_media_upload(request.clone(), 22)
            .await
            .unwrap();
        assert!(successful_runner.calls.load(Ordering::SeqCst) >= 5);
        let upload = receipt.subject_id.to_string();
        let persisted = db.read(move |conn| Ok((
            conn.query_row("SELECT a.availability FROM media_attachments a JOIN media_uploads u ON u.attachment_id=a.attachment_id WHERE u.upload_id=?1",[&upload],|row|row.get::<_,String>(0))?,
            conn.query_row("SELECT COUNT(*) FROM media_av_normalization_evidence e JOIN media_uploads u ON u.attachment_id=e.attachment_id WHERE u.upload_id=?1",[&upload],|row|row.get::<_,i64>(0))?,
            conn.query_row("SELECT COUNT(*) FROM media_attachment_components c JOIN media_uploads u ON u.attachment_id=c.attachment_id WHERE u.upload_id=?1 AND c.component_kind='video_model' AND c.lifecycle_state='ready'",[&upload],|row|row.get::<_,i64>(0))?
        ))).await.unwrap();
        assert_eq!(persisted, ("ready".into(), 1, 1));
        drop(recovery);
        drop(db);
        let reopened_db = cockpit_db::Db::open(&database_path).unwrap();
        let reopened = MediaStorageRecovery::open(reopened_db, &temp.path().join("media"))
            .unwrap()
            .with_av_runtime(runtime)
            .with_av_runner(successful_runner);
        assert_eq!(
            reopened.finalize_media_upload(request, 23).await.unwrap(),
            receipt
        );
    }

    #[tokio::test]
    async fn message_image_batch_proof_failure_has_zero_egress_and_live_authority() {
        let temp = tempfile::TempDir::new().unwrap();
        let db = cockpit_db::Db::open(&temp.path().join("db.sqlite")).unwrap();
        let session = Uuid::now_v7();
        let project = "22".repeat(32);
        let root = temp.path().join("media");
        let storage = MediaStorageRecovery::open_or_create(db.clone(), &root).unwrap();
        let mut fixtures = Vec::new();
        for (index, bytes) in [b"first".as_slice(), b"second".as_slice()]
            .into_iter()
            .enumerate()
        {
            let attachment = Uuid::now_v7();
            let component = Uuid::now_v7();
            let storage_id = Uuid::now_v7();
            let reservation = format!("batch-reservation-{index}");
            std::fs::write(root.join(storage_id.to_string()), bytes).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                std::fs::set_permissions(
                    root.join(storage_id.to_string()),
                    std::fs::Permissions::from_mode(0o600),
                )
                .unwrap();
            }
            let file = File::open(root.join(storage_id.to_string())).unwrap();
            let identity = stable_identity_digest(&file).unwrap();
            let checksum = crate::intel::hex_lower(&Sha256::digest(bytes));
            let record = MediaAttachmentRecord {
                attachment_id: attachment,
                session_id: session,
                canonical_project_digest: project.clone(),
                media_kind: MediaKind::Image,
                source_kind: MediaSourceKind::AuthenticatedSessionUpload,
                canonical_container: "png".into(),
                canonical_mime: "image/png".into(),
                availability: MediaAvailability::Quarantined,
                attachment_version: 1,
                availability_generation: 1,
                reference_generation: 1,
                captured_capability_generation: 1,
                source_identity_digest: "11".repeat(32),
                source_byte_length: bytes.len() as u64,
                source_sha256: checksum.clone(),
                selected_video_stream: None,
                selected_audio_stream: None,
                created_at_unix_ms: 1,
                updated_at_unix_ms: 1,
                draft_expires_at_unix_ms: None,
                first_referenced_at_unix_ms: None,
            };
            let component_record = MediaAttachmentComponent {
                component_id: component,
                attachment_id: attachment,
                attachment_version: 1,
                component_kind: "image_model".into(),
                storage_id,
                lifecycle_state: "ready".into(),
                component_generation: 1,
                stable_identity_digest: identity,
                byte_length: bytes.len() as u64,
                sha256: checksum,
                reservation_id: reservation.clone(),
                created_at_unix_ms: 1,
                updated_at_unix_ms: 1,
            };
            db.transaction(move|conn|{conn.execute("INSERT OR IGNORE INTO sessions(session_id,project_id,project_root,started_at,last_active_at) VALUES(?1,'p','/redacted',1,1)",[session.to_string()])?;conn.execute("INSERT INTO media_reservations(reservation_id,policy_version,project_id,owner_session_key,operation,purpose,recovery_id,state,version,queue_sequence,deadline_monotonic_ms,created_wall_ms,published) VALUES(?1,1,'p',?2,'upload','image',?1,'settling',1,?3,100,1,1)",params![reservation,session.to_string(),index as i64+1])?;cockpit_db::Db::insert_media_attachment_conn(conn,&record)?;cockpit_db::Db::insert_media_attachment_component_conn(conn,&component_record)?;for generation in 1..5{let next=[MediaAvailability::Probing,MediaAvailability::Decoding,MediaAvailability::Normalizing,MediaAvailability::Ready][generation-1];cockpit_db::Db::transition_media_attachment_conn(conn,attachment,1,generation as u64,next,1)?;}Ok(())}).await.unwrap();
            fixtures.push((attachment, storage_id));
        }
        std::fs::write(root.join(fixtures[1].1.to_string()), b"tampered").unwrap();
        let ledger = crate::media_reservation::MediaReservationLedger::new(
            db.clone(),
            std::sync::Arc::new(FixedMediaClock),
        );
        let result = storage
            .acquire_message_images_bound(
                fixtures.iter().map(|value| value.0).collect(),
                session,
                project,
                "submission".into(),
                &ledger,
                1024,
                5,
            )
            .await;
        assert!(result.is_err());
        let counts=db.read(|conn|Ok((conn.query_row("SELECT COUNT(*) FROM media_attachment_component_leases WHERE released_at_unix_ms IS NULL",[],|row|row.get::<_,i64>(0))?,conn.query_row("SELECT COUNT(*) FROM media_attachment_references WHERE released_at_unix_ms IS NULL",[],|row|row.get::<_,i64>(0))?,conn.query_row("SELECT COUNT(*) FROM media_downstream_ownership WHERE released_wall_ms IS NULL",[],|row|row.get::<_,i64>(0))?))).await.unwrap();
        assert_eq!(counts, (0, 0, 0));
    }

    #[tokio::test]
    async fn local_discard_replays_aliases_reopens_and_rolls_back_faults() {
        use cockpit_db::media_attachments::{
            LocalMediaActorRoleV1, LocalMediaMutationPayloadV1, LocalMediaMutationV1,
        };
        let temp = tempfile::TempDir::new().unwrap();
        let path = temp.path().join("db.sqlite");
        let db = cockpit_db::Db::open(&path).unwrap();
        let session = Uuid::now_v7();
        let attachment = Uuid::now_v7();
        let fault_attachment = Uuid::now_v7();
        let project = "11".repeat(32);
        let record_session = session;
        let record_project = project.clone();
        let record = move |id| MediaAttachmentRecord {
            attachment_id: id,
            session_id: record_session,
            canonical_project_digest: record_project.clone(),
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
        db.transaction(move|conn|{conn.execute("INSERT INTO sessions(session_id,project_id,project_root,started_at,last_active_at)VALUES(?1,'p','/redacted',1,1)",[session.to_string()])?;cockpit_db::Db::insert_media_attachment_conn(conn,&record(attachment))?;cockpit_db::Db::insert_media_attachment_conn(conn,&record(fault_attachment))?;Ok(())}).await.unwrap();
        let storage =
            MediaStorageRecovery::open_or_create(db.clone(), &temp.path().join("media")).unwrap();
        let request = LocalMediaMutationV1 {
            schema_version: 1,
            kind: "localMediaMutation".into(),
            local_operation_id: Uuid::now_v7(),
            actor_principal_digest: "44".repeat(32),
            actor_role: LocalMediaActorRoleV1::Owner,
            payload: LocalMediaMutationPayloadV1::Discard {
                session_id: session,
                canonical_project_digest: project.clone(),
                attachment_id: attachment,
                attachment_version: 1,
                availability_generation: 1,
                reference_generation: 1,
                origin_upload: None,
            },
        };
        let receipt = storage
            .discard_media_attachment(request.clone(), 2)
            .await
            .unwrap();
        assert_eq!(
            receipt.outcome,
            cockpit_db::media_attachments::LocalMediaMutationOutcomeV1::Applied
        );
        assert_eq!(
            storage
                .discard_media_attachment(request.clone(), 3)
                .await
                .unwrap(),
            receipt
        );
        let mut alias = request.clone();
        alias.local_operation_id = Uuid::now_v7();
        assert_eq!(
            storage
                .discard_media_attachment(alias.clone(), 4)
                .await
                .unwrap(),
            receipt
        );
        drop(storage);
        drop(db);
        let reopened_db = cockpit_db::Db::open(&path).unwrap();
        let reopened =
            MediaStorageRecovery::open(reopened_db.clone(), &temp.path().join("media")).unwrap();
        assert_eq!(
            reopened.discard_media_attachment(alias, 5).await.unwrap(),
            receipt
        );
        reopened_db.transaction(|conn|{conn.execute_batch("CREATE TRIGGER fail_discard_operation BEFORE INSERT ON local_media_operations BEGIN SELECT RAISE(ABORT,'injected discard operation failure'); END;")?;Ok(())}).await.unwrap();
        let fault = LocalMediaMutationV1 {
            schema_version: 1,
            kind: "localMediaMutation".into(),
            local_operation_id: Uuid::now_v7(),
            actor_principal_digest: "44".repeat(32),
            actor_role: LocalMediaActorRoleV1::Owner,
            payload: LocalMediaMutationPayloadV1::Discard {
                session_id: session,
                canonical_project_digest: project,
                attachment_id: fault_attachment,
                attachment_version: 1,
                availability_generation: 1,
                reference_generation: 1,
                origin_upload: None,
            },
        };
        assert!(reopened.discard_media_attachment(fault, 6).await.is_err());
        let state=reopened_db.read(move|conn|Ok((conn.query_row("SELECT availability FROM media_attachments WHERE attachment_id=?1",[fault_attachment.to_string()],|row|row.get::<_,String>(0))?,conn.query_row("SELECT COUNT(*) FROM media_attachment_cleanup_intents WHERE attachment_id=?1",[fault_attachment.to_string()],|row|row.get::<_,i64>(0))?))).await.unwrap();
        assert_eq!(state, ("registered".into(), 0));
    }

    #[tokio::test]
    #[ignore = "manual system-runtime conformance; required tests use the injected runner"]
    async fn executable_ffmpeg_vectors_cover_named_dimensions_and_frame_rates() {
        fn executable(name: &str) -> Option<std::path::PathBuf> {
            std::env::var_os("PATH")
                .into_iter()
                .flat_map(|value| std::env::split_paths(&value).collect::<Vec<_>>())
                .map(|directory| directory.join(name))
                .find(|path| path.is_file())
        }
        let (Some(ffmpeg), Some(ffprobe)) = (executable("ffmpeg"), executable("ffprobe")) else {
            return;
        };
        let runtime = ApprovedAvRuntime {
            ffmpeg: ffmpeg.clone(),
            ffprobe,
            fingerprint: "cd".repeat(32),
        };
        let runner = SystemAvRuntimeRunner;
        verify_required_video_encoders(&runtime, &runner, false)
            .await
            .unwrap();
        for ((source_width, source_height), sar, expected) in [
            ((1920, 1080), (1, 1), (1280, 720)),
            ((640, 360), (1, 1), (640, 360)),
            ((1440, 1080), (4, 3), (1280, 720)),
            ((720, 480), (8, 9), (640, 480)),
            ((3, 3), (1, 1), (2, 2)),
        ] {
            let directory = tempfile::TempDir::new().unwrap();
            let source = directory.path().join("source.mkv");
            let filter = format!("testsrc=size={source_width}x{source_height}:rate=1");
            let status = std::process::Command::new(&ffmpeg)
                .env_clear()
                .args([
                    "-nostdin",
                    "-hide_banner",
                    "-loglevel",
                    "error",
                    "-f",
                    "lavfi",
                    "-i",
                    &filter,
                    "-frames:v",
                    "1",
                    "-c:v",
                    "libx264",
                    "-pix_fmt",
                    "yuv444p",
                    "-y",
                ])
                .arg(&source)
                .status()
                .unwrap();
            assert!(status.success());
            let (document, _) =
                run_bounded_ffprobe(&runtime, &runner, std::fs::read(source).unwrap())
                    .await
                    .unwrap();
            let video = document
                .streams
                .iter()
                .find(|stream| stream.codec_type == "video")
                .unwrap();
            assert_eq!(
                (video.width.unwrap(), video.height.unwrap()),
                (source_width, source_height)
            );
            assert_eq!(
                select_video_dimensions(source_width, source_height, sar.0, sar.1).unwrap(),
                expected
            );
        }
        for (rate, frames, expected) in [
            ("1", "1", (1, 1)),
            ("24000/1001", "3", (24_000, 1_001)),
            ("30000/1001", "3", (24, 1)),
        ] {
            let directory = tempfile::TempDir::new().unwrap();
            let source = directory.path().join("rate.mkv");
            let filter = format!("color=black:size=16x16:rate={rate}");
            let status = std::process::Command::new(&ffmpeg)
                .env_clear()
                .args([
                    "-nostdin",
                    "-hide_banner",
                    "-loglevel",
                    "error",
                    "-f",
                    "lavfi",
                    "-i",
                    &filter,
                    "-frames:v",
                    frames,
                    "-c:v",
                    "libx264",
                    "-pix_fmt",
                    "yuv420p",
                    "-y",
                ])
                .arg(&source)
                .status()
                .unwrap();
            assert!(status.success());
            let (document, _) =
                run_bounded_ffprobe(&runtime, &runner, std::fs::read(source).unwrap())
                    .await
                    .unwrap();
            let video = document
                .streams
                .iter()
                .find(|stream| stream.codec_type == "video")
                .unwrap();
            let actual =
                select_video_rate(&selected_video_timestamps(&document, video).unwrap()).unwrap();
            assert_eq!((actual.0, actual.1), expected);
        }
        let directory = tempfile::TempDir::new().unwrap();
        let source = directory.path().join("vfr.mkv");
        let status = std::process::Command::new(&ffmpeg)
            .env_clear()
            .args([
                "-nostdin",
                "-hide_banner",
                "-loglevel",
                "error",
                "-f",
                "lavfi",
                "-i",
                "color=black:size=16x16:rate=10",
                "-frames:v",
                "3",
                "-vf",
                "setpts=if(eq(N\\,0)\\,0\\,if(eq(N\\,1)\\,1\\,5))",
                "-vsync",
                "vfr",
                "-c:v",
                "libx264",
                "-pix_fmt",
                "yuv420p",
                "-y",
            ])
            .arg(&source)
            .status()
            .unwrap();
        assert!(status.success());
        let (document, _) = run_bounded_ffprobe(&runtime, &runner, std::fs::read(source).unwrap())
            .await
            .unwrap();
        let video = document
            .streams
            .iter()
            .find(|stream| stream.codec_type == "video")
            .unwrap();
        let actual =
            select_video_rate(&selected_video_timestamps(&document, video).unwrap()).unwrap();
        assert_eq!((actual.0, actual.1), (4, 1));
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

    async fn cleanup_fixture() -> (
        tempfile::TempDir,
        MediaStorageRecovery,
        cockpit_db::Db,
        Uuid,
        Uuid,
        Uuid,
    ) {
        let temp = tempfile::TempDir::new().unwrap();
        let root_path = temp.path().join("media");
        let root = DirGuard::open_root(&root_path, true).unwrap();
        let storage_id = Uuid::now_v7();
        let mut file = root.create_file_exclusive(&storage_id.to_string()).unwrap();
        file.write_all(b"cleanup bytes").unwrap();
        file.sync_all().unwrap();
        let identity = stable_identity_digest(&file).unwrap();
        let (length, checksum) = read_full_digest(&mut file).unwrap();
        let db = cockpit_db::Db::open_in_memory_async().await.unwrap();
        let session = Uuid::now_v7();
        let attachment = Uuid::now_v7();
        let component = Uuid::now_v7();
        db.transaction(move|conn|{conn.execute("INSERT INTO sessions(session_id,project_id,project_root,started_at,last_active_at) VALUES(?1,'p','/redacted',1,1)",[session.to_string()])?;conn.execute("INSERT INTO media_reservations(reservation_id,policy_version,project_id,owner_session_key,operation,purpose,recovery_id,state,version,queue_sequence,deadline_monotonic_ms,created_wall_ms) VALUES('cleanup-reservation',1,'p',?1,'cleanup','retention','cleanup-recovery','settling',1,1,1,1)",[session.to_string()])?;cockpit_db::Db::insert_media_attachment_conn(conn,&MediaAttachmentRecord{attachment_id:attachment,session_id:session,canonical_project_digest:"11".repeat(32),media_kind:MediaKind::Image,source_kind:MediaSourceKind::RetainedHttps,canonical_container:"png".into(),canonical_mime:"image/png".into(),availability:MediaAvailability::OwnedCleanupPending,attachment_version:1,availability_generation:2,reference_generation:1,captured_capability_generation:1,source_identity_digest:"22".repeat(32),source_byte_length:length,source_sha256:checksum.clone(),selected_video_stream:None,selected_audio_stream:None,created_at_unix_ms:1,updated_at_unix_ms:1,draft_expires_at_unix_ms:None,first_referenced_at_unix_ms:Some(1)})?;cockpit_db::Db::insert_media_attachment_component_conn(conn,&MediaAttachmentComponent{component_id:component,attachment_id:attachment,attachment_version:1,component_kind:"image_model".into(),storage_id,lifecycle_state:"cleanup_pending".into(),component_generation:2,stable_identity_digest:identity,byte_length:length,sha256:checksum,reservation_id:"cleanup-reservation".into(),created_at_unix_ms:1,updated_at_unix_ms:1})?;conn.execute("INSERT INTO media_attachment_cleanup_intents(intent_id,attachment_id,attachment_version,expected_availability_generation,expected_reference_generation,component_set_digest,reason,created_at_unix_ms) VALUES(?1,?2,'1','2','1',?3,'session_retention',1)",params![Uuid::now_v7().to_string(),attachment.to_string(),"33".repeat(32)])?;Ok(())}).await.unwrap();
        let storage = MediaStorageRecovery::open(db.clone(), &root_path).unwrap();
        (temp, storage, db, attachment, component, storage_id)
    }

    #[tokio::test]
    async fn cleanup_reconciles_restart_once_and_releases_only_after_evidence() {
        let (_temp, storage, db, attachment, component, _) = cleanup_fixture().await;
        assert_eq!(
            storage.reconcile_media_cleanup_intents(10).await.unwrap(),
            1
        );
        assert_eq!(
            storage.reconcile_media_cleanup_intents(11).await.unwrap(),
            0
        );
        let state:(String,String,i64,i64)=db.read(move|conn|Ok(conn.query_row("SELECT a.availability,r.state,(SELECT COUNT(*) FROM media_component_deletion_evidence WHERE component_id=?1),(SELECT COUNT(*) FROM media_attachment_cleanup_intents WHERE attachment_id=?2 AND completed_at_unix_ms IS NOT NULL) FROM media_attachments a JOIN media_reservations r ON r.reservation_id='cleanup-reservation' WHERE a.attachment_id=?2",params![component.to_string(),attachment.to_string()],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?)))?)).await.unwrap();
        assert_eq!(
            state,
            ("retained_copy_deleted".into(), "released".into(), 1, 1)
        );
    }

    #[tokio::test]
    async fn cleanup_tamper_blocks_and_preserves_intent_without_release() {
        let (temp, storage, db, attachment, component, storage_id) = cleanup_fixture().await;
        std::fs::write(
            temp.path().join("media").join(storage_id.to_string()),
            b"tampered bytes",
        )
        .unwrap();
        assert!(storage.reconcile_media_cleanup_intents(10).await.is_err());
        let state:(String,String,i64,i64)=db.read(move|conn|Ok(conn.query_row("SELECT a.availability,r.state,(SELECT COUNT(*) FROM media_cleanup_security_evidence WHERE component_id=?1),(SELECT COUNT(*) FROM media_attachment_cleanup_intents WHERE attachment_id=?2 AND completed_at_unix_ms IS NULL) FROM media_attachments a JOIN media_reservations r ON r.reservation_id='cleanup-reservation' WHERE a.attachment_id=?2",params![component.to_string(),attachment.to_string()],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?)))?)).await.unwrap();
        assert_eq!(state, ("security_blocked".into(), "settling".into(), 1, 1));
    }

    #[tokio::test]
    async fn component_lease_returns_only_fully_verified_held_bytes() {
        let temp = tempfile::TempDir::new().unwrap();
        let root_path = temp.path().join("media");
        let root = DirGuard::open_root(&root_path, true).unwrap();
        let storage_id = Uuid::now_v7();
        let mut file = root.create_file_exclusive(&storage_id.to_string()).unwrap();
        file.write_all(b"safe preview").unwrap();
        file.sync_all().unwrap();
        let identity = stable_identity_digest(&file).unwrap();
        let (length, checksum) = read_full_digest(&mut file).unwrap();
        let db = cockpit_db::Db::open_in_memory_async().await.unwrap();
        let session_id = Uuid::now_v7();
        let attachment_id = Uuid::now_v7();
        let component_id = Uuid::now_v7();
        db.transaction(move |conn| {
            conn.execute("INSERT INTO sessions(session_id,project_id,project_root,started_at,last_active_at) VALUES(?1,'p','/redacted',1,1)",[session_id.to_string()])?;
            cockpit_db::Db::insert_media_attachment_conn(conn,&MediaAttachmentRecord { attachment_id,session_id,canonical_project_digest:"11".repeat(32),media_kind:MediaKind::Image,source_kind:MediaSourceKind::RetainedHttps,canonical_container:"png".into(),canonical_mime:"image/png".into(),availability:MediaAvailability::Ready,attachment_version:1,availability_generation:5,reference_generation:1,captured_capability_generation:7,source_identity_digest:"22".repeat(32),source_byte_length:length,source_sha256:checksum.clone(),selected_video_stream:None,selected_audio_stream:None,created_at_unix_ms:1,updated_at_unix_ms:1,draft_expires_at_unix_ms:None,first_referenced_at_unix_ms:None})?;
            cockpit_db::Db::insert_media_attachment_component_conn(conn,&MediaAttachmentComponent { component_id,attachment_id,attachment_version:1,component_kind:"browser_thumbnail".into(),storage_id,lifecycle_state:"ready".into(),component_generation:1,stable_identity_digest:identity,byte_length:length,sha256:checksum,reservation_id:"reservation".into(),created_at_unix_ms:1,updated_at_unix_ms:1 })?;
            Ok(())
        }).await.unwrap();
        let storage = MediaStorageRecovery::open(db.clone(), &root_path).unwrap();
        let lease = storage
            .acquire_component_lease(
                Uuid::now_v7(),
                attachment_id,
                1,
                5,
                7,
                MediaComponentLeaseKind::Preview,
                2,
            )
            .await
            .unwrap();
        assert_eq!(lease.authority().component.component_id, component_id);
        assert_eq!(lease.read_verified(3).await.unwrap(), b"safe preview");
        let live:i64=db.read(move|conn|Ok(conn.query_row("SELECT COUNT(*) FROM media_attachment_component_leases WHERE attachment_id=?1 AND released_at_unix_ms IS NULL",[attachment_id.to_string()],|row|row.get(0))?)).await.unwrap();
        assert_eq!(live, 0);
        let abandoned_id = Uuid::now_v7();
        let abandoned = storage
            .acquire_component_lease(
                abandoned_id,
                attachment_id,
                1,
                5,
                7,
                MediaComponentLeaseKind::Preview,
                4,
            )
            .await
            .unwrap();
        drop(abandoned);
        let reopened = MediaStorageRecovery::open(db.clone(), &root_path).unwrap();
        assert_eq!(
            reopened
                .reconcile_abandoned_component_leases(5)
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            reopened
                .reconcile_abandoned_component_leases(6)
                .await
                .unwrap(),
            0
        );
        let evidence:i64=db.read(move|conn|Ok(conn.query_row("SELECT COUNT(*) FROM media_component_lease_reconciliation_evidence WHERE lease_id=?1 AND reason='daemon_restart'",[abandoned_id.to_string()],|row|row.get(0))?)).await.unwrap();
        assert_eq!(evidence, 1);
        std::fs::write(root_path.join(storage_id.to_string()), b"evil preview").unwrap();
        let failed_lease = Uuid::now_v7();
        assert!(
            reopened
                .acquire_component_lease(
                    failed_lease,
                    attachment_id,
                    1,
                    5,
                    7,
                    MediaComponentLeaseKind::Preview,
                    7
                )
                .await
                .is_err()
        );
        let blocked:(String,String,String,i64)=db.read(move|conn|Ok(conn.query_row("SELECT a.availability,a.availability_generation,c.component_generation,(SELECT COUNT(*) FROM media_component_security_evidence e WHERE e.lease_id=?1 AND e.reason='storage_security_violation') FROM media_attachments a JOIN media_attachment_components c ON c.attachment_id=a.attachment_id WHERE a.attachment_id=?2",params![failed_lease.to_string(),attachment_id.to_string()],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?)))?)).await.unwrap();
        assert_eq!(
            blocked,
            ("security_blocked".into(), "6".into(), "2".into(), 1)
        );
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
