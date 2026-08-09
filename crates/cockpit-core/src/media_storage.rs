//! Private held-handle storage recovery for security-blocked media.
//!
//! Transport callers cannot mint a proof. The snapshot, every no-follow open,
//! full read, post-read identity check, and reducer commit run inside one DB
//! writer transaction while all verified file handles remain live.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use anyhow::{Context, Result, ensure};
use cockpit_db::media_attachments::{
    LocalMediaOwnerReceiptV1, MediaSecurityRecoveryDisposition, RecoverSecurityBlockedMediaV1,
    SecurityRecoverySnapshot, SecurityRecoverySnapshotResult, SecurityRecoveryVerification,
};
use sha2::{Digest, Sha256};

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
}

impl MediaStorageRecovery {
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
        })
    }

    pub(crate) async fn recover(
        &self,
        request: RecoverSecurityBlockedMediaV1,
        borrowed_source: Option<BorrowedSourceHandle>,
        now_unix_ms: i64,
    ) -> Result<LocalMediaOwnerReceiptV1> {
        let root = self.owned_root.clone();
        self.db
            .transaction(move |conn| {
                let snapshot =
                    match cockpit_db::Db::security_recovery_snapshot_conn(conn, &request)? {
                        SecurityRecoverySnapshotResult::Replay(receipt) => return Ok(receipt),
                        SecurityRecoverySnapshotResult::Current(snapshot) => snapshot,
                    };
                cockpit_db::Db::validate_recover_security_blocked_media_v1(
                    &request,
                    snapshot.attachment.source_kind,
                )?;
                let mut held_proof = None;
                let verification = match request.disposition {
                    MediaSecurityRecoveryDisposition::RetainBlocked => {
                        SecurityRecoveryVerification::NotRequired
                    }
                    MediaSecurityRecoveryDisposition::ResumeVerifiedCleanup => {
                        match verify_all_handles(
                            &root,
                            &snapshot,
                            request.borrowed_source_evidence_digest.as_deref(),
                            borrowed_source,
                        ) {
                            Ok(proof) => {
                                held_proof = Some(proof);
                                SecurityRecoveryVerification::Verified
                            }
                            Err(_) => SecurityRecoveryVerification::Unverifiable,
                        }
                    }
                };
                let receipt = cockpit_db::Db::commit_security_recovery_conn(
                    conn,
                    &request,
                    &snapshot,
                    verification,
                    now_unix_ms,
                )?;
                drop(held_proof);
                Ok(receipt)
            })
            .await
    }
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
        ensure!(
            source.evidence_digest
                == source_evidence_digest(
                    &mut source.file,
                    &snapshot.attachment.source_identity_digest,
                    snapshot.attachment.source_byte_length,
                    &snapshot.attachment.source_sha256,
                )?,
            "borrowed source evidence changed"
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
fn stable_identity_digest(_file: &File) -> Result<String> {
    anyhow::bail!("Windows stable file identity recovery is unavailable")
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

    struct Fixture {
        _temp: tempfile::TempDir,
        root_path: std::path::PathBuf,
        db: cockpit_db::Db,
        request: RecoverSecurityBlockedMediaV1,
        storage_id: Uuid,
    }

    async fn fixture() -> Fixture {
        let temp = tempfile::TempDir::new().unwrap();
        let root_path = temp.path().join("media");
        let root = DirGuard::open_root(&root_path, true).unwrap();
        let storage_id = Uuid::now_v7();
        let mut file = root.create_file_exclusive(&storage_id.to_string()).unwrap();
        file.write_all(b"verified media bytes").unwrap();
        file.sync_all().unwrap();
        let identity = stable_identity_digest(&file).unwrap();
        let (byte_length, checksum) = read_full_digest(&mut file).unwrap();

        let db = cockpit_db::Db::open_in_memory_async().await.unwrap();
        let session_id = Uuid::now_v7();
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
        db.transaction(move |conn| {
            conn.execute("INSERT INTO sessions (session_id,project_id,project_root,started_at,last_active_at) VALUES (?1,'project','/redacted',1,1)", [session_id.to_string()])?;
            cockpit_db::Db::insert_media_attachment_conn(conn, &MediaAttachmentRecord {
                attachment_id,
                session_id,
                canonical_project_digest: "11".repeat(32),
                media_kind: MediaKind::Image,
                source_kind: MediaSourceKind::RetainedHttps,
                canonical_container: "png".into(),
                canonical_mime: "image/png".into(),
                availability: MediaAvailability::Quarantined,
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
            borrowed_source_evidence_digest: None,
            disposition: MediaSecurityRecoveryDisposition::ResumeVerifiedCleanup,
        };
        Fixture {
            _temp: temp,
            root_path,
            db,
            request,
            storage_id,
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
            .recover(fixture.request.clone(), None, 10)
            .await
            .unwrap();
        assert_eq!(
            receipt.outcome,
            MediaSecurityRecoveryOutcome::CleanupResumed
        );
        assert_eq!(receipt.availability_generation_after, 3);
        let replay = recovery
            .recover(fixture.request.clone(), None, 99)
            .await
            .unwrap();
        assert_eq!(replay, receipt);
        let mut conflict = fixture.request.clone();
        conflict.disposition = MediaSecurityRecoveryDisposition::RetainBlocked;
        assert!(
            recovery
                .recover(conflict, None, 100)
                .await
                .unwrap_err()
                .to_string()
                .contains("local operation conflict")
        );
        drop(recovery);
        let reopened = MediaStorageRecovery::open(fixture.db, &fixture.root_path).unwrap();
        assert_eq!(
            reopened.recover(fixture.request, None, 101).await.unwrap(),
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
            .recover(fixture.request.clone(), None, 10)
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
            recovery.recover(fixture.request, None, 11).await.unwrap(),
            receipt
        );
    }
}
