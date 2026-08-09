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
    LocalMediaOwnerReceiptV1, MediaAvailability, MediaSecurityRecoveryComponentTransitionV1,
    MediaSecurityRecoveryDisposition, MediaSecurityRecoveryOutcome, MediaSourceKind,
    RecoverSecurityBlockedMediaV1, SecurityRecoverySnapshot, SecurityRecoverySnapshotResult,
};
use rusqlite::{Connection, params};
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
