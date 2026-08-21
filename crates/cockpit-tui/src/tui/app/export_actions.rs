use super::*;

#[cfg(test)]
static EXPORT_WRITE_THREAD_OBSERVER: std::sync::Mutex<
    Option<(
        std::path::PathBuf,
        tokio::sync::oneshot::Sender<std::thread::ThreadId>,
    )>,
> = std::sync::Mutex::new(None);

#[cfg(test)]
pub(super) fn observe_export_write_thread(
    target: std::path::PathBuf,
) -> tokio::sync::oneshot::Receiver<std::thread::ThreadId> {
    let (sender, receiver) = tokio::sync::oneshot::channel();
    *EXPORT_WRITE_THREAD_OBSERVER.lock().unwrap() = Some((target, sender));
    receiver
}
#[cfg(test)]
use crate::tui::agent_runner::AttachedRequest;
use crate::tui::agent_runner::AttachedRequestBinding;
use base64::Engine;
use cockpit_core::daemon::proto::{ExportSessionKind, Request, Response};
#[cfg(test)]
use tokio::sync::mpsc;

const EXPORT_ACTION_KEY: &str = "export";
impl App {
    /// `/export` (default) — ask the attached daemon for a redacted
    /// transcript and write it asynchronously, overwriting any prior file.
    pub(super) fn export_transcript_json(&mut self, file_stem: &str, exports_dir: &Path) {
        let Some(session_id) = self.current_session_id() else {
            self.push_plain("/export: no active session to export".to_string());
            return;
        };
        let action = self.export_transcript_action_name();
        self.start_export_action(
            action,
            "/export",
            session_id,
            file_stem,
            exports_dir,
            ExportSessionKind::TranscriptJson,
        );
    }

    /// `/export debug` (hidden) — ask the attached daemon for the full
    /// redacted CLI bundle and write it asynchronously.
    pub(super) fn export_debug_bundle(
        &mut self,
        session_id: uuid::Uuid,
        file_stem: &str,
        exports_dir: &Path,
    ) {
        let action = self.export_debug_action_name();
        self.start_export_action(
            action,
            "/export debug",
            session_id,
            file_stem,
            exports_dir,
            ExportSessionKind::DebugBundle,
        );
    }

    fn start_export_action(
        &mut self,
        action: &'static str,
        command: &'static str,
        session_id: uuid::Uuid,
        file_stem: &str,
        exports_dir: &Path,
        kind: ExportSessionKind,
    ) {
        let operation = self.export_blocking_operation();
        debug_assert!(operation.registration().actions.contains(&action));
        #[cfg(test)]
        let barrier = self.take_owned_test_barrier(operation);
        #[cfg(test)]
        let has_test_gate = barrier.is_some();
        #[cfg(not(test))]
        let has_test_gate = false;
        let attached_request = self
            .agent_runner
            .as_ref()
            .and_then(|runner| runner.as_ref().ok())
            .map(|runner| runner.attached_request_binding());
        if attached_request.is_none() && !has_test_gate {
            self.push_plain(format!(
                "{command}: an attached daemon is required for export"
            ));
            return;
        }

        let export_key = AsyncActionKey::new(EXPORT_ACTION_KEY);
        self.push_plain(match kind {
            ExportSessionKind::TranscriptJson => "/export: writing transcript…".to_string(),
            ExportSessionKind::DebugBundle => "/export debug: writing bundle…".to_string(),
        });
        let file_stem = file_stem.to_string();
        let exports_dir = exports_dir.to_path_buf();
        let request = Request::ExportSessionData {
            session_id,
            kind,
            include_generated_artifacts: false,
            // The TUI export is invariantly redacted; the raw opt-in is the
            // local `cockpit export --include-sensitive` CLI path only.
            include_sensitive: false,
        };
        self.async_actions.start_export(
            AsyncActionKind::Blocking(action),
            AsyncActionPolicy::Replace(export_key),
            move |shutdown| async move {
                #[cfg(test)]
                if let Some(barrier) = barrier {
                    tokio::task::spawn_blocking(move || barrier.arrive_and_wait())
                        .await
                        .map_err(|error| error.to_string())?;
                    return Ok(AsyncActionPayload::Unit);
                }
                export_via_attached_daemon(
                    attached_request.expect("export dispatch checked attached request"),
                    request,
                    kind,
                    file_stem,
                    exports_dir,
                    command,
                    shutdown,
                )
                .await
                .map(AsyncActionPayload::Text)
            },
        );
    }
}

async fn export_via_attached_daemon(
    attached_request: AttachedRequestBinding,
    request: Request,
    kind: ExportSessionKind,
    file_stem: String,
    exports_dir: std::path::PathBuf,
    command: &'static str,
    shutdown: std::sync::Arc<crate::tui::async_action::AsyncActionCancellation>,
) -> Result<String, String> {
    let response = tokio::select! {
        biased;
        () = shutdown.cancelled() => return Err(format!("{command}: export cancelled by shutdown")),
        response = attached_request.request(request) => response,
    }
    .map_err(|error| format!("{command}: daemon request failed: {error}"))?;
    let Response::ExportSessionData { data } = response else {
        return Err(format!(
            "{command}: daemon request failed: unexpected daemon response"
        ));
    };
    // The export bytes never rode the response frame: pull them as bounded
    // bulk chunks, then verify the transfer's length and digest before writing.
    let bytes = pull_bulk_transfer(&attached_request, &data.transfer, command, &shutdown).await?;
    let out_path = exports_dir.join(format!("{file_stem}.{}", data.filename_extension));
    recover_deferred_export_cleanup(&exports_dir).await;
    prepare_export_directory(&exports_dir, command).await?;
    write_export_no_clobber(&out_path, &bytes, command, &shutdown).await?;
    let sessions = data.session_count.unwrap_or(1);
    Ok(match kind {
        ExportSessionKind::TranscriptJson => format!(
            "Exported conversation ({} bytes) → {}",
            data.byte_len(),
            out_path.display()
        ),
        ExportSessionKind::DebugBundle => format!(
            "Exported debug bundle ({} session{}, {} bytes) → {}",
            sessions,
            if sessions == 1 { "" } else { "s" },
            data.byte_len(),
            out_path.display()
        ),
    })
}

async fn prepare_export_directory(
    exports_dir: &std::path::Path,
    command: &'static str,
) -> Result<(), String> {
    #[cfg(windows)]
    {
        let exports_dir = exports_dir.to_path_buf();
        tokio::task::spawn_blocking(move || {
            crate::clipboard::recovery::windows::DirHandle::open_or_create(&exports_dir)
        })
        .await
        .map_err(|error| format!("{command}: export directory worker failed: {error}"))?
        .map(|_| ())
        .map_err(|error| format!("{command}: securing export directory failed: {error}"))
    }
    #[cfg(not(windows))]
    {
        tokio::fs::create_dir_all(exports_dir)
            .await
            .map_err(|error| format!("{command}: creating export directory failed: {error}"))
    }
}

pub(super) async fn recover_deferred_export_cleanup(exports_dir: &std::path::Path) {
    let records = exports_dir.join(".cockpit-export-recovery");
    let records_secure = std::fs::symlink_metadata(&records).is_ok_and(|metadata| {
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return false;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
            metadata.uid() == unsafe { libc::geteuid() }
                && metadata.permissions().mode() & 0o077 == 0
        }
        #[cfg(windows)]
        {
            crate::clipboard::recovery::windows::DirHandle::open_or_create(&records).is_ok()
        }
        #[cfg(not(any(unix, windows)))]
        {
            false
        }
    });
    if !records_secure {
        return;
    }
    if let Ok(mut entries) = tokio::fs::read_dir(&records).await {
        while let Ok(Some(entry)) = entries.next_entry().await {
            let record_name = entry.file_name();
            let Some(record_text) = record_name
                .to_str()
                .and_then(|name| name.strip_suffix(".record"))
            else {
                continue;
            };
            let Ok(record_id) = uuid::Uuid::parse_str(record_text) else {
                continue;
            };
            if record_id.get_version_num() != 7 || record_id.to_string() != record_text {
                continue;
            }
            let Ok(record) = tokio::fs::read_to_string(entry.path()).await else {
                continue;
            };
            let mut lines = record.lines();
            let (Some("v1"), Some(name), None) = (lines.next(), lines.next(), lines.next()) else {
                continue;
            };
            let owned = name
                .strip_suffix(".partial")
                .and_then(|stem| stem.rsplit_once('.'))
                .is_some_and(|(target, id_text)| {
                    uuid::Uuid::parse_str(id_text).is_ok_and(|id| {
                        target.starts_with('.')
                            && target.len() > 1
                            && id.get_version_num() == 7
                            && id.to_string() == id_text
                    })
                });
            let candidate = exports_dir.join(name);
            if !owned {
                continue;
            }
            let cleanup = tokio::task::spawn_blocking(move || {
                crate::tui::async_action::secure_unlink_owned_temp(&candidate)
            })
            .await;
            let cleaned = match cleanup {
                Ok(Ok(())) => true,
                Ok(Err(error)) => error.kind() == std::io::ErrorKind::NotFound,
                Err(_) => false,
            };
            if cleaned {
                let _ = tokio::fs::remove_file(entry.path()).await;
            }
        }
        let records = records.clone();
        let _ = tokio::task::spawn_blocking(move || std::fs::File::open(records)?.sync_all()).await;
    }
}

/// Publish through the shared platform-held atomic no-clobber implementation.
/// Its blocking callable owns its relative temporary handle through cleanup.
pub(super) async fn write_export_no_clobber(
    out_path: &std::path::Path,
    bytes: &[u8],
    command: &'static str,
    shutdown: &std::sync::Arc<AsyncActionCancellation>,
) -> Result<(), String> {
    if !crate::tui::async_action::secure_export_cleanup_supported() {
        return Err(format!("{command}: secure export cleanup is unavailable"));
    }
    let worker_out = out_path.to_path_buf();
    let worker_bytes = bytes.to_vec();
    let worker_shutdown = std::sync::Arc::clone(shutdown);
    tokio::task::spawn_blocking(move || {
        #[cfg(test)]
        {
            let mut observer = EXPORT_WRITE_THREAD_OBSERVER.lock().unwrap();
            if observer
                .as_ref()
                .is_some_and(|(target, _)| target == &worker_out)
                && let Some((_, sender)) = observer.take()
            {
                let _ = sender.send(std::thread::current().id());
            }
        }
        crate::clipboard::file_publish::publish_no_clobber_bounded_elsewhere(
            &worker_out,
            &worker_bytes,
            &|| worker_shutdown.is_cancelled(),
        )
        .map(|_| ())
        .map_err(|error| format!("{command}: publishing export failed: {error}"))
    })
    .await
    .map_err(|error| format!("{command}: export worker failed: {error}"))?
}

/// Pull a staged bulk transfer chunk by chunk and verify it end to end.
///
/// The reference carries the authoritative length and SHA-256; a transfer that
/// does not reproduce both exactly is rejected rather than written to disk.
async fn pull_bulk_transfer(
    attached_request: &AttachedRequestBinding,
    transfer: &cockpit_core::daemon::proto::remote_transport::bulk::RemoteBulkTransferRef,
    command: &'static str,
    shutdown: &AsyncActionCancellation,
) -> Result<Vec<u8>, String> {
    use sha2::{Digest as _, Sha256};

    let expected_len = transfer.total_length_value();
    // Deliberately NOT `with_capacity(expected_len)`: the length arrives on the
    // wire, and sizing a buffer from it hands a peer an allocation primitive.
    // `RemoteBulkTransferRef` already refuses a length above its class limit at
    // deserialization, so this is defence in depth — the buffer still only ever
    // grows with bytes that actually arrived, and the loop below refuses to
    // exceed the declared length.
    let mut bytes: Vec<u8> = Vec::new();
    let mut chunk_index: u32 = 0;
    loop {
        let response = tokio::select! {
            biased;
            () = shutdown.cancelled() => return Err(format!("{command}: export cancelled by shutdown")),
            // The TUI export is invariantly redacted, so its transfer is the
            // type-bound `RedactedExport` kind: read it through the type-bound
            // reader (not the generic bulk reader) for custody consistency.
            response = attached_request.request(Request::ReadRedactedExportChunk {
                transfer_id: transfer.transfer_id,
                chunk_index,
            }) => response,
        }
            .map_err(|error| format!("{command}: reading export data failed: {error}"))?;
        let Response::BulkTransferChunk {
            chunk_index: got,
            data_base64,
            last,
        } = response
        else {
            return Err(format!(
                "{command}: reading export data failed: unexpected daemon response"
            ));
        };
        if got != chunk_index {
            return Err(format!(
                "{command}: reading export data failed: out-of-order chunk"
            ));
        }
        let chunk = base64::engine::general_purpose::STANDARD
            .decode(data_base64)
            .map_err(|error| format!("{command}: decoding export data failed: {error}"))?;
        if bytes.len() as u64 + chunk.len() as u64 > expected_len {
            return Err(format!(
                "{command}: reading export data failed: transfer overran its declared length"
            ));
        }
        bytes.extend_from_slice(&chunk);
        if last {
            break;
        }
        chunk_index += 1;
    }
    if bytes.len() as u64 != expected_len {
        return Err(format!(
            "{command}: reading export data failed: transfer length mismatch"
        ));
    }
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    if hasher.finalize().as_slice() != transfer.sha256 {
        return Err(format!(
            "{command}: reading export data failed: transfer digest mismatch"
        ));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::agent_runner::{AgentRunner, ClientTasks, UsageCounts};
    use cockpit_core::daemon::proto::ExportSessionData;
    use cockpit_core::daemon::proto::remote_transport::bulk as proto_bulk;
    use std::sync::{Arc, Mutex};

    fn last_plain(app: &App) -> &str {
        match app.history.last().expect("history line") {
            HistoryEntry::Plain { line } => line,
            other => panic!("expected plain line, got {other:?}"),
        }
    }

    fn runner(
        session_id: uuid::Uuid,
        attached_request_tx: mpsc::Sender<AttachedRequest>,
    ) -> AgentRunner {
        let (input_tx, _input_rx) = mpsc::channel::<crate::tui::agent_runner::RunnerInput>(1);
        let (record_tx, _record_rx) = mpsc::channel(1);
        let (control_tx, _control_rx) = mpsc::channel(1);
        AgentRunner {
            input_tx,
            record_tx,
            control_tx,
            attached_request_tx,
            events: Arc::new(Mutex::new(Vec::new())),
            event_notify: Arc::new(tokio::sync::Notify::new()),
            active_agent: Arc::new(Mutex::new("Build".to_string())),
            active_agent_path: Arc::new(Mutex::new(vec!["Build".to_string()])),
            skill_inventory_names: Arc::new(Mutex::new(None)),
            foreground_target: Some(cockpit_core::engine::message::QueueTarget::root("Build")),
            active_model_state: None,
            session_id_state: Arc::new(Mutex::new(session_id)),
            attachment_epoch: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            submission_session_tx: tokio::sync::watch::channel(
                crate::tui::agent_runner::SubmissionSessionBinding::new(session_id, 0),
            )
            .0,
            awaiting_durable: Default::default(),
            short_id: "abc123".to_string(),
            project_id: "project".to_string(),
            usage: UsageCounts::default(),
            owns_daemon: false,
            socket: std::path::PathBuf::from("/tmp/cockpit-test.sock"),
            history: Vec::new(),
            paused_work: Vec::new(),
            repair_required: None,
            btw_fork: None,
            daemon_version: "test".to_string(),
            daemon_compatible: true,
            current_client: None,
            attach_context: None,
            last_applied_seq: None,
            client_tasks: ClientTasks::default(),
            #[cfg(test)]
            test_session_switch_rx: Arc::new(Mutex::new(None)),
            #[cfg(test)]
            test_force_can_switch: false,
            test_advance_epoch_when_switch_task_created: false,
        }
    }

    fn digest_of(bytes: &[u8]) -> [u8; 32] {
        use sha2::{Digest as _, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&hasher.finalize());
        digest
    }

    fn transfer_ref(bytes: &[u8]) -> proto_bulk::RemoteBulkTransferRef {
        let transfer_id = cockpit_core::daemon::proto::remote_protocol_id::tag_protocol_id_bytes::<
            cockpit_core::daemon::proto::remote_protocol_id::kind::Transfer,
        >([0x2A; 16])
        .unwrap();
        proto_bulk::RemoteBulkTransferRef::new(
            transfer_id,
            bytes.len() as u64,
            digest_of(bytes),
            proto_bulk::RemoteBulkMimeClass::RedactedExport,
        )
        .unwrap()
    }

    fn response(
        session_id: uuid::Uuid,
        kind: ExportSessionKind,
        extension: &str,
        bytes: &[u8],
    ) -> Response {
        Response::ExportSessionData {
            data: ExportSessionData {
                session_id,
                kind,
                filename_extension: extension.to_string(),
                mime: "application/octet-stream".to_string(),
                transfer: transfer_ref(bytes),
                session_count: Some(1),
                redacted: true,
            },
        }
    }

    /// Answer the follow-up bulk pull with `bytes` as a single final chunk.
    async fn serve_bulk_chunk(rx: &mut mpsc::Receiver<AttachedRequest>, bytes: &[u8]) {
        let request = rx.recv().await.unwrap();
        let Request::ReadRedactedExportChunk { chunk_index, .. } = request.request else {
            panic!("expected a ReadRedactedExportChunk pull");
        };
        assert_eq!(chunk_index, 0);
        let _ = request.response_tx.send(Ok(Response::BulkTransferChunk {
            chunk_index: 0,
            data_base64: base64::engine::general_purpose::STANDARD.encode(bytes),
            last: true,
        }));
    }

    async fn drain_until_idle(app: &mut App) {
        while app.async_actions.pending_count() != 0 {
            let notify = app.async_actions.notifier();
            let notified = notify.notified();
            app.drain_async_actions();
            if app.async_actions.pending_count() == 0 {
                return;
            }
            notified.await;
        }
        app.drain_async_actions();
    }

    #[test]
    fn export_transcript_json_without_current_session_starts_no_action() {
        let tmp = tempfile::TempDir::new().unwrap();
        let exports_dir = tmp.path().join("exports");
        let mut app = App::new(Some(tmp.path()), false);
        app.launch.session_id = None;
        app.export_transcript_json("conversation", &exports_dir);
        assert_eq!(last_plain(&app), "/export: no active session to export");
        assert_eq!(app.async_actions.pending_count(), 0);
    }

    #[test]
    fn export_without_attached_daemon_starts_no_action_or_request() {
        let tmp = tempfile::TempDir::new().unwrap();
        let exports_dir = tmp.path().join("exports");
        let mut app = App::new(Some(tmp.path()), false);
        app.launch.session_id = Some(uuid::Uuid::new_v4());
        app.export_transcript_json("conversation", &exports_dir);
        assert!(last_plain(&app).contains("attached daemon is required"));
        assert_eq!(app.async_actions.pending_count(), 0);
    }

    #[tokio::test]
    async fn both_exports_send_one_redacted_rpc_then_write_response_extension() {
        let tmp = tempfile::TempDir::new().unwrap();
        let exports_dir = tmp.path().join("exports");
        let session_id = uuid::Uuid::new_v4();
        let (tx, mut rx) = mpsc::channel(2);
        let mut app = App::new(Some(tmp.path()), false);
        app.agent_runner = Some(Ok(runner(session_id, tx)));
        app.export_transcript_json("conversation", &exports_dir);
        assert_eq!(last_plain(&app), "/export: writing transcript…");
        assert!(!exports_dir.exists());
        let request = rx.recv().await.unwrap();
        assert!(matches!(
            request.request,
            Request::ExportSessionData {
                kind: ExportSessionKind::TranscriptJson,
                ..
            }
        ));
        request
            .response_tx
            .send(Ok(response(
                session_id,
                ExportSessionKind::TranscriptJson,
                "daemon-json",
                b"[]",
            )))
            .unwrap();
        serve_bulk_chunk(&mut rx, b"[]").await;
        drain_until_idle(&mut app).await;
        assert_eq!(
            std::fs::read(exports_dir.join("conversation.daemon-json")).unwrap(),
            b"[]"
        );

        app.export_debug_bundle(session_id, "conversation", &exports_dir);
        assert_eq!(last_plain(&app), "/export debug: writing bundle…");
        let request = rx.recv().await.unwrap();
        assert!(matches!(
            request.request,
            Request::ExportSessionData {
                kind: ExportSessionKind::DebugBundle,
                ..
            }
        ));
        request
            .response_tx
            .send(Ok(response(
                session_id,
                ExportSessionKind::DebugBundle,
                "daemon-zip",
                b"zip",
            )))
            .unwrap();
        serve_bulk_chunk(&mut rx, b"zip").await;
        drain_until_idle(&mut app).await;
        assert_eq!(
            std::fs::read(exports_dir.join("conversation.daemon-zip")).unwrap(),
            b"zip"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn export_writes_off_the_loop_thread() {
        let event_loop_thread = std::thread::current().id();
        let tmp = tempfile::tempdir().unwrap();
        let exports = tmp.path().join("exports");
        let target = exports.join("threaded.json");
        let write_thread = observe_export_write_thread(target.clone());
        let session_id = uuid::Uuid::new_v4();
        let (tx, mut rx) = mpsc::channel(2);
        let mut app = App::new(Some(tmp.path()), false);
        app.agent_runner = Some(Ok(runner(session_id, tx)));

        app.export_transcript_json("threaded", &exports);
        let request = rx.recv().await.unwrap();
        assert!(matches!(
            request.request,
            Request::ExportSessionData {
                session_id: requested,
                kind: ExportSessionKind::TranscriptJson,
                ..
            } if requested == session_id
        ));
        request
            .response_tx
            .send(Ok(response(
                session_id,
                ExportSessionKind::TranscriptJson,
                "json",
                b"complete",
            )))
            .unwrap();
        serve_bulk_chunk(&mut rx, b"complete").await;

        assert_ne!(write_thread.await.unwrap(), event_loop_thread);
        drain_until_idle(&mut app).await;
        assert_eq!(tokio::fs::read(target).await.unwrap(), b"complete");
        assert_eq!(
            std::fs::read_dir(&exports)
                .unwrap()
                .filter_map(Result::ok)
                .filter(|entry| entry.file_name().to_string_lossy().contains("partial"))
                .count(),
            0
        );
    }

    #[tokio::test]
    async fn malformed_export_data_is_a_decode_failure_without_a_file() {
        let tmp = tempfile::tempdir().unwrap();
        let session_id = uuid::Uuid::new_v4();
        let (tx, mut rx) = mpsc::channel(1);
        let task = tokio::spawn(export_via_attached_daemon(
            AttachedRequestBinding::new(tx, session_id, 0),
            Request::ExportSessionData {
                session_id,
                kind: ExportSessionKind::TranscriptJson,
                include_generated_artifacts: false,
                include_sensitive: false,
            },
            ExportSessionKind::TranscriptJson,
            "x".to_string(),
            tmp.path().join("exports"),
            "/export",
            std::sync::Arc::new(AsyncActionCancellation::default()),
        ));
        let request = rx.recv().await.unwrap();
        request
            .response_tx
            .send(Ok(response(
                session_id,
                ExportSessionKind::TranscriptJson,
                "json",
                b"ok",
            )))
            .unwrap();
        // The transfer promised the digest of b"ok" but the carrier delivers
        // different bytes of the same length: the pull must refuse to write.
        serve_bulk_chunk(&mut rx, b"NO").await;
        let error = task.await.unwrap().unwrap_err();
        assert!(
            error.contains("transfer digest mismatch"),
            "unexpected error: {error}"
        );
        assert!(!tmp.path().join("exports/x.json").exists());
    }

    #[tokio::test]
    async fn export_publish_is_no_clobber_and_cleans_partial_file() {
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("existing.json");
        tokio::fs::write(&target, b"original").await.unwrap();

        let cancellation = std::sync::Arc::new(AsyncActionCancellation::default());
        let error = write_export_no_clobber(&target, b"replacement", "/export", &cancellation)
            .await
            .unwrap_err();

        assert!(error.contains("already exists"));
        assert_eq!(tokio::fs::read(&target).await.unwrap(), b"original");
        let leftovers = std::fs::read_dir(tmp.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().contains("partial"))
            .count();
        assert_eq!(leftovers, 0);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn next_export_start_clears_deferred_cleanup_record() {
        let tmp = tempfile::tempdir().unwrap();
        use std::os::unix::fs::PermissionsExt as _;
        let name = format!(".old.json.{}.partial", uuid::Uuid::now_v7());
        let deferred = tmp.path().join(&name);
        tokio::fs::write(&deferred, b"partial").await.unwrap();
        let records = tmp.path().join(".cockpit-export-recovery");
        tokio::fs::create_dir(&records).await.unwrap();
        std::fs::set_permissions(&records, std::fs::Permissions::from_mode(0o700)).unwrap();
        let record = records.join(format!("{}.record", uuid::Uuid::now_v7()));
        tokio::fs::write(&record, format!("v1\n{name}\n"))
            .await
            .unwrap();
        recover_deferred_export_cleanup(tmp.path()).await;
        assert!(!deferred.exists());
        assert!(!record.exists());
    }

    #[tokio::test]
    async fn recovery_ignores_planted_partial_names_and_symlinks() {
        let tmp = tempfile::tempdir().unwrap();
        let notes = tmp.path().join("notes.partial");
        tokio::fs::write(&notes, b"keep").await.unwrap();
        let planted = tmp.path().join(".notes.not-a-uuid.partial");
        tokio::fs::write(&planted, b"keep").await.unwrap();
        #[cfg(unix)]
        let symlink = {
            let target = tmp.path().join("valuable");
            tokio::fs::write(&target, b"keep").await.unwrap();
            let link = tmp
                .path()
                .join(format!(".x.{}.partial", uuid::Uuid::new_v4()));
            std::os::unix::fs::symlink(&target, &link).unwrap();
            Some((link, target))
        };
        recover_deferred_export_cleanup(tmp.path()).await;
        assert!(notes.exists());
        assert!(planted.exists());
        #[cfg(unix)]
        if let Some((link, target)) = symlink {
            assert!(link.exists());
            assert_eq!(tokio::fs::read(target).await.unwrap(), b"keep");
        }
    }

    #[tokio::test]
    async fn replacement_discards_the_superseded_export_result() {
        let tmp = tempfile::tempdir().unwrap();
        let session_id = uuid::Uuid::new_v4();
        let exports = tmp.path().join("exports");
        let (tx, mut rx) = mpsc::channel(2);
        let mut app = App::new(Some(tmp.path()), false);
        app.agent_runner = Some(Ok(runner(session_id, tx)));
        app.export_transcript_json("first", &exports);
        let first = rx.recv().await.unwrap();
        app.export_debug_bundle(session_id, "second", &exports);
        let second = rx.recv().await.unwrap();
        assert!(
            first
                .response_tx
                .send(Ok(response(
                    session_id,
                    ExportSessionKind::TranscriptJson,
                    "json",
                    b"first"
                )))
                .is_err()
        );
        second
            .response_tx
            .send(Ok(response(
                session_id,
                ExportSessionKind::DebugBundle,
                "zip",
                b"second",
            )))
            .unwrap();
        serve_bulk_chunk(&mut rx, b"second").await;
        drain_until_idle(&mut app).await;
        let lines = app
            .history
            .iter()
            .filter_map(|entry| match entry {
                HistoryEntry::Plain { line } => Some(line),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            lines
                .iter()
                .filter(|line| line.starts_with("Exported"))
                .count(),
            1
        );
        assert!(!lines.iter().any(|line| line.contains("first.json")));
    }

    #[tokio::test]
    async fn export_handlers_report_unexpected_payloads() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        let transcript_action = app.export_transcript_action_name();
        let debug_action = app.export_debug_action_name();
        for (action, expected) in [
            (transcript_action, "/export: unexpected async response"),
            (debug_action, "/export debug: unexpected async response"),
        ] {
            let id = app
                .async_actions
                .start(
                    AsyncActionKind::Blocking(action),
                    AsyncActionPolicy::AllowConcurrent,
                    std::future::pending::<Result<AsyncActionPayload, String>>(),
                )
                .id();
            app.apply_async_action_result(AsyncActionResult {
                id,
                kind: AsyncActionKind::Blocking(action),
                payload: Ok(AsyncActionPayload::Unit),
            });
            assert_eq!(last_plain(&app), expected);
        }
    }

    #[tokio::test]
    async fn missing_session_error_is_rendered_without_a_file() {
        let tmp = tempfile::tempdir().unwrap();
        let session_id = uuid::Uuid::new_v4();
        let exports = tmp.path().join("exports");
        let (tx, mut rx) = mpsc::channel(1);
        let mut app = App::new(Some(tmp.path()), false);
        app.agent_runner = Some(Ok(runner(session_id, tx)));
        app.export_transcript_json("conversation", &exports);
        let request = rx.recv().await.unwrap();
        request
            .response_tx
            .send(Err(format!("session {session_id} not found in the DB")))
            .unwrap();
        drain_until_idle(&mut app).await;
        assert!(last_plain(&app).contains("not found in the DB"));
        assert!(!exports.exists());
    }
}
