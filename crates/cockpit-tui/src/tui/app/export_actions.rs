use super::*;
use crate::tui::agent_runner::AttachedRequest;
use base64::Engine;
use cockpit_core::daemon::proto::{ExportSessionKind, Request, Response};
use tokio::sync::{mpsc, oneshot};

const EXPORT_ACTION_KEY: &str = "export";
const EXPORT_TRANSCRIPT_ACTION: &str = "export.transcript";
const EXPORT_DEBUG_ACTION: &str = "export.debug";

impl App {
    /// `/export` (default) — ask the attached daemon for a redacted
    /// transcript and write it asynchronously, overwriting any prior file.
    pub(super) fn export_transcript_json(&mut self, file_stem: &str, exports_dir: &Path) {
        let Some(session_id) = self.current_session_id() else {
            self.push_plain("/export: no active session to export".to_string());
            return;
        };
        self.start_export_action(
            EXPORT_TRANSCRIPT_ACTION,
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
        self.start_export_action(
            EXPORT_DEBUG_ACTION,
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
        let Some(attached_request_tx) = self
            .agent_runner
            .as_ref()
            .and_then(|runner| runner.as_ref().ok())
            .map(|runner| runner.attached_request_tx.clone())
        else {
            self.push_plain(format!(
                "{command}: an attached daemon is required for export"
            ));
            return;
        };

        self.push_plain(match kind {
            ExportSessionKind::TranscriptJson => "/export: writing transcript…".to_string(),
            ExportSessionKind::DebugBundle => "/export debug: writing bundle…".to_string(),
        });
        let file_stem = file_stem.to_string();
        let exports_dir = exports_dir.to_path_buf();
        self.async_actions.start(
            AsyncActionKind::Internal(action),
            AsyncActionPolicy::Replace(AsyncActionKey::new(EXPORT_ACTION_KEY)),
            async move {
                export_via_attached_daemon(
                    attached_request_tx,
                    session_id,
                    kind,
                    file_stem,
                    exports_dir,
                    command,
                )
                .await
                .map(AsyncActionPayload::Text)
            },
        );
    }
}

async fn export_via_attached_daemon(
    attached_request_tx: mpsc::Sender<AttachedRequest>,
    session_id: uuid::Uuid,
    kind: ExportSessionKind,
    file_stem: String,
    exports_dir: std::path::PathBuf,
    command: &'static str,
) -> Result<String, String> {
    let (response_tx, response_rx) = oneshot::channel();
    attached_request_tx
        .send(AttachedRequest {
            request: Request::ExportSessionData {
                session_id,
                kind,
                include_generated_artifacts: false,
                include_sensitive: false,
            },
            response_tx,
        })
        .await
        .map_err(|_| format!("{command}: daemon request failed: daemon client task has stopped"))?;
    let response = response_rx
        .await
        .map_err(|_| {
            format!("{command}: daemon request failed: daemon client dropped reply channel")
        })?
        .map_err(|error| format!("{command}: daemon request failed: {error}"))?;
    let Response::ExportSessionData { data } = response else {
        return Err(format!(
            "{command}: daemon request failed: unexpected daemon response"
        ));
    };
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(data.content_base64)
        .map_err(|error| format!("{command}: decoding export data failed: {error}"))?;
    let out_path = exports_dir.join(format!("{file_stem}.{}", data.filename_extension));
    tokio::fs::create_dir_all(&exports_dir)
        .await
        .map_err(|error| format!("{command}: creating export directory failed: {error}"))?;
    tokio::fs::write(&out_path, bytes)
        .await
        .map_err(|error| format!("{command}: writing export failed: {error}"))?;
    let sessions = data.session_count.unwrap_or(1);
    Ok(match kind {
        ExportSessionKind::TranscriptJson => format!(
            "Exported conversation ({} bytes) → {}",
            data.byte_len,
            out_path.display()
        ),
        ExportSessionKind::DebugBundle => format!(
            "Exported debug bundle ({} session{}, {} bytes) → {}",
            sessions,
            if sessions == 1 { "" } else { "s" },
            data.byte_len,
            out_path.display()
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::agent_runner::{AgentRunner, ClientTasks, UsageCounts};
    use cockpit_core::daemon::proto::ExportSessionData;
    use cockpit_core::engine::message::UserSubmission;
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
        let (input_tx, _input_rx) = mpsc::channel::<UserSubmission>(1);
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
        }
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
                content_base64: base64::engine::general_purpose::STANDARD.encode(bytes),
                byte_len: bytes.len(),
                session_count: Some(1),
                redacted: true,
            },
        }
    }

    async fn drain_until_idle(app: &mut App) {
        for _ in 0..100 {
            tokio::task::yield_now().await;
            app.drain_async_actions();
            if app.async_actions.pending_count() == 0 {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        panic!("export action did not finish");
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
                include_sensitive: false,
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
                include_sensitive: false,
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
        drain_until_idle(&mut app).await;
        assert_eq!(
            std::fs::read(exports_dir.join("conversation.daemon-zip")).unwrap(),
            b"zip"
        );
    }

    #[tokio::test]
    async fn malformed_export_data_is_a_decode_failure_without_a_file() {
        let tmp = tempfile::tempdir().unwrap();
        let session_id = uuid::Uuid::new_v4();
        let (tx, mut rx) = mpsc::channel(1);
        let task = tokio::spawn(export_via_attached_daemon(
            tx,
            session_id,
            ExportSessionKind::TranscriptJson,
            "x".to_string(),
            tmp.path().join("exports"),
            "/export",
        ));
        let request = rx.recv().await.unwrap();
        let Response::ExportSessionData { mut data } =
            response(session_id, ExportSessionKind::TranscriptJson, "json", b"ok")
        else {
            unreachable!()
        };
        data.content_base64 = "not-base64".to_string();
        request
            .response_tx
            .send(Ok(Response::ExportSessionData { data }))
            .unwrap();
        assert!(
            task.await
                .unwrap()
                .unwrap_err()
                .contains("decoding export data failed")
        );
        assert!(!tmp.path().join("exports/x.json").exists());
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
        for (action, expected) in [
            (
                EXPORT_TRANSCRIPT_ACTION,
                "/export: unexpected async response",
            ),
            (
                EXPORT_DEBUG_ACTION,
                "/export debug: unexpected async response",
            ),
        ] {
            let id = app
                .async_actions
                .start(
                    AsyncActionKind::Internal(action),
                    AsyncActionPolicy::AllowConcurrent,
                    std::future::pending::<Result<AsyncActionPayload, String>>(),
                )
                .id();
            app.apply_async_action_result(AsyncActionResult {
                id,
                kind: AsyncActionKind::Internal(action),
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
