use super::*;
use crate::daemon::proto::Response;
use cockpit_client::is_protocol_version_mismatch;
use cockpit_proto::{Body, Envelope, ProtoStream};
use tokio::net::{UnixListener, UnixStream};
use uuid::Uuid;

#[tokio::test]
async fn dropping_owned_session_aborts_watcher_and_runs_guard_cleanup() {
    use tokio::io::AsyncBufReadExt as _;

    struct NotifyDrop(Option<tokio::sync::oneshot::Sender<()>>);
    impl Drop for NotifyDrop {
        fn drop(&mut self) {
            if let Some(notify) = self.0.take() {
                let _ = notify.send(());
            }
        }
    }

    let root = tempfile::tempdir().unwrap();
    let socket = root.path().join("owned-session.sock");
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    let stop = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut reader = tokio::io::BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        line
    });
    let (requests, _request_rx) = tokio::sync::mpsc::channel(1);
    let (_events, event_rx) = tokio::sync::mpsc::channel(1);
    let client = DaemonClient::from_in_process(cockpit_client::InProcessConnection {
        requests,
        events: event_rx,
    });
    let (watcher_dropped, watcher_drop) = tokio::sync::oneshot::channel();
    let signal_task = tokio::spawn(async move {
        let _notify = NotifyDrop(Some(watcher_dropped));
        std::future::pending::<()>().await;
    });
    let session = OwnedDaemonSession {
        client,
        guard: Some(crate::daemon::ephemeral_guard::EphemeralDaemonGuard::new_for_socket(socket)),
        signal_task: Some(signal_task),
    };

    tokio::task::spawn_blocking(move || drop(session))
        .await
        .unwrap();

    tokio::time::timeout(Duration::from_secs(2), watcher_drop)
        .await
        .expect("signal watcher was detached")
        .unwrap();
    let line = tokio::time::timeout(Duration::from_secs(2), stop)
        .await
        .expect("guard cleanup did not contact daemon")
        .unwrap();
    assert!(line.contains("stop_daemon"));
}

#[test]
fn ephemeral_spawn_arms_raii_before_the_first_wait() {
    let source = include_str!("client.rs");
    let spawn = source
        .find("let child = spawn_detached_ephemeral(&paths)?;")
        .expect("ephemeral spawn funnel");
    let arm = source[spawn..]
        .find("EphemeralDaemonGuard::new")
        .map(|offset| spawn + offset)
        .expect("provisional owner armed after spawn");
    let wait = source[spawn..]
        .find("wait_for_daemon(&paths.socket).await")
        .map(|offset| spawn + offset)
        .expect("daemon readiness wait");
    assert!(
        spawn < arm && arm < wait,
        "no cancellation window before RAII"
    );
}

fn daemon_status_response_with(
    daemon_version: impl Into<String>,
    protocol_version: u32,
) -> Response {
    Response::DaemonStatus {
        pid: 1,
        uptime_secs: 2,
        active_sessions: 0,
        socket_path: "/tmp/cockpit.sock".to_string(),
        daemon_version: daemon_version.into(),
        protocol_version,
        paused_sessions: 0,
        database_path: ":memory:".to_string(),
        schema_version: crate::db::EXPECTED_SCHEMA_VERSION,
    }
}

fn attach_request_with_client_protocol_version(
    session_id: Option<Uuid>,
    client_protocol_version: u32,
) -> Request {
    Request::Attach {
        session_id,
        since_seq: None,
        project_root: Some("/tmp".into()),
        initial_model: None,
        no_sandbox: false,
        interactive: true,
        session_entry_mode: Some(proto::SessionEntryMode::Code),
        model_override: None,
        client_protocol_version,
        env_snapshot: None,
        env_policy: crate::env_snapshot::EnvDriftPolicy::Daemon,
    }
}

fn attached_response(session_id: Uuid) -> Response {
    Response::Attached {
        session_id,
        session_entry_mode: proto::SessionEntryMode::Code,
        short_id: "abc123".to_string(),
        project_root: "/tmp".to_string(),
        project_id: "project".to_string(),
        active_agent: "Build".to_string(),
        active_agent_path: Vec::new(),
        foreground_target: None,
        active_subagent: None,
        active_model_state: None,
        history: Vec::new(),
        paused_work: Vec::new(),
        repair_required: None,
        daemon_version: proto::DAEMON_VERSION.to_string(),
        compatible: true,
        env_baseline: None,
        env_session: None,
        env_drift: None,
        env_policy_applied: crate::env_snapshot::EnvDriftPolicy::Daemon,
        btw_fork: None,
    }
}

fn bind_test_socket() -> (tempfile::TempDir, PathBuf, UnixListener) {
    let dir = tempfile::tempdir().expect("tempdir");
    let socket = dir.path().join("daemon.sock");
    let listener = UnixListener::bind(&socket).expect("bind daemon socket");
    (dir, socket, listener)
}

async fn send_daemon_hello(
    daemon: &mut ProtoStream<UnixStream>,
    daemon_version: impl Into<String>,
    protocol_version: u32,
) {
    daemon
        .send(&Envelope::response(
            Uuid::nil(),
            daemon_status_response_with(daemon_version, protocol_version),
        ))
        .await
        .unwrap();
}

#[tokio::test]
async fn negotiation_parses_daemon_hello_on_connect() {
    let (_dir, socket, listener) = bind_test_socket();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut daemon = ProtoStream::new(stream);
        send_daemon_hello(&mut daemon, "0.1.handshake", proto::PROTOCOL_VERSION).await;
    });

    let client = DaemonClient::connect(&socket).await.unwrap();

    assert_eq!(client.negotiated().daemon_version, "0.1.handshake");
    assert_eq!(
        client.negotiated().daemon_protocol_version,
        proto::PROTOCOL_VERSION
    );
    assert_eq!(client.negotiated().version, proto::PROTOCOL_VERSION);
    server.await.unwrap();
}

#[tokio::test]
async fn negotiation_preserves_typed_protocol_version_mismatch() {
    let (_dir, socket, listener) = bind_test_socket();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut daemon = ProtoStream::new(stream);
        send_daemon_hello(&mut daemon, "0.1.incompatible", proto::PROTOCOL_VERSION + 1).await;
    });

    let error = match DaemonClient::connect(&socket).await {
        Ok(_) => panic!("an incompatible daemon hello must reject the connection"),
        Err(error) => error,
    };

    assert!(is_protocol_version_mismatch(&error));
    let payload = error
        .downcast_ref::<proto::ErrorPayload>()
        .expect("the typed protocol error must survive the anyhow boundary");
    assert_eq!(payload.code, proto::ErrorCode::ProtocolVersion);
    assert!(!is_protocol_version_mismatch(&anyhow!(
        "wire protocol version mismatch in unrelated transport text"
    )));
    server.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn negotiation_rejects_a_daemon_that_does_not_send_a_hello() {
    let (_dir, socket, listener) = bind_test_socket();
    let server = tokio::spawn(async move {
        let (_stream, _) = listener.accept().await.unwrap();
        tokio::time::sleep(Duration::from_secs(10)).await;
    });
    let connect = tokio::spawn({
        let socket = socket.clone();
        async move { DaemonClient::connect(&socket).await }
    });

    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_millis(500)).await;
    let error = match connect.await.unwrap() {
        Ok(_) => panic!("missing hello must fail closed"),
        Err(error) => error,
    };
    assert!(is_protocol_version_mismatch(&error));
    let payload = error
        .downcast_ref::<proto::ErrorPayload>()
        .expect("missing hello must preserve a typed protocol error");
    assert_eq!(payload.code, proto::ErrorCode::ProtocolVersion);
    assert!(payload.message.contains("hello timed out"));
    server.abort();
}

#[tokio::test]
async fn negotiation_sends_attach_with_negotiated_client_protocol_version() {
    let (_dir, socket, listener) = bind_test_socket();
    let session_id = Uuid::new_v4();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut daemon = ProtoStream::new(stream);
        send_daemon_hello(
            &mut daemon,
            "0.1.handshake",
            proto::MIN_SUPPORTED_PROTOCOL_VERSION,
        )
        .await;
        daemon.set_negotiated_version(proto::MIN_SUPPORTED_PROTOCOL_VERSION);
        let request_id = match daemon.recv().await.unwrap().unwrap() {
            proto::RecvFrame::Envelope(env) => match env.body {
                Body::Request { id, request, .. } => {
                    match request {
                        Request::Attach {
                            client_protocol_version,
                            ..
                        } => assert_eq!(
                            client_protocol_version,
                            proto::MIN_SUPPORTED_PROTOCOL_VERSION
                        ),
                        other => panic!("expected attach request, got {other:?}"),
                    }
                    id
                }
                other => panic!("expected request body, got {other:?}"),
            },
            other => panic!("expected request envelope, got {other:?}"),
        };
        daemon
            .send(&Envelope::response(
                request_id,
                attached_response(session_id),
            ))
            .await
            .unwrap();
    });

    let client = DaemonClient::connect(&socket).await.unwrap();
    client
        .request(attach_request_with_client_protocol_version(
            Some(session_id),
            client.negotiated().version,
        ))
        .await
        .unwrap()
        .unwrap();

    server.await.unwrap();
}

/// Daemonless = own ephemeral daemon (`daemonless-tui-ephemeral-lifecycle.md`
/// §1). `LifecycleMode::AttachOwnEphemeral` attaches to this process's
/// cached ephemeral daemon when it's already up and reports
/// `owns_daemon = true` at that exact socket — i.e. a re-attach in the
/// same daemonless TUI (`/compact`, `/sessions` resume, `/new`)
/// reconnects to the owned daemon instead of spawning a second one. The
/// daemon is run in-process at the cached path with isolated XDG dirs, so
/// the spawn branch (which would launch a child) is never taken.
#[tokio::test]
async fn connect_uses_registered_in_process_context_without_socket() {
    let _guard = crate::test_env::lock_async().await;
    reset_own_ephemeral_paths_for_test();
    let root = tempfile::tempdir().expect("daemon path tempdir");

    let paths = temp_ephemeral_paths(root.path(), "cockpit-in-process-test");
    assert!(
        !paths.socket.exists(),
        "in-process transport must not require a socket file"
    );
    let db = crate::db::Db::open_in_memory().expect("in-memory daemon db");
    let ctx = crate::daemon::boot_in_process_with_db(paths.clone(), db)
        .await
        .expect("boot local daemon context");
    let client = connect_local_daemon(&paths.socket)
        .await
        .expect("connect by local socket key");
    let response = client
        .request_ok(Request::DaemonStatus)
        .await
        .expect("local daemon status");
    match response {
        Response::DaemonStatus { socket_path, .. } => {
            assert_eq!(socket_path, paths.socket.display().to_string());
        }
        other => panic!("unexpected response: {other:?}"),
    }
    assert!(
        !paths.socket.exists(),
        "in-process transport must not create a socket file"
    );
    drop(client);
    drop(ctx);
    reset_own_ephemeral_paths_for_test();
}

#[tokio::test]
async fn attach_own_ephemeral_uses_in_process_context() {
    let _guard = crate::test_env::lock_async().await;
    reset_own_ephemeral_paths_for_test();
    let root = tempfile::tempdir().expect("daemon path tempdir");

    let own = temp_ephemeral_paths(root.path(), "cockpit-eph-test-owned");
    set_own_ephemeral_paths_for_test(own.clone());
    let db = crate::db::Db::open_in_memory().expect("in-memory daemon db");
    let _ctx = crate::daemon::boot_in_process_with_db(own.clone(), db)
        .await
        .expect("boot local daemon context");

    let connected = probe_or_spawn(LifecycleMode::AttachOwnEphemeral)
        .await
        .expect("attach to own in-process daemon");
    assert!(
        !connected.owns_daemon,
        "in-process daemonless mode needs no child-process guard"
    );
    assert_eq!(
        connected.socket, own.socket,
        "must reuse the process-local owned path as the local transport key"
    );
    assert!(
        !connected.socket.exists(),
        "in-process daemonless mode must not bind a Unix socket"
    );
    connected
        .client
        .request_ok(Request::DaemonStatus)
        .await
        .expect("owned in-process daemon answers");

    reset_own_ephemeral_paths_for_test();
}

#[tokio::test(flavor = "current_thread")]
async fn in_process_auto_promote_hellos_without_os_socket() {
    let env = crate::test_env::TestEnvGuard::isolated_cockpit_home_async().await;
    let runtime = env.path().expect("isolated runtime root").join("runtime");
    env.set_var("XDG_RUNTIME_DIR", &runtime);
    let _promote = crate::daemon::enable_in_process_auto_promote();

    let session = super::ensure_persistent_daemon()
        .await
        .expect("in-process auto-promote must hello");
    let paths = crate::daemon::DaemonPaths::resolve_canonical().expect("canonical paths");
    assert!(
        !paths.socket.exists(),
        "in-process auto-promote must not bind {}",
        paths.socket.display()
    );
    session
        .client
        .request_ok(Request::DaemonStatus)
        .await
        .expect("promoted owner answers DaemonStatus");
}

#[tokio::test(flavor = "current_thread")]
async fn boot_test_persistent_daemon_hellos_without_os_socket() {
    let env = crate::test_env::TestEnvGuard::isolated_cockpit_home_async().await;
    let runtime = env.path().expect("isolated runtime root").join("runtime");
    env.set_var("XDG_RUNTIME_DIR", &runtime);
    let _daemon = crate::daemon::boot_test_persistent_daemon()
        .await
        .expect("boot isolated test daemon");

    let paths = crate::daemon::DaemonPaths::resolve_canonical().expect("canonical paths");
    let client = connect_local_daemon(&paths.socket)
        .await
        .expect("registered owner must hello");
    assert!(
        !paths.socket.exists(),
        "test persistent daemon must not bind {}",
        paths.socket.display()
    );
    client
        .request_ok(Request::DaemonStatus)
        .await
        .expect("booted owner answers DaemonStatus");
}

#[test]
fn attach_own_ephemeral_reuses_cached_path() {
    let _guard = crate::test_env::lock();
    let root = tempfile::tempdir().expect("daemon path tempdir");
    let own = temp_ephemeral_paths(root.path(), "cockpit-eph-test-cache");
    reset_own_ephemeral_paths_for_test();
    set_own_ephemeral_paths_for_test(own.clone());

    let first = own_ephemeral_paths().expect("first owned path");
    let second = own_ephemeral_paths().expect("second owned path");

    assert_eq!(first.socket, own.socket);
    assert_eq!(first.socket, second.socket);
    assert_eq!(first.pid_file, own.pid_file);
    assert_eq!(first.pid_file, second.pid_file);
    reset_own_ephemeral_paths_for_test();
}

#[test]
fn always_ephemeral_allocates_fresh_paths() {
    let root = tempfile::tempdir().expect("daemon path tempdir");
    let first = temp_ephemeral_paths(root.path(), "cockpit-eph-test-always-one");
    let second = temp_ephemeral_paths(root.path(), "cockpit-eph-test-always-two");

    assert_ne!(first.socket, second.socket);
    assert_ne!(first.pid_file, second.pid_file);
}

#[tokio::test]
async fn lifecycle_guard_is_retained_only_after_endpoint_acceptance() {
    struct DropSpy(std::sync::Arc<std::sync::atomic::AtomicUsize>);
    impl Drop for DropSpy {
        fn drop(&mut self) {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    let drops = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut retained = Vec::new();
    let (accepted, acceptance) = tokio::sync::oneshot::channel();
    accepted.send(()).unwrap();
    retain_guard_after_acceptance(
        Some(DropSpy(std::sync::Arc::clone(&drops))),
        acceptance,
        &mut retained,
    )
    .await;
    assert_eq!(retained.len(), 1);
    assert_eq!(drops.load(std::sync::atomic::Ordering::SeqCst), 0);
    drop(retained);
    assert_eq!(drops.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[tokio::test]
async fn cancelled_lifecycle_acceptance_reaps_unclaimed_guard() {
    struct DropSpy(std::sync::Arc<std::sync::atomic::AtomicUsize>);
    impl Drop for DropSpy {
        fn drop(&mut self) {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    let drops = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut retained = Vec::new();
    let (accepted, acceptance) = tokio::sync::oneshot::channel::<()>();
    drop(accepted);
    retain_guard_after_acceptance(
        Some(DropSpy(std::sync::Arc::clone(&drops))),
        acceptance,
        &mut retained,
    )
    .await;
    assert!(retained.is_empty());
    assert_eq!(drops.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[test]
fn lifecycle_intents_preserve_persistent_and_ephemeral_policy() {
    assert_eq!(
        mode_for_intent(cockpit_client::LifecycleIntent::AttachOrAutoPromote),
        LifecycleMode::AttachOrAutoPromote
    );
    assert_eq!(
        mode_for_intent(cockpit_client::LifecycleIntent::EnsurePersistent),
        LifecycleMode::AttachOrAutoPromote
    );
    assert_eq!(
        mode_for_intent(cockpit_client::LifecycleIntent::AttachOrEphemeral),
        LifecycleMode::AttachOrEphemeral
    );
    assert_eq!(
        mode_for_intent(cockpit_client::LifecycleIntent::AlwaysEphemeral),
        LifecycleMode::AlwaysEphemeral
    );
    assert_eq!(
        mode_for_intent(cockpit_client::LifecycleIntent::AttachOwnEphemeral),
        LifecycleMode::AttachOwnEphemeral
    );
}
