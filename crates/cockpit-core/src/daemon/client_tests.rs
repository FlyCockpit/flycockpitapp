#![cfg(test)]

use super::*;
use crate::daemon::proto::Response;
use cockpit_client::is_protocol_version_mismatch;
use cockpit_proto::{Body, Envelope, ProtoStream};
use tokio::net::{UnixListener, UnixStream};
use uuid::Uuid;

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
        session_entry_mode: proto::NonCodeSessionEntryMode::Assistant,
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
        resume_compaction_offer: None,
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

fn canonical_ephemeral_paths() -> crate::daemon::DaemonPaths {
    let mut paths = crate::daemon::DaemonPaths::resolve_canonical()
        .expect("resolve isolated canonical daemon paths");
    paths.ephemeral = true;
    paths
}

fn publish_test_ephemeral_owner(paths: &crate::daemon::DaemonPaths) -> std::process::Child {
    let executable = std::fs::canonicalize("/bin/sleep").expect("canonical fixture executable");
    let child = std::process::Command::new(&executable)
        .arg("30")
        .spawn()
        .expect("spawn ephemeral owner fixture child");
    cockpit_host::daemon_lifecycle::write_pid_file(&paths.pid_file, child.id(), &executable)
        .expect("publish ephemeral owner receipt");
    crate::daemon::write_endpoint_record(paths).expect("publish ephemeral endpoint record");
    child
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

async fn confirm_client_lifetime(daemon: &mut ProtoStream<UnixStream>) {
    let id = match daemon.recv().await.unwrap().unwrap() {
        cockpit_proto::RecvFrame::Envelope(envelope) => match envelope.body {
            Body::Request {
                id,
                request: Request::DaemonStatus,
                ..
            } => id,
            other => panic!("expected lifetime confirmation, got {other:?}"),
        },
        other => panic!("expected lifetime confirmation envelope, got {other:?}"),
    };
    daemon
        .send(&Envelope::response(
            id,
            daemon_status_response_with("0.1.handshake", proto::PROTOCOL_VERSION),
        ))
        .await
        .unwrap();
}

async fn accept_restart_if_idle(daemon: &mut ProtoStream<UnixStream>) {
    let id = match daemon.recv().await.unwrap().unwrap() {
        cockpit_proto::RecvFrame::Envelope(envelope) => match envelope.body {
            Body::Request {
                id,
                request: Request::RestartIfIdle,
                ..
            } => id,
            other => panic!("expected RestartIfIdle, got {other:?}"),
        },
        other => panic!("expected RestartIfIdle envelope, got {other:?}"),
    };
    daemon
        .send(&Envelope::response(
            id,
            Response::RestartDecision {
                will_restart: true,
                reason: None,
            },
        ))
        .await
        .unwrap();
}

async fn accept_live_promotion_or_restart(
    daemon: &mut ProtoStream<UnixStream>,
    listener: &UnixListener,
) {
    let request = match daemon.recv().await.unwrap().unwrap() {
        cockpit_proto::RecvFrame::Envelope(envelope) => match envelope.body {
            Body::Request { id, request, .. } => (id, request),
            other => panic!("expected promotion request, got {other:?}"),
        },
        other => panic!("expected promotion request envelope, got {other:?}"),
    };
    match request.1 {
        Request::RestartIfIdle => {
            daemon
                .send(&Envelope::response(
                    request.0,
                    Response::RestartDecision {
                        will_restart: true,
                        reason: None,
                    },
                ))
                .await
                .unwrap();
        }
        Request::PromoteToPersistent => {
            daemon
                .send(&Envelope::response(request.0, Response::Unknown))
                .await
                .unwrap();
            let (stream, _) = listener
                .accept()
                .await
                .expect("accept restart fallback client");
            let mut fallback = ProtoStream::new(stream);
            send_daemon_hello(&mut fallback, "0.1.ephemeral", proto::PROTOCOL_VERSION).await;
            confirm_client_lifetime(&mut fallback).await;
            accept_restart_if_idle(&mut fallback).await;
        }
        other => panic!("expected PromoteToPersistent or RestartIfIdle, got {other:?}"),
    }
}

#[tokio::test]
async fn negotiation_parses_daemon_hello_on_connect() {
    let (_dir, socket, listener) = bind_test_socket();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut daemon = ProtoStream::new(stream);
        send_daemon_hello(&mut daemon, "0.1.handshake", proto::PROTOCOL_VERSION).await;
        confirm_client_lifetime(&mut daemon).await;
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
        confirm_client_lifetime(&mut daemon).await;
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

#[tokio::test]
async fn connect_uses_registered_in_process_context_without_socket() {
    let _guard = crate::test_env::lock_async().await;
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
}

#[tokio::test(flavor = "current_thread")]
async fn one_shot_daemon_uses_an_in_process_owner_without_socket_metadata() {
    let env = crate::test_env::TestEnvGuard::isolated_cockpit_home_async().await;
    let runtime = env.path().expect("isolated runtime root").join("runtime");
    env.set_var("XDG_RUNTIME_DIR", &runtime);

    let response = super::run_one_shot_daemon(|client| {
        Box::pin(async move { client.request_ok(Request::DaemonStatus).await })
    })
    .await
    .expect("one-shot daemon status");
    assert!(matches!(response, Response::DaemonStatus { .. }));

    let paths = crate::daemon::DaemonPaths::resolve_canonical().expect("canonical paths");
    assert!(
        !paths.socket.exists(),
        "one-shot in-process owner must not bind {}",
        paths.socket.display()
    );
    assert!(
        !paths.pid_file.exists(),
        "one-shot in-process owner must not publish a pid record"
    );
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
async fn accepted_assistant_promotion_replaces_the_ephemeral_owner_with_persistent() {
    let env = crate::test_env::TestEnvGuard::isolated_cockpit_home_async().await;
    let runtime = env.path().expect("isolated runtime root").join("runtime");
    env.set_var("XDG_RUNTIME_DIR", &runtime);
    let _promote = crate::daemon::enable_in_process_auto_promote();

    let paths = canonical_ephemeral_paths();
    let mut owner_child = publish_test_ephemeral_owner(&paths);
    let listener = UnixListener::bind(&paths.socket).expect("bind ephemeral promotion socket");
    let socket = paths.socket.clone();
    let predecessor_paths = paths.clone();
    let predecessor = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept promotion client");
        let mut daemon = ProtoStream::new(stream);
        send_daemon_hello(&mut daemon, "0.1.ephemeral", proto::PROTOCOL_VERSION).await;
        confirm_client_lifetime(&mut daemon).await;
        accept_live_promotion_or_restart(&mut daemon, &listener).await;
        drop(daemon);
        drop(listener);
        owner_child.kill().expect("stop released predecessor child");
        owner_child.wait().expect("reap released predecessor child");
        std::fs::remove_file(predecessor_paths.pid_file)
            .expect("release accepted predecessor receipt");
        std::fs::remove_file(&socket).expect("release accepted predecessor socket");
    });

    let promoted = promote_ephemeral_owner(&paths, None)
        .await
        .expect("accepted promotion must acquire a persistent replacement");

    assert!(promoted.promoted_from_ephemeral);
    assert!(!promoted.owns_daemon);
    promoted
        .client
        .request_ok(Request::DaemonStatus)
        .await
        .expect("persistent replacement answers DaemonStatus");
    predecessor.await.expect("predecessor task");
}

#[test]
fn promoted_lifecycle_resolution_preserves_an_independent_startup_notice() {
    let (requests, _request_rx) = tokio::sync::mpsc::channel(1);
    let (_events_tx, events) = tokio::sync::mpsc::channel(1);
    let resolution = lifecycle_resolution(ConnectedDaemon {
        client: DaemonClient::from_in_process(cockpit_client::InProcessConnection {
            requests,
            events,
        }),
        endpoint: cockpit_client::ClientEndpoint::Wire(PathBuf::from("persistent.sock")),
        owns_daemon: false,
        ephemeral_owner: false,
        socket: PathBuf::from("persistent.sock"),
        startup_notice: Some("daemon version skew resolved".to_string()),
        promoted_from_ephemeral: true,
    });

    assert_eq!(
        resolution.startup_notice.as_deref(),
        Some("daemon version skew resolved")
    );
    assert!(
        resolution.promoted_from_ephemeral,
        "the TUI must receive the ownership transition even when startup text is present"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn accepted_promotion_terminal_failure_releases_the_lifecycle_host() {
    let env = crate::test_env::TestEnvGuard::isolated_cockpit_home_async().await;
    let runtime = env.path().expect("isolated runtime root").join("runtime");
    env.set_var("XDG_RUNTIME_DIR", &runtime);
    let paths = canonical_ephemeral_paths();
    let mut owner_child = publish_test_ephemeral_owner(&paths);
    let listener = UnixListener::bind(&paths.socket).expect("bind ephemeral promotion socket");
    let socket = paths.socket.clone();
    let predecessor_paths = paths.clone();
    let predecessor = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept promotion client");
        let mut daemon = ProtoStream::new(stream);
        send_daemon_hello(&mut daemon, "0.1.ephemeral", proto::PROTOCOL_VERSION).await;
        confirm_client_lifetime(&mut daemon).await;
        accept_restart_if_idle(&mut daemon).await;
        drop(daemon);
        drop(listener);
        owner_child.kill().expect("stop released predecessor child");
        owner_child.wait().expect("reap released predecessor child");
        std::fs::remove_file(predecessor_paths.pid_file)
            .expect("release accepted predecessor receipt");
        std::fs::remove_file(&socket).expect("release accepted predecessor socket");
    });

    let (lifecycle, requests) = cockpit_client::LifecycleClient::channel(2);
    let resolution_count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let host = tokio::spawn({
        let paths = paths.clone();
        let resolution_count = std::sync::Arc::clone(&resolution_count);
        async move {
            serve_lifecycle_requests_with(
                requests,
                move |request| -> LifecycleResolutionFuture<'_> {
                    let paths = paths.clone();
                    let attempt =
                        resolution_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    Box::pin(async move {
                        if attempt == 0 {
                            assert_eq!(
                                request.intent,
                                cockpit_client::LifecycleIntent::PromoteToPersistent
                            );
                            let recovery = PromotionRecoveryPolicy {
                                replacement_timeout: Duration::ZERO,
                                predecessor_release_timeout: Duration::ZERO,
                            };
                            let connected = promote_ephemeral_owner_with_recovery_policy(
                                &paths,
                                Some(request),
                                recovery,
                            )
                            .await?;
                            Ok(lifecycle_resolution(connected))
                        } else {
                            Ok(cockpit_client::LifecycleResolution {
                                endpoint: cockpit_client::ClientEndpoint::Wire(
                                    paths.socket.clone(),
                                ),
                                owns_daemon: false,
                                ephemeral_owner: false,
                                socket: paths.socket.clone(),
                                startup_notice: Some("later lifecycle notice".to_string()),
                                promoted_from_ephemeral: false,
                            })
                        }
                    })
                },
            )
            .await
        }
    });

    let terminal = tokio::time::timeout(
        Duration::from_secs(1),
        lifecycle.resolve(cockpit_client::LifecycleIntent::PromoteToPersistent),
    )
    .await
    .expect("accepted promotion recovery must reach a terminal result")
    .expect_err("expired accepted-handoff deadline must reject the promotion");
    assert!(
        terminal.contains("persistent Assistant daemon replacement"),
        "terminal policy must remain observable through lifecycle resolution"
    );

    let later = lifecycle
        .resolve(cockpit_client::LifecycleIntent::AttachOrPersistent)
        .await
        .expect("terminal promotion failure must not wedge the lifecycle host");
    assert_eq!(
        later.startup_notice.as_deref(),
        Some("later lifecycle notice")
    );
    assert_eq!(
        resolution_count.load(std::sync::atomic::Ordering::SeqCst),
        2,
        "the serialized host must accept a request after the terminal recovery failure"
    );

    drop(lifecycle);
    host.await
        .expect("lifecycle host task")
        .expect("lifecycle host");
    predecessor.await.expect("predecessor task");
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
fn socket_ephemeral_shutdown_authority_transfers_to_client_presence_after_boot() {
    let source = include_str!("client.rs");
    let receipt = source
        .find("guard.bind_published_receipt()?")
        .expect("the provisional guard binds the boot receipt");
    let disarm = source[receipt..]
        .find("guard.disarm()")
        .map(|offset| receipt + offset)
        .expect("a booted ephemeral guard transfers shutdown authority");
    assert!(receipt < disarm);
    assert!(
        !source.contains("take_owned_daemon_guard")
            && !source.contains("take_lifecycle_guard")
            && !source.contains("owned_daemons"),
        "no foreground or lifecycle actor may retain socket-owner shutdown authority"
    );
}

#[test]
fn lifecycle_intents_preserve_persistent_and_ephemeral_policy() {
    assert_eq!(
        mode_for_intent(cockpit_client::LifecycleIntent::AttachOrPersistent),
        LifecycleMode::AttachOrPersistent
    );
    assert_eq!(
        mode_for_intent(cockpit_client::LifecycleIntent::AttachOrEphemeral),
        LifecycleMode::AttachOrEphemeral
    );
    assert_eq!(
        mode_for_intent(cockpit_client::LifecycleIntent::PromoteToPersistent),
        LifecycleMode::PromoteToPersistent
    );
}

#[test]
fn background_agents_setting_selects_new_owner_lifetime() {
    assert_eq!(
        LifecycleMode::from_background_agents(true),
        LifecycleMode::AttachOrPersistent
    );
    assert_eq!(
        LifecycleMode::from_background_agents(false),
        LifecycleMode::AttachOrEphemeral
    );
}

#[test]
fn discover_attach_plan_restart_release_spawns_instead_of_failing() {
    use crate::daemon::DaemonStatus;

    assert_eq!(
        discover_attach_plan(DaemonStatus::LivePidSocketUnreachable, false),
        DiscoverAttachPlan::WaitForRestart
    );
    assert_eq!(
        after_restart_wait(SharedWaitError::Released),
        RestartWaitPlan::WaitForReplacement
    );
    assert_eq!(
        after_restart_wait(SharedWaitError::Wedged),
        RestartWaitPlan::FailWedged
    );
}

#[test]
fn discover_attach_plan_fails_closed_for_unavailable_owners() {
    use crate::daemon::DaemonStatus;

    assert_eq!(
        discover_attach_plan(DaemonStatus::IncompatibleProtocol, true),
        DiscoverAttachPlan::FailIncompatible
    );
    assert_eq!(
        discover_attach_plan(DaemonStatus::UnverifiedPid, false),
        DiscoverAttachPlan::FailUnreachable
    );
}
