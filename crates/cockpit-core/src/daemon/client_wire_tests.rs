use super::*;
use cockpit_client::{ClientEndpoint, InProcessConnection, InProcessEndpoint};
use cockpit_proto::{Body, Envelope, ErrorCode, ErrorPayload, RecvFrame, Response};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

struct WireOwnerFixtureState {
    expect_promotion: bool,
    promotion_observed: AtomicBool,
    restart_if_idle_observed: AtomicBool,
}

fn connected_with_endpoint(
    client: cockpit_client::DaemonClient,
    endpoint: ClientEndpoint,
) -> ConnectedDaemon {
    ConnectedDaemon {
        client,
        endpoint,
        owns_daemon: false,
        ephemeral_owner: false,
        socket: PathBuf::from("daemon.sock"),
        startup_notice: None,
        promoted_from_ephemeral: false,
    }
}

fn canonical_ephemeral_paths() -> crate::daemon::DaemonPaths {
    let mut paths = crate::daemon::DaemonPaths::resolve_canonical()
        .expect("resolve isolated canonical daemon paths");
    paths.ephemeral = true;
    paths
}

fn spawn_fixture_owner_child() -> (std::process::Child, PathBuf) {
    #[cfg(unix)]
    {
        let executable = std::fs::canonicalize("/bin/sleep").expect("sleep executable");
        let child = std::process::Command::new(&executable)
            .arg("30")
            .spawn()
            .expect("spawn ephemeral owner fixture child");
        (child, executable)
    }
    #[cfg(windows)]
    {
        let executable = PathBuf::from(
            std::env::var("COMSPEC")
                .unwrap_or_else(|_| String::from("C:\\Windows\\System32\\cmd.exe")),
        );
        let child = std::process::Command::new(&executable)
            .args(["/C", "ping", "127.0.0.1", "-n", "60"])
            .spawn()
            .expect("spawn ephemeral owner fixture child");
        (child, executable)
    }
}

fn publish_test_ephemeral_owner(
    paths: &crate::daemon::DaemonPaths,
    child: &std::process::Child,
    executable: &Path,
) {
    cockpit_host::daemon_lifecycle::write_pid_file(&paths.pid_file, child.id(), executable)
        .expect("publish ephemeral owner receipt");
    crate::daemon::write_endpoint_record(paths).expect("publish ephemeral endpoint record");
}

async fn bind_test_pipe_listener() -> (tempfile::TempDir, PathBuf, crate::daemon::DaemonListener) {
    let dir = tempfile::tempdir().expect("tempdir");
    let socket = dir.path().join("daemon.sock");
    let listener = crate::daemon::bind_private_socket(&socket).expect("bind wire owner");
    (dir, socket, listener)
}

#[cfg(unix)]
async fn accept_test_pipe(listener: &crate::daemon::DaemonListener) -> tokio::net::UnixStream {
    listener.accept().await.expect("accept").0
}

#[cfg(windows)]
async fn accept_test_pipe(
    listener: &mut crate::daemon::DaemonListener,
) -> tokio::net::windows::named_pipe::NamedPipeServer {
    listener.accept().await.expect("accept")
}

async fn send_test_daemon_hello<S>(daemon: &mut cockpit_proto::ProtoStream<S>)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    daemon
        .send(&Envelope::response(
            uuid::Uuid::nil(),
            test_daemon_status_response(),
        ))
        .await
        .expect("hello");
}

fn test_daemon_status_response() -> Response {
    Response::DaemonStatus {
        pid: 1,
        uptime_secs: 0,
        active_sessions: 0,
        socket_path: "daemon.sock".into(),
        daemon_version: "0.1.acp".into(),
        protocol_version: proto::PROTOCOL_VERSION,
        paused_sessions: 0,
        database_path: "test.db".into(),
        schema_version: crate::db::EXPECTED_SCHEMA_VERSION,
    }
}

async fn confirm_test_client_lifetime<S>(daemon: &mut cockpit_proto::ProtoStream<S>)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    let id = match daemon.recv().await.expect("recv").expect("frame") {
        RecvFrame::Envelope(envelope) => match envelope.body {
            Body::Request {
                id,
                request: Request::DaemonStatus,
                ..
            } => id,
            other => panic!("expected lifetime confirmation, got {other:?}"),
        },
        other => panic!("expected envelope, got {other:?}"),
    };
    daemon
        .send(&Envelope::response(id, test_daemon_status_response()))
        .await
        .expect("lifetime confirmation");
}

async fn complete_test_wire_connect_handshake<S>(daemon: &mut cockpit_proto::ProtoStream<S>)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    confirm_test_client_lifetime(daemon).await;
    let id = match daemon.recv().await.expect("recv").expect("frame") {
        RecvFrame::Envelope(envelope) => match envelope.body {
            Body::Request {
                id,
                request: Request::ExchangeLocalPeerCredential,
                ..
            } => id,
            other => panic!("expected peer credential exchange, got {other:?}"),
        },
        other => panic!("expected peer credential exchange envelope, got {other:?}"),
    };
    daemon
        .send(&Envelope::response(
            id,
            Response::LocalPeerCredential {
                token: proto::OwnerCapabilityToken::new("test-peer-token"),
                role: proto::LocalClientRole::Cli,
            },
        ))
        .await
        .expect("peer credential exchange");
}

async fn serve_wire_owner_connection<S>(
    daemon: &mut cockpit_proto::ProtoStream<S>,
    state: &WireOwnerFixtureState,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    send_test_daemon_hello(daemon).await;
    loop {
        match tokio::time::timeout(Duration::from_millis(500), daemon.recv()).await {
            Ok(Ok(Some(RecvFrame::Envelope(envelope)))) => match envelope.body {
                Body::Request { id, request, .. } => {
                    let response = match request {
                        Request::DaemonStatus => test_daemon_status_response(),
                        Request::ExchangeLocalPeerCredential => Response::LocalPeerCredential {
                            token: proto::OwnerCapabilityToken::new("test-peer-token"),
                            role: proto::LocalClientRole::Cli,
                        },
                        Request::RestartIfIdle => {
                            state.restart_if_idle_observed.store(true, Ordering::SeqCst);
                            Response::RestartDecision {
                                will_restart: false,
                                reason: Some(
                                    "fixture owner stays live for ACP attach tests".into(),
                                ),
                            }
                        }
                        Request::PromoteToPersistent => {
                            assert!(
                                state.expect_promotion,
                                "unexpected PromoteToPersistent on this connection"
                            );
                            state.promotion_observed.store(true, Ordering::SeqCst);
                            Response::Ack
                        }
                        other => panic!("unexpected wire-owner request: {other:?}"),
                    };
                    daemon
                        .send(&Envelope::response(id, response))
                        .await
                        .expect("wire-owner response");
                }
                other => panic!("unexpected wire-owner body: {other:?}"),
            },
            _ => break,
        }
    }
}

fn spawn_wire_owner_server(
    listener: crate::daemon::DaemonListener,
    expect_promotion: bool,
) -> (tokio::task::JoinHandle<()>, Arc<WireOwnerFixtureState>) {
    let state = Arc::new(WireOwnerFixtureState {
        expect_promotion,
        promotion_observed: AtomicBool::new(false),
        restart_if_idle_observed: AtomicBool::new(false),
    });
    let state_for_task = Arc::clone(&state);
    let server = tokio::spawn(async move {
        let mut listener = listener;
        loop {
            #[cfg(unix)]
            let stream = match listener.accept().await {
                Ok((stream, _)) => stream,
                Err(_) => break,
            };
            #[cfg(windows)]
            let stream = match listener.accept().await {
                Ok(stream) => stream,
                Err(_) => break,
            };
            let mut daemon = cockpit_proto::ProtoStream::new(stream);
            serve_wire_owner_connection(&mut daemon, &state_for_task).await;
        }
    });
    (server, state)
}

#[test]
fn validate_acp_connected_daemon_rejects_in_process_owner() {
    let (requests, _request_rx) = tokio::sync::mpsc::channel(1);
    let (_events_tx, events) = tokio::sync::mpsc::channel(1);
    let (connections, _connection_rx) = tokio::sync::mpsc::channel(1);
    let (sensitive, _sensitive_rx) = tokio::sync::mpsc::channel(1);
    let endpoint = ClientEndpoint::InProcess(InProcessEndpoint::new(connections, sensitive));
    let connected = connected_with_endpoint(
        cockpit_client::DaemonClient::from_in_process(InProcessConnection { requests, events }),
        endpoint,
    );

    let error = validate_acp_connected_daemon(&connected).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("ACP requires a discoverable wire ledger owner")
    );
}

#[test]
fn validate_acp_connected_daemon_rejects_wire_endpoint_with_in_process_client() {
    let (requests, _request_rx) = tokio::sync::mpsc::channel(1);
    let (_events_tx, events) = tokio::sync::mpsc::channel(1);
    let connected = connected_with_endpoint(
        cockpit_client::DaemonClient::from_in_process(InProcessConnection { requests, events }),
        ClientEndpoint::Wire(PathBuf::from("daemon.sock")),
    );

    let error = validate_acp_connected_daemon(&connected).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("ACP requires a wire-backed ledger client")
    );
}

#[tokio::test]
async fn validate_acp_connected_daemon_accepts_wire_owner_with_capability() {
    let (dir, socket, listener) = bind_test_pipe_listener().await;

    let server = tokio::spawn(async move {
        #[cfg(unix)]
        let stream = accept_test_pipe(&listener).await;
        #[cfg(windows)]
        let stream = {
            let mut listener = listener;
            accept_test_pipe(&mut listener).await
        };
        let mut daemon = cockpit_proto::ProtoStream::new(stream);
        send_test_daemon_hello(&mut daemon).await;
        complete_test_wire_connect_handshake(&mut daemon).await;
    });

    let client = cockpit_client::DaemonClient::connect(&socket)
        .await
        .expect("wire connect");
    let connected = connected_with_endpoint(client, ClientEndpoint::Wire(socket.clone()));

    validate_acp_connected_daemon(&connected).expect("wire owner with capability");
    assert!(connected.client.is_socket_backed());

    drop(connected);
    server.await.expect("server");
    drop(dir);
}

#[tokio::test]
async fn validate_acp_connected_daemon_rejects_wire_owner_without_capability() {
    let (dir, socket, listener) = bind_test_pipe_listener().await;

    let server = tokio::spawn(async move {
        #[cfg(unix)]
        let stream = accept_test_pipe(&listener).await;
        #[cfg(windows)]
        let stream = {
            let mut listener = listener;
            accept_test_pipe(&mut listener).await
        };
        let mut daemon = cockpit_proto::ProtoStream::new(stream);
        send_test_daemon_hello(&mut daemon).await;
        confirm_test_client_lifetime(&mut daemon).await;
        let id = match daemon.recv().await.expect("recv").expect("frame") {
            RecvFrame::Envelope(envelope) => match envelope.body {
                Body::Request {
                    id,
                    request: Request::ExchangeLocalPeerCredential,
                    ..
                } => id,
                other => panic!("expected peer credential exchange, got {other:?}"),
            },
            other => panic!("expected peer credential exchange envelope, got {other:?}"),
        };
        daemon
            .send(&Envelope::error(
                Some(id),
                ErrorPayload {
                    code: ErrorCode::Authorization,
                    message: "peer role attestation failed".into(),
                },
            ))
            .await
            .expect("deny peer credential exchange");
    });

    // An exchange denied for missing launch provenance keeps the client
    // connected as an unauthenticated, table-governed peer (public RPCs
    // stay reachable); it just never holds an owner-class credential.
    let client = cockpit_client::DaemonClient::connect(&socket)
        .await
        .expect("authorization denial must not fail the wire connect");
    let connected = connected_with_endpoint(client, ClientEndpoint::Wire(socket.clone()));

    let error = validate_acp_connected_daemon(&connected)
        .expect_err("ACP ingress requires the peer-bound owner credential");
    assert!(error.to_string().contains("owner credential"), "{error:#}");
    assert!(!connected.client.has_owner_capability());

    drop(connected);
    server.await.expect("server");
    drop(dir);
}

#[tokio::test(flavor = "current_thread")]
async fn acquire_acp_socket_daemon_attaches_to_running_wire_owner() {
    let env = crate::test_env::TestEnvGuard::isolated_cockpit_home_async().await;
    let runtime = env.path().expect("isolated runtime root").join("runtime");
    env.set_var("XDG_RUNTIME_DIR", &runtime);

    let paths = canonical_ephemeral_paths();
    let (mut owner_child, executable) = spawn_fixture_owner_child();
    publish_test_ephemeral_owner(&paths, &owner_child, &executable);
    let listener = crate::daemon::bind_private_socket(&paths.socket).expect("bind owner");
    crate::daemon::skew_restart::reset_skew_restart_cooldown_for_tests();
    let (server, fixture) = spawn_wire_owner_server(listener, false);

    let client = acquire_acp_socket_daemon(false)
        .await
        .expect("ACP must attach to a discoverable wire owner");
    assert!(client.is_socket_backed());
    assert!(client.has_owner_capability());
    assert!(
        fixture.restart_if_idle_observed.load(Ordering::SeqCst),
        "attach must run the production version-skew RestartIfIdle probe before reuse"
    );
    assert!(
        !fixture.promotion_observed.load(Ordering::SeqCst),
        "ACP with background_agents=false must not promote an attached ephemeral owner"
    );
    client
        .request_ok(Request::DaemonStatus)
        .await
        .expect("attached wire owner answers DaemonStatus");

    drop(client);
    server.abort();
    owner_child.kill().ok();
    owner_child.wait().ok();
    let _ = std::fs::remove_file(&paths.socket);
    let _ = std::fs::remove_file(&paths.pid_file);
}

#[tokio::test(flavor = "current_thread")]
async fn acquire_acp_socket_daemon_promotes_ephemeral_when_background_agents_enabled() {
    let env = crate::test_env::TestEnvGuard::isolated_cockpit_home_async().await;
    let runtime = env.path().expect("isolated runtime root").join("runtime");
    env.set_var("XDG_RUNTIME_DIR", &runtime);

    let paths = canonical_ephemeral_paths();
    let (mut owner_child, executable) = spawn_fixture_owner_child();
    publish_test_ephemeral_owner(&paths, &owner_child, &executable);
    let listener = crate::daemon::bind_private_socket(&paths.socket).expect("bind owner");
    crate::daemon::skew_restart::reset_skew_restart_cooldown_for_tests();
    let (server, fixture) = spawn_wire_owner_server(listener, true);

    let client = acquire_acp_socket_daemon(true)
        .await
        .expect("ACP must attach and promote an ephemeral wire owner");
    assert!(client.is_socket_backed());
    assert!(client.has_owner_capability());
    assert!(
        fixture.restart_if_idle_observed.load(Ordering::SeqCst),
        "promotion attach must run the production version-skew RestartIfIdle probe before reuse"
    );
    assert!(
        fixture.promotion_observed.load(Ordering::SeqCst),
        "ACP with background_agents=true must promote an attached ephemeral wire owner in place"
    );
    client
        .request_ok(Request::DaemonStatus)
        .await
        .expect("promoted wire owner answers DaemonStatus");

    drop(client);
    server.abort();
    owner_child.kill().ok();
    owner_child.wait().ok();
    let _ = std::fs::remove_file(&paths.socket);
    let _ = std::fs::remove_file(&paths.pid_file);
}

#[tokio::test(flavor = "current_thread")]
async fn acquire_acp_socket_daemon_spawns_ephemeral_wire_owner_when_absent() {
    let env = crate::test_env::TestEnvGuard::isolated_cockpit_home_async().await;
    let runtime = env.path().expect("isolated runtime root").join("runtime");
    env.set_var("XDG_RUNTIME_DIR", &runtime);

    let paths = crate::daemon::DaemonPaths::resolve_canonical().expect("canonical paths");
    assert!(
        !paths.socket.exists() && !paths.pid_file.exists(),
        "isolated home must not already host a daemon"
    );

    let client = acquire_acp_socket_daemon(false)
        .await
        .expect("ACP must spawn a discoverable ephemeral wire owner when none is running");
    assert!(client.is_socket_backed());
    assert!(client.has_owner_capability());
    client
        .request_ok(Request::DaemonStatus)
        .await
        .expect("spawned wire owner answers DaemonStatus");

    drop(client);
    tokio::time::timeout(Duration::from_secs(5), async {
        while paths.socket.exists() || paths.pid_file.exists() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("spawned ephemeral wire owner must reap after the last ACP client disconnects");
}

#[tokio::test(flavor = "current_thread")]
async fn acquire_acp_socket_daemon_spawns_persistent_wire_owner_when_background_agents_enabled() {
    let env = crate::test_env::TestEnvGuard::isolated_cockpit_home_async().await;
    let runtime = env.path().expect("isolated runtime root").join("runtime");
    env.set_var("XDG_RUNTIME_DIR", &runtime);

    let paths = crate::daemon::DaemonPaths::resolve_canonical().expect("canonical paths");
    assert!(
        !paths.socket.exists() && !paths.pid_file.exists(),
        "isolated home must not already host a daemon"
    );

    let client = acquire_acp_socket_daemon(true)
        .await
        .expect("ACP must spawn a discoverable persistent wire owner when none is running");
    assert!(client.is_socket_backed());
    assert!(client.has_owner_capability());
    client
        .request_ok(Request::DaemonStatus)
        .await
        .expect("spawned persistent wire owner answers DaemonStatus");

    drop(client);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        paths.socket.exists(),
        "background_agents=true spawn must keep the wire owner after ACP disconnect"
    );
    assert!(
        paths.pid_file.exists(),
        "background_agents=true spawn must keep the pid receipt after ACP disconnect"
    );

    crate::daemon::stop(&paths).expect("stop spawned persistent wire owner");
    tokio::time::timeout(Duration::from_secs(5), async {
        while paths.socket.exists() || paths.pid_file.exists() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("stopped persistent wire owner must retire its metadata");
}

#[tokio::test(flavor = "current_thread")]
async fn acquire_acp_socket_daemon_rejects_in_process_auto_promote_owner() {
    let env = crate::test_env::TestEnvGuard::isolated_cockpit_home_async().await;
    let runtime = env.path().expect("isolated runtime root").join("runtime");
    env.set_var("XDG_RUNTIME_DIR", &runtime);
    let _promote = crate::daemon::enable_in_process_auto_promote();

    let session = ensure_persistent_daemon()
        .await
        .expect("in-process auto-promote must hello");
    let error = acquire_acp_socket_daemon(false)
        .await
        .expect_err("ACP must reject the in-process optimization");
    assert!(
        error
            .to_string()
            .contains("ACP requires a wire-backed ledger client")
            || error
                .to_string()
                .contains("ACP requires a discoverable wire ledger owner")
    );
    drop(session);
}
