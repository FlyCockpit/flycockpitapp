#![cfg(test)]

use super::*;
use crate::daemon::proto::Response;
use cockpit_client::is_protocol_version_mismatch;
use cockpit_proto::{Body, Envelope, ProtoStream};
use tokio::net::{UnixListener, UnixStream};
use uuid::Uuid;

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
        pending_recovery_sessions: Vec::new(),
    }
}

fn attach_request(session_id: Option<Uuid>) -> Request {
    Request::Attach {
        session_id,
        since_seq: None,
        project_root: Some("/tmp".into()),
        initial_model: None,
        no_sandbox: false,
        interactive: true,
        session_entry_mode: proto::NonCodeSessionEntryMode::Assistant,
        model_override: None,
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
        removed_user_message_seqs: Vec::new(),
        paused_work: Vec::new(),
        repair_required: None,
        resume_compaction_offer: None,
        daemon_version: proto::DAEMON_VERSION.to_string(),
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

/// Publish a receipt for a live, daemon-shaped process (the spawn harness
/// held in `daemon worker`) so a pinned release witness can verify it.
fn publish_verified_test_owner(paths: &crate::daemon::DaemonPaths) -> std::process::Child {
    let binary = crate::daemon::discover_daemon_spawn_harness_executable()
        .expect("daemon spawn harness is built with the test binary");
    let child = std::process::Command::new(&binary)
        .args(["daemon", "worker"])
        .env("COCKPIT_WORKER_WATCH_TEST_HOLD", "1")
        .spawn()
        .expect("spawn daemon-shaped owner fixture");
    cockpit_host::daemon_lifecycle::write_pid_file(&paths.pid_file, child.id(), &binary)
        .expect("publish owner receipt");
    crate::daemon::write_endpoint_record(paths).expect("publish owner endpoint record");
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

async fn complete_wire_connect_handshake(daemon: &mut ProtoStream<UnixStream>) {
    confirm_client_lifetime(daemon).await;
    let id = match daemon.recv().await.unwrap().unwrap() {
        cockpit_proto::RecvFrame::Envelope(envelope) => match envelope.body {
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

async fn accept_in_place_promotion(
    daemon: &mut ProtoStream<UnixStream>,
    listener: &UnixListener,
    paths: &crate::daemon::DaemonPaths,
) {
    let request = match daemon.recv().await.unwrap().unwrap() {
        cockpit_proto::RecvFrame::Envelope(envelope) => match envelope.body {
            Body::Request { id, request, .. } => (id, request),
            other => panic!("expected promotion request, got {other:?}"),
        },
        other => panic!("expected promotion request envelope, got {other:?}"),
    };
    match request.1 {
        Request::PromoteToPersistent => {
            let mut persistent = paths.clone();
            persistent.ephemeral = false;
            crate::daemon::write_endpoint_record(&persistent)
                .expect("publish persistent endpoint after in-place promotion");
            daemon
                .send(&Envelope::response(request.0, Response::Ack))
                .await
                .unwrap();
            // Discovery probes the same socket for a hello, then the client
            // re-attaches. Serve both on this live owner.
            let (probe, _) = listener
                .accept()
                .await
                .expect("accept post-promotion discovery probe");
            let mut probe = ProtoStream::new(probe);
            send_daemon_hello(&mut probe, "0.1.persistent", proto::PROTOCOL_VERSION).await;
            drop(probe);
            let (stream, _) = listener
                .accept()
                .await
                .expect("accept post-promotion client on the same socket");
            let mut promoted = ProtoStream::new(stream);
            send_daemon_hello(&mut promoted, "0.1.persistent", proto::PROTOCOL_VERSION).await;
            // The re-attached client performs the full wire connect handshake
            // (lifetime confirmation plus the local peer credential exchange).
            complete_wire_connect_handshake(&mut promoted).await;
            loop {
                match tokio::time::timeout(std::time::Duration::from_millis(200), promoted.recv())
                    .await
                {
                    Ok(Ok(Some(cockpit_proto::RecvFrame::Envelope(envelope)))) => {
                        match envelope.body {
                            Body::Request {
                                id,
                                request: Request::DaemonStatus,
                                ..
                            } => {
                                promoted
                                    .send(&Envelope::response(
                                        id,
                                        daemon_status_response_with(
                                            "0.1.persistent",
                                            proto::PROTOCOL_VERSION,
                                        ),
                                    ))
                                    .await
                                    .unwrap();
                            }
                            other => panic!("unexpected post-promotion request: {other:?}"),
                        }
                    }
                    _ => break,
                }
            }
        }
        other => panic!("expected PromoteToPersistent, got {other:?}"),
    }
}

#[tokio::test]
async fn negotiation_parses_daemon_hello_on_connect() {
    let (_dir, socket, listener) = bind_test_socket();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut daemon = ProtoStream::new(stream);
        send_daemon_hello(&mut daemon, "0.1.handshake", proto::PROTOCOL_VERSION).await;
        complete_wire_connect_handshake(&mut daemon).await;
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

/// A daemon that accepts and then closes before its hello (an owner that
/// began draining after discovery) keeps the fail-closed typed protocol
/// error, and is additionally marked as a mid-handshake close so a lifecycle
/// resolver can wait for the owner to exit and rediscover instead of
/// stranding the caller. A timed-out or incompatible hello never carries
/// that marker.
#[tokio::test]
async fn negotiation_marks_a_daemon_that_closes_before_its_hello() {
    let (_dir, socket, listener) = bind_test_socket();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        drop(stream);
    });
    let error = match DaemonClient::connect(&socket).await {
        Ok(_) => panic!("a daemon that closes before its hello must fail the connect"),
        Err(error) => error,
    };
    assert!(cockpit_client::is_daemon_closed_during_handshake(&error));
    assert!(is_protocol_version_mismatch(&error));
    let payload = error
        .downcast_ref::<proto::ErrorPayload>()
        .expect("a mid-handshake close keeps the typed protocol error");
    assert!(
        payload
            .message
            .contains("closed the connection before its hello")
    );
    assert_eq!(error.to_string(), payload.to_string());
    server.await.unwrap();

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
    assert!(!cockpit_client::is_daemon_closed_during_handshake(&error));
    server.await.unwrap();
}

/// Draining-owner recovery is scoped: only a mid-handshake close or a gone
/// listener counts as a departing owner.
#[test]
fn departing_owner_recovery_requires_a_close_or_a_gone_listener() {
    assert!(is_departing_owner_attach_error(&anyhow::Error::new(
        std::io::Error::from(std::io::ErrorKind::ConnectionRefused)
    )));
    assert!(is_departing_owner_attach_error(
        &anyhow::Error::new(cockpit_client::DaemonClosedDuringHandshake)
            .context("daemon protocol handshake failed")
    ));
    assert!(!is_departing_owner_attach_error(&anyhow::Error::new(
        proto::ErrorPayload {
            code: proto::ErrorCode::ProtocolVersion,
            message: "daemon protocol handshake failed: daemon hello timed out".into(),
        }
    )));
}

async fn isolated_canonical_paths(
    env: &crate::test_env::TestEnvGuard,
) -> crate::daemon::DaemonPaths {
    let runtime = env.path().expect("isolated runtime root").join("runtime");
    env.set_var("XDG_RUNTIME_DIR", &runtime);
    canonical_ephemeral_paths()
}

/// Serve a daemon hello to every connection on `listener` until aborted.
fn serve_hellos(listener: UnixListener, version: &'static str) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let mut daemon = ProtoStream::new(stream);
            send_daemon_hello(&mut daemon, version, proto::PROTOCOL_VERSION).await;
        }
    })
}

fn stop_fixture_owner(mut child: std::process::Child) {
    child.kill().expect("stop fixture owner");
    child.wait().expect("reap fixture owner");
}

async fn await_departing_within(
    paths: &crate::daemon::DaemonPaths,
    owner: DiscoveredOwner,
    budget: &mut DepartingOwnerBudget,
    bound: Duration,
) -> Result<()> {
    tokio::time::timeout(
        bound,
        await_departing_owner(paths, owner, budget, anyhow!("attach closed")),
    )
    .await
    .expect("the departing-owner wait is bounded by its budget")
}

/// An owner that exited and retired its endpoint lets the resolver
/// rediscover (and spawn) — observed through the handle pinned to the
/// receipt captured before the attach.
#[tokio::test(flavor = "current_thread")]
async fn departing_owner_wait_returns_once_the_pinned_owner_retired() {
    let env = crate::test_env::TestEnvGuard::isolated_cockpit_home_async().await;
    let paths = isolated_canonical_paths(&env).await;
    let owner_child = publish_verified_test_owner(&paths);
    let owner = DiscoveredOwner::capture(&paths);
    assert!(
        owner.receipt.is_some(),
        "the receipt is captured before the attach"
    );
    stop_fixture_owner(owner_child);
    std::fs::remove_file(&paths.pid_file).expect("owner retires its receipt");
    let mut budget = DepartingOwnerBudget::default();
    await_departing_within(&paths, owner, &mut budget, Duration::from_secs(10))
        .await
        .expect("a retired owner allows rediscovery");
}

/// A crashed owner (SIGKILL mid-drain) leaves its receipt and socket behind.
/// That stale endpoint must not turn into a hard attach failure: once the
/// pinned process is gone and the endpoint no longer answers, the resolver
/// rediscovers, where the spawn path reclaims the stale metadata.
#[tokio::test(flavor = "current_thread")]
async fn departing_owner_wait_recovers_from_a_crash_that_left_its_endpoint() {
    let env = crate::test_env::TestEnvGuard::isolated_cockpit_home_async().await;
    let paths = isolated_canonical_paths(&env).await;
    let owner_child = publish_verified_test_owner(&paths);
    let listener = UnixListener::bind(&paths.socket).expect("bind fixture owner socket");
    let owner = DiscoveredOwner::capture(&paths);
    // Crash: the process dies and its listener closes, but the receipt and
    // the socket path stay published.
    stop_fixture_owner(owner_child);
    drop(listener);
    assert!(paths.pid_file.exists() && paths.socket.exists());
    let mut budget = DepartingOwnerBudget::default();
    await_departing_within(&paths, owner, &mut budget, Duration::from_secs(10))
        .await
        .expect("a crashed owner with a stale endpoint allows rediscovery");
}

/// A successor published by another starter before this waiter looks again
/// ends the wait (its receipt differs from the captured one): the resolver
/// attaches to it instead of failing.
#[tokio::test(flavor = "current_thread")]
async fn departing_owner_wait_returns_when_a_replacement_is_published_first() {
    let env = crate::test_env::TestEnvGuard::isolated_cockpit_home_async().await;
    let paths = isolated_canonical_paths(&env).await;
    let departing = publish_verified_test_owner(&paths);
    let owner = DiscoveredOwner::capture(&paths);
    stop_fixture_owner(departing);
    std::fs::remove_file(&paths.pid_file).expect("departing owner retires its receipt");
    // Another starter publishes a healthy successor at the same endpoint.
    let successor = publish_verified_test_owner(&paths);
    let listener = UnixListener::bind(&paths.socket).expect("bind successor socket");
    let server = serve_hellos(listener, "0.1.successor");
    assert_ne!(
        cockpit_host::daemon_lifecycle::read_daemon_pid_record(&paths.pid_file),
        owner.receipt,
        "the successor has its own receipt"
    );
    let mut budget = DepartingOwnerBudget::default();
    await_departing_within(&paths, owner, &mut budget, Duration::from_secs(10))
        .await
        .expect("a published successor ends the wait");
    server.abort();
    stop_fixture_owner(successor);
}

/// A live owner that neither retires nor answers again fails closed with the
/// original attach error once the shared budget is spent — and the wait never
/// signals it.
#[tokio::test(flavor = "current_thread")]
async fn departing_owner_wait_fails_closed_when_the_owner_stays_alive() {
    let env = crate::test_env::TestEnvGuard::isolated_cockpit_home_async().await;
    let paths = isolated_canonical_paths(&env).await;
    let mut owner_child = publish_verified_test_owner(&paths);
    let owner = DiscoveredOwner::capture(&paths);
    let mut budget = DepartingOwnerBudget {
        deadline: Some(tokio::time::Instant::now() + Duration::from_millis(300)),
        ..DepartingOwnerBudget::default()
    };
    let error = await_departing_within(&paths, owner, &mut budget, Duration::from_secs(5))
        .await
        .expect_err("a live, silent owner is not departing");
    assert_eq!(error.to_string(), "attach closed");
    assert!(
        owner_child
            .try_wait()
            .expect("poll fixture owner")
            .is_none(),
        "the wait never signals the owner"
    );
    stop_fixture_owner(owner_child);
}

/// A transient close must not be waited out: as soon as the same owner
/// answers a hello again the resolver retries the attach.
#[tokio::test(flavor = "current_thread")]
async fn departing_owner_wait_returns_when_the_same_owner_answers_again() {
    let env = crate::test_env::TestEnvGuard::isolated_cockpit_home_async().await;
    let paths = isolated_canonical_paths(&env).await;
    let mut owner_child = publish_verified_test_owner(&paths);
    let listener = UnixListener::bind(&paths.socket).expect("bind fixture owner socket");
    let owner = DiscoveredOwner::capture(&paths);
    let server = serve_hellos(listener, "0.1.answers-again");
    let mut budget = DepartingOwnerBudget::default();
    await_departing_within(&paths, owner, &mut budget, Duration::from_secs(5))
        .await
        .expect("the resolver retries the attach");
    assert!(
        owner_child
            .try_wait()
            .expect("poll fixture owner")
            .is_none(),
        "the owner is still the same live process"
    );
    server.abort();
    stop_fixture_owner(owner_child);
}

/// An owner whose identity cannot be verified (no pinned handle — e.g. its
/// executable was replaced in place) still gets the transient-close retry:
/// the wait re-probes instead of failing at once.
#[tokio::test(flavor = "current_thread")]
async fn departing_owner_wait_reprobes_an_owner_without_a_pinned_handle() {
    let env = crate::test_env::TestEnvGuard::isolated_cockpit_home_async().await;
    let paths = isolated_canonical_paths(&env).await;
    // `/bin/sleep` is not daemon-shaped, so no verified handle is pinned.
    let owner_child = publish_test_ephemeral_owner(&paths);
    let listener = UnixListener::bind(&paths.socket).expect("bind fixture owner socket");
    let owner = DiscoveredOwner::capture(&paths);
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
    assert!(owner.process.is_none(), "the identity is not verified");
    let server = serve_hellos(listener, "0.1.unverified");
    let mut budget = DepartingOwnerBudget::default();
    await_departing_within(&paths, owner, &mut budget, Duration::from_secs(5))
        .await
        .expect("an unverified owner that answers again is retried");
    server.abort();
    stop_fixture_owner(owner_child);
}

#[tokio::test]
async fn negotiated_client_round_trips_attach() {
    let (_dir, socket, listener) = bind_test_socket();
    let session_id = Uuid::new_v4();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut daemon = ProtoStream::new(stream);
        send_daemon_hello(&mut daemon, "0.1.handshake", proto::PROTOCOL_VERSION).await;
        complete_wire_connect_handshake(&mut daemon).await;
        let request_id = match daemon.recv().await.unwrap().unwrap() {
            proto::RecvFrame::Envelope(env) => match env.body {
                Body::Request { id, request, .. } => {
                    assert!(
                        matches!(request, Request::Attach { .. }),
                        "expected attach request, got {request:?}"
                    );
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
        .request(attach_request(Some(session_id)))
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
async fn one_shot_daemon_uses_the_ephemeral_socket_owner_and_reaps_metadata() {
    let env = crate::test_env::TestEnvGuard::isolated_cockpit_home_async().await;
    let runtime = env.path().expect("isolated runtime root").join("runtime");
    env.set_var("XDG_RUNTIME_DIR", &runtime);

    let response = super::run_one_shot_daemon(|client| {
        Box::pin(async move { client.request_ok(Request::DaemonStatus).await })
    })
    .await
    .expect("one-shot daemon status");
    assert!(matches!(response, Response::LockedBootstrapHello(_)));

    let paths = crate::daemon::DaemonPaths::resolve_canonical().expect("canonical paths");
    // The owner holds the last-client handoff grace before draining, then
    // must retire within the original bound.
    tokio::time::timeout(
        crate::daemon::server::LAST_CLIENT_HANDOFF_GRACE + std::time::Duration::from_secs(2),
        async {
            while paths.socket.exists() || paths.pid_file.exists() {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        },
    )
    .await
    .expect("ephemeral socket owner must reap after its last one-shot client disconnects");
    assert!(
        !paths.pid_file.exists(),
        "ephemeral socket owner must retire its pid record"
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
async fn accepted_assistant_promotion_keeps_the_live_owner_in_place() {
    let env = crate::test_env::TestEnvGuard::isolated_cockpit_home_async().await;
    let runtime = env.path().expect("isolated runtime root").join("runtime");
    env.set_var("XDG_RUNTIME_DIR", &runtime);

    let paths = canonical_ephemeral_paths();
    let mut owner_child = publish_test_ephemeral_owner(&paths);
    let listener = UnixListener::bind(&paths.socket).expect("bind ephemeral promotion socket");
    let socket = paths.socket.clone();
    let owner_pid = owner_child.id();
    let predecessor_paths = paths.clone();
    let predecessor = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept promotion client");
        let mut daemon = ProtoStream::new(stream);
        send_daemon_hello(&mut daemon, "0.1.ephemeral", proto::PROTOCOL_VERSION).await;
        complete_wire_connect_handshake(&mut daemon).await;
        accept_in_place_promotion(&mut daemon, &listener, &predecessor_paths).await;
        drop(daemon);
        drop(listener);
        owner_child.kill().expect("stop fixture owner child");
        owner_child.wait().expect("reap fixture owner child");
        std::fs::remove_file(predecessor_paths.pid_file)
            .expect("release fixture predecessor receipt");
        std::fs::remove_file(&socket).expect("release fixture socket");
    });

    let promoted = promote_ephemeral_owner(&paths, None)
        .await
        .expect("accepted promotion must keep the live owner");

    assert!(promoted.promoted_from_ephemeral);
    assert!(!promoted.owns_daemon);
    assert_eq!(promoted.socket, paths.socket);
    assert!(!promoted.ephemeral_owner);
    let receipt = match cockpit_host::daemon_lifecycle::read_daemon_pid_record(&paths.pid_file) {
        Some(receipt) => receipt,
        other => panic!("in-place promotion must keep the same pid receipt, got {other:?}"),
    };
    assert_eq!(receipt.pid, owner_pid);
    promoted
        .client
        .request_ok(Request::DaemonStatus)
        .await
        .expect("promoted owner answers DaemonStatus on the same socket");
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
        complete_wire_connect_handshake(&mut daemon).await;
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
                                process_watch: None,
                                lifetime_client: None,
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
