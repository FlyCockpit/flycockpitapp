use crate::support::{SpawnedDaemon, output_text};

#[cfg(unix)]
#[test]
fn cold_clients_started_within_ten_ms_share_one_daemon() {
    use crate::support::{
        HermeticCockpit, HermeticLaunchKind, HermeticProfile, INITIAL_PTY_COLS, INITIAL_PTY_ROWS,
    };
    use portable_pty::{PtySize, native_pty_system};
    use std::io::Read as _;

    let mut session = HermeticCockpit::prepare(HermeticProfile::Default);
    let trust = session
        .spec()
        .launch_path(HermeticLaunchKind::TrustSet)
        .std_command()
        .output()
        .expect("pre-trust race project");
    assert!(trust.status.success(), "{}", output_text(&trust));
    let mut launch = session.spec().launch_path(HermeticLaunchKind::PtyChild);
    launch.args = vec!["stats".to_string()];
    let spawn_client = || {
        let pair = native_pty_system()
            .openpty(PtySize {
                rows: INITIAL_PTY_ROWS,
                cols: INITIAL_PTY_COLS,
                pixel_width: 0,
                pixel_height: 0,
            })
            .expect("open client PTY");
        let child = pair
            .slave
            .spawn_command(launch.pty_command())
            .expect("spawn PTY client");
        drop(pair.slave);
        let reader = pair.master.try_clone_reader().expect("clone PTY reader");
        (child, pair.master, reader)
    };

    let (mut first, first_pty, mut first_output) = spawn_client();
    std::thread::sleep(std::time::Duration::from_millis(5));
    let (mut second, second_pty, mut second_output) = spawn_client();
    let first_status = first.wait().expect("wait first PTY client");
    let second_status = second.wait().expect("wait second PTY client");
    drop(first_pty);
    drop(second_pty);
    let mut first_text = String::new();
    first_output
        .read_to_string(&mut first_text)
        .expect("read first PTY output");
    let mut second_text = String::new();
    second_output
        .read_to_string(&mut second_text)
        .expect("read second PTY output");
    assert!(
        first_status.success(),
        "first racing PTY client failed: {first_text}"
    );
    assert!(
        second_status.success(),
        "second racing PTY client failed: {second_text}"
    );

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
    let status = loop {
        let mut command = session
            .spec()
            .launch_path(HermeticLaunchKind::DaemonStatus)
            .std_command();
        let output = command.arg("--json").output().expect("daemon status");
        if output.status.success() {
            break output;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "racing PTY clients did not publish a daemon: {}",
            output_text(&output)
        );
        std::thread::sleep(std::time::Duration::from_millis(20));
    };
    assert!(status.status.success(), "{}", output_text(&status));
    let value: serde_json::Value = serde_json::from_slice(&status.stdout).expect("status JSON");
    let published_pid = value["pid"].as_u64().expect("published daemon pid");
    assert!(published_pid > 0);

    session.stop_child_spawned_daemon();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn spawned_daemon_start_status_stop_round_trip() {
    let daemon = SpawnedDaemon::start().await;
    let isolated_root = daemon.home().home_dir().to_path_buf();

    let output = daemon
        .command()
        .args(["daemon", "status"])
        .output()
        .expect("daemon status command");
    assert!(output.status.success(), "{}", output_text(&output));
    assert!(output_text(&output).contains("daemon: running"));

    drop(daemon);
    assert!(
        !isolated_root.exists(),
        "exact child reap must finish before isolated-home removal: {}",
        isolated_root.display()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn typed_client_sends_request_and_receives_event() {
    let daemon = SpawnedDaemon::start().await;
    let client = daemon.client().await;

    let status = client.status().await.expect("daemon status response");
    assert_eq!(
        status.socket_path,
        daemon.socket_path().display().to_string()
    );
    assert!(status.protocol_version > 0);

    // Every newly connected client receives the daemon's current global
    // caffeination snapshot before any request-driven broadcasts. Consume
    // that initial state so the assertion below observes this request's
    // transition rather than the connection snapshot.
    let initial = client
        .next_caffeinate_state_unbounded()
        .await
        .expect("initial caffeinate state");
    assert!(!initial.active);

    let response = client
        .set_caffeinate(true)
        .await
        .expect("set caffeinate response");

    let event = client
        .next_caffeinate_state_unbounded()
        .await
        .expect("caffeinate event");
    assert_eq!(event.active, response.active);
    assert_eq!(event.lid_close_guaranteed, response.lid_close_guaranteed);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn spawned_daemons_are_parallel_safe() {
    let (first, second) = tokio::join!(SpawnedDaemon::start(), SpawnedDaemon::start());

    assert_ne!(first.socket_path(), second.socket_path());
    assert_ne!(first.pid(), second.pid());
    assert_eq!(
        first.status().await.socket_path,
        first.socket_path().display().to_string()
    );
    assert_eq!(
        second.status().await.socket_path,
        second.socket_path().display().to_string()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restart_running_daemon_replaces_pid_and_keeps_socket_usable() {
    let daemon = SpawnedDaemon::start().await;
    let old_pid = daemon.pid();

    let output = daemon.restart_via_command(0).await;
    assert!(output.status.success(), "{}", output_text(&output));
    assert!(output_text(&output).contains("daemon: restarted"));

    assert_ne!(
        daemon.pid(),
        old_pid,
        "restart must publish a new generation"
    );
    daemon.status().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restart_when_not_running_starts_daemon() {
    let daemon = SpawnedDaemon::start().await;
    let stop = daemon.stop_via_command(0);
    assert!(stop.status.success(), "{}", output_text(&stop));
    assert!(
        daemon.try_pid().is_none(),
        "stop success must retire pid metadata"
    );

    let output = daemon.restart_via_command(0).await;
    assert!(output.status.success(), "{}", output_text(&output));
    assert!(
        output_text(&output).contains("daemon: was not running; started"),
        "{}",
        output_text(&output)
    );

    daemon.wait_for_handshake().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stop_with_unreachable_socket_waits_for_exact_daemon_retirement() {
    let daemon = SpawnedDaemon::start().await;
    let output = daemon.stop_via_unreachable_socket();

    assert!(output.status.success(), "{}", output_text(&output));
    assert!(
        output_text(&output).contains("socket unreachable; used SIGTERM"),
        "{}",
        output_text(&output)
    );
    assert!(
        daemon.try_pid().is_none(),
        "stop success must retire pid metadata"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restart_with_unreachable_socket_retires_then_replaces_exact_daemon() {
    let daemon = SpawnedDaemon::start().await;
    let old_pid = daemon.pid();

    let output = daemon.restart_via_unreachable_socket().await;
    assert!(output.status.success(), "{}", output_text(&output));
    assert!(output_text(&output).contains("daemon: restarted"));
    assert_ne!(
        daemon.pid(),
        old_pid,
        "restart must publish a new generation"
    );
    daemon.wait_for_handshake().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sigterm_operation_allows_restart_against_same_home() {
    let daemon = SpawnedDaemon::start().await;
    let old_pid = daemon.pid();

    daemon.sigterm().await;
    daemon.restart_same_home().await;

    let status = daemon.status().await;
    assert_ne!(status.pid, old_pid);
    assert_eq!(
        status.socket_path,
        daemon.socket_path().display().to_string()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sigkill_operation_allows_restart_against_same_home() {
    let daemon = SpawnedDaemon::start().await;
    let old_pid = daemon.pid();

    daemon.sigkill().await;
    daemon.restart_same_home().await;

    let status = daemon.status().await;
    assert_ne!(status.pid, old_pid);
    assert_eq!(
        status.socket_path,
        daemon.socket_path().display().to_string()
    );
}
