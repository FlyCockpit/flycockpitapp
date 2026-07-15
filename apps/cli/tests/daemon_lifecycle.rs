#![cfg(unix)]

mod support;

use std::time::Duration;

use support::{SpawnedDaemon, output_text, wait_until};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn spawned_daemon_start_status_stop_round_trip() {
    let daemon = SpawnedDaemon::start().await;

    let output = daemon
        .command()
        .args(["daemon", "status"])
        .output()
        .expect("daemon status command");
    assert!(output.status.success(), "{}", output_text(&output));
    assert!(output_text(&output).contains("daemon: running"));
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

    let response = client
        .set_caffeinate(true)
        .await
        .expect("set caffeinate response");

    let event = client
        .next_caffeinate_state(Duration::from_secs(5))
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

    let output = daemon
        .command()
        .args(["daemon", "restart", "--grace", "0"])
        .output()
        .expect("daemon restart command");
    assert!(output.status.success(), "{}", output_text(&output));
    assert!(output_text(&output).contains("daemon: restarted"));

    wait_until("replacement daemon pid", Duration::from_secs(5), || async {
        daemon.try_pid().is_some_and(|pid| pid != old_pid)
    })
    .await;
    daemon.wait_for_handshake().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restart_when_not_running_starts_daemon() {
    let daemon = SpawnedDaemon::start().await;
    let stop = daemon
        .command()
        .args(["daemon", "stop", "--grace", "0"])
        .output()
        .expect("daemon stop command");
    assert!(stop.status.success(), "{}", output_text(&stop));
    wait_until("daemon pid cleanup", Duration::from_secs(5), || async {
        daemon.try_pid().is_none()
    })
    .await;

    let output = daemon
        .command()
        .args(["daemon", "restart", "--grace", "0"])
        .output()
        .expect("daemon restart command");
    assert!(output.status.success(), "{}", output_text(&output));
    assert!(
        output_text(&output).contains("daemon: was not running; started"),
        "{}",
        output_text(&output)
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
