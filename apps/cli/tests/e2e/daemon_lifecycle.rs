use crate::support::{IsolatedHome, SpawnedDaemon, assert_success, output_text};

struct DetachedDaemonCleanup<'a>(&'a IsolatedHome);

impl Drop for DetachedDaemonCleanup<'_> {
    fn drop(&mut self) {
        let _ = self
            .0
            .cockpit()
            .args(["daemon", "stop", "--grace", "0"])
            .output();
        if let Some(pid) = cockpit_host::daemon_lifecycle::read_pid_file(&self.0.pid_file())
            && cockpit_host::daemon_lifecycle::process_exists(pid)
        {
            // SAFETY: this best-effort test cleanup targets only the isolated
            // daemon PID published under this test's private home.
            let _ = unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
        }
    }
}

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
async fn restart_running_daemon_rolls_worker_and_keeps_socket_usable() {
    let daemon = SpawnedDaemon::start().await;
    let old_supervisor_pid = daemon.pid();

    let output = daemon.restart_via_command(0).await;
    assert!(output.status.success(), "{}", output_text(&output));
    assert!(output_text(&output).contains("daemon: rolled worker"));

    assert_eq!(
        daemon.pid(),
        old_supervisor_pid,
        "restart must retain the stable supervisor"
    );
    daemon.status().await;
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ready_pipe_failure_after_canonicalized_upgrade_keeps_predecessor_serving() {
    let daemon = SpawnedDaemon::start().await;
    let status_before = daemon
        .command()
        .args(["daemon", "status", "--json"])
        .output()
        .expect("status before failed upgrade");
    assert_success(
        "status before failed upgrade",
        &status_before,
        daemon.home(),
    );
    let before: serde_json::Value =
        serde_json::from_slice(&status_before.stdout).expect("decode status before upgrade");
    let non_worker_binary = std::fs::canonicalize("/bin/sleep")
        .expect("canonicalize a real non-worker binary before upgrade spawn");

    let upgrade = daemon
        .command()
        .args(["daemon", "upgrade", "--binary"])
        .arg(&non_worker_binary)
        .output()
        .expect("upgrade with ready-pipe-failing binary");

    assert!(
        !upgrade.status.success(),
        "a successor that never writes fd 4 must abort upgrade"
    );
    let status_after = daemon
        .command()
        .args(["daemon", "status", "--json"])
        .output()
        .expect("status after failed upgrade");
    assert_success("status after failed upgrade", &status_after, daemon.home());
    let after: serde_json::Value =
        serde_json::from_slice(&status_after.stdout).expect("decode status after upgrade");
    assert_eq!(after["worker_pid"], before["worker_pid"]);
    assert_eq!(after["generation"], before["generation"]);
    assert!(
        after["last_handover"]
            .as_str()
            .is_some_and(|outcome| outcome.starts_with("aborted: staging successor readiness")),
        "status must retain the post-canonicalization readiness abort reason: {after}"
    );
    let text_status = daemon
        .command()
        .args(["daemon", "status"])
        .output()
        .expect("text status after failed upgrade");
    assert_success(
        "text status after failed upgrade",
        &text_status,
        daemon.home(),
    );
    assert!(
        output_text(&text_status).contains("last handover: aborted: staging successor readiness"),
        "text status must retain the abort outcome: {}",
        output_text(&text_status)
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
    assert_eq!(output_text(&output).trim(), "daemon: stopped");
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
async fn sigkill_then_client_reclaims_detached_daemon_without_manual_restart() {
    let home = IsolatedHome::new();
    let _cleanup = DetachedDaemonCleanup(&home);
    home.trust_project();

    let first = home
        .cockpit()
        .arg("stats")
        .output()
        .expect("cold stats client");
    assert_success("cold stats client", &first, &home);
    let old_pid = cockpit_host::daemon_lifecycle::read_pid_file(&home.pid_file())
        .expect("cold client published detached daemon pid");
    let rendezvous = home.pid_file().with_file_name("daemon.json");
    assert!(home.socket_path().exists(), "cold daemon socket must exist");
    assert!(rendezvous.exists(), "cold daemon rendezvous must exist");

    // SAFETY: old_pid came from this test's isolated, hello-capable daemon.
    let killed = unsafe { libc::kill(old_pid as libc::pid_t, libc::SIGKILL) };
    assert_eq!(
        killed,
        0,
        "SIGKILL detached daemon {old_pid}: {}",
        std::io::Error::last_os_error()
    );
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while cockpit_host::daemon_lifecycle::process_exists(old_pid) {
        assert!(
            std::time::Instant::now() < deadline,
            "detached daemon {old_pid} remained live after SIGKILL"
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }

    assert!(home.pid_file().exists(), "SIGKILL must leave the pid file");
    assert!(home.socket_path().exists(), "SIGKILL must leave the socket");
    assert!(rendezvous.exists(), "SIGKILL must leave the rendezvous");

    let reclaimed = home
        .cockpit()
        .arg("stats")
        .output()
        .expect("client after SIGKILL");
    assert_success("client after SIGKILL", &reclaimed, &home);
    let new_pid = cockpit_host::daemon_lifecycle::read_pid_file(&home.pid_file())
        .expect("replacement daemon pid");
    assert_ne!(new_pid, old_pid, "client must publish a new generation");
    let replacement_status = home
        .cockpit()
        .args(["daemon", "status", "--json"])
        .output()
        .expect("replacement daemon status");
    assert_success("replacement daemon status", &replacement_status, &home);
    let status: serde_json::Value =
        serde_json::from_slice(&replacement_status.stdout).expect("replacement status JSON");
    assert_eq!(status["pid"].as_u64(), Some(u64::from(new_pid)));
    assert_eq!(
        status["socket_path"].as_str(),
        Some(home.socket_path().to_string_lossy().as_ref())
    );

    let stopped = home
        .cockpit()
        .args(["daemon", "stop", "--grace", "0"])
        .output()
        .expect("stop reclaimed daemon");
    assert_success("stop reclaimed daemon", &stopped, &home);
}
