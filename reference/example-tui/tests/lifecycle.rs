//! End-to-end lifecycle: first instance starts the daemon, later instances
//! attach to the same clock, and the last disconnect tears the daemon down.

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, Instant};

static TEST_SEQ: AtomicU64 = AtomicU64::new(0);

struct TestHome {
    dir: PathBuf,
}

impl TestHome {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "excoc-test-{}-{}",
            std::process::id(),
            TEST_SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).expect("temp home");
        Self { dir }
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_excoc"));
        command
            .args(args)
            .env("EXCOC_HOME", &self.dir)
            .env("EXCOC_TICK_MS", "50")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command
    }

    fn pid_file(&self) -> PathBuf {
        self.dir.join("excoc.pid")
    }

    fn log(&self) -> String {
        std::fs::read_to_string(self.dir.join("excoc.log")).unwrap_or_default()
    }
}

impl Drop for TestHome {
    fn drop(&mut self) {
        if let Some(pid) = pid_file_pid(&self.pid_file())
            && excoc::host::process_exists(pid)
        {
            excoc::host::terminate(pid);
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

struct ClientProcess {
    child: Child,
    stdout: Receiver<String>,
    stderr: Receiver<String>,
}

impl ClientProcess {
    fn spawn(home: &TestHome) -> Self {
        let mut child = home.command(&[]).spawn().expect("spawn excoc client");
        let stdout = take_lines(child.stdout.take().expect("client stdout"));
        let stderr = take_lines(child.stderr.take().expect("client stderr"));
        Self {
            child,
            stdout,
            stderr,
        }
    }

    fn wait_line(&self, timeout: Duration) -> String {
        match self.stdout.recv_timeout(timeout) {
            Ok(line) => line,
            Err(_) => {
                let err: Vec<String> = self.stderr.try_iter().collect();
                panic!(
                    "timed out waiting for client output\nstderr: {}",
                    err.join("\n")
                );
            }
        }
    }

    fn wait_connected(&self) -> u32 {
        self.wait_connected_full().0
    }

    /// Wait for the next `connected pid=P opened_at_ms=M` line, skipping any
    /// uptime lines that precede it (as happens after a reconnect).
    fn wait_connected_full(&self) -> (u32, u64) {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                panic!("timed out waiting for connected line");
            }
            let line = self.wait_line(remaining);
            if let Some(parsed) = parse_connected(&line) {
                return parsed;
            }
        }
    }

    fn wait_uptime(&self) -> (u64, usize) {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                panic!("timed out waiting for uptime line");
            }
            let line = self.wait_line(remaining);
            if let Some(parsed) = parse_uptime(&line) {
                return parsed;
            }
        }
    }
}

impl Drop for ClientProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn take_lines<R>(reader: R) -> Receiver<String>
where
    R: std::io::Read + Send + 'static,
{
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let reader = BufReader::new(reader);
        for line in reader.lines() {
            match line {
                Ok(line) => {
                    if tx.send(line).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });
    rx
}

fn parse_connected(line: &str) -> Option<(u32, u64)> {
    let rest = line.strip_prefix("connected pid=")?;
    let mut parts = rest.split_whitespace();
    let pid = parts.next()?.parse().ok()?;
    let opened_at_ms = parts.next()?.strip_prefix("opened_at_ms=")?.parse().ok()?;
    Some((pid, opened_at_ms))
}

fn parse_reset(output: &str) -> Option<(u32, u32)> {
    let line = output
        .lines()
        .find(|line| line.starts_with("reset: daemon "))?;
    let rest = line.strip_prefix("reset: daemon ")?;
    let mut parts = rest.split_whitespace();
    let old = parts.next()?.parse().ok()?;
    if parts.next()? != "->" {
        return None;
    }
    let new = parts.next()?.parse().ok()?;
    Some((old, new))
}

fn parse_uptime(line: &str) -> Option<(u64, usize)> {
    let mut parts = line.split_whitespace();
    if parts.next()? != "uptime" {
        return None;
    }
    let secs = parts.next()?.trim_end_matches('s').parse().ok()?;
    if parts.next()? != "clients" {
        return None;
    }
    let clients = parts.next()?.parse().ok()?;
    Some((secs, clients))
}

fn wait_clients(client: &ClientProcess, expected: usize) -> (u64, usize) {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        assert!(
            !remaining.is_zero(),
            "timed out waiting for clients={expected}"
        );
        let (secs, clients) = {
            let line = client.wait_line(remaining);
            parse_uptime(&line).unwrap_or_else(|| panic!("expected uptime line, got {line:?}"))
        };
        if clients == expected {
            return (secs, clients);
        }
    }
}

fn wait_until(timeout: Duration, mut pred: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if pred() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn status_output(home: &TestHome) -> String {
    let output = home.command(&["status"]).output().expect("excoc status");
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

fn pid_file_pid(path: &Path) -> Option<u32> {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|contents| contents.trim().parse().ok())
}

#[test]
fn first_instance_starts_daemon_and_counts() {
    let home = TestHome::new();
    assert_eq!(status_output(&home), "not running");

    let client = ClientProcess::spawn(&home);
    let pid = client.wait_connected();
    let (secs, clients) = client.wait_uptime();
    assert_eq!(clients, 1);
    assert!(
        secs <= 2,
        "fresh daemon should count from open time, got {secs}s"
    );
    assert_eq!(pid_file_pid(&home.pid_file()), Some(pid));
    assert!(
        status_output(&home).starts_with(&format!("running  pid={pid}")),
        "status should see the live daemon; log:\n{}",
        home.log()
    );
}

#[test]
fn second_instance_attaches_to_the_same_clock() {
    let home = TestHome::new();
    let first = ClientProcess::spawn(&home);
    let pid = first.wait_connected();
    let _ = first.wait_uptime();
    std::thread::sleep(Duration::from_millis(200));

    let second = ClientProcess::spawn(&home);
    let second_pid = second.wait_connected();
    assert_eq!(second_pid, pid, "second client must attach, not spawn");

    let (first_secs, first_clients) = first.wait_uptime();
    let (second_secs, second_clients) = second.wait_uptime();
    assert!(
        first_clients >= 1 && second_clients >= 1,
        "both clients should see the shared owner"
    );
    assert!(
        (first_secs as i64 - second_secs as i64).abs() <= 1,
        "clients must share the daemon open time (first={first_secs}s second={second_secs}s)"
    );
}

#[test]
fn last_client_disconnect_closes_the_daemon() {
    let home = TestHome::new();
    let first = ClientProcess::spawn(&home);
    let pid = first.wait_connected();
    let _ = first.wait_uptime();

    let second = ClientProcess::spawn(&home);
    assert_eq!(second.wait_connected(), pid);
    let _ = second.wait_uptime();

    drop(first);
    assert!(
        wait_until(Duration::from_secs(2), || {
            pid_file_pid(&home.pid_file()) == Some(pid)
        }),
        "daemon must stay up while a client remains"
    );
    let (secs, clients) = wait_clients(&second, 1);
    assert_eq!(clients, 1, "surviving client should see the drop");
    assert!(secs <= 5, "clock must not reset while the daemon is alive");

    drop(second);
    assert!(
        wait_until(Duration::from_secs(3), || {
            !home.pid_file().exists() && status_output(&home) == "not running"
        }),
        "last disconnect must close the daemon; log:\n{}",
        home.log()
    );

    let third = ClientProcess::spawn(&home);
    let new_pid = third.wait_connected();
    assert_ne!(new_pid, pid, "a new daemon should start after teardown");
    let (secs, clients) = third.wait_uptime();
    assert_eq!(clients, 1);
    assert!(secs <= 2, "new daemon must count from its own open time");
}

#[test]
fn reset_hands_off_to_a_new_daemon_without_losing_uptime() {
    let home = TestHome::new();
    let client = ClientProcess::spawn(&home);
    let (pid, opened_at) = client.wait_connected_full();
    let _ = client.wait_uptime();

    // Trigger the handoff from a separate control connection.
    let output = home.command(&["reset"]).output().expect("excoc reset");
    assert!(
        output.status.success(),
        "reset failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let (reset_old, reset_new) =
        parse_reset(&stdout).unwrap_or_else(|| panic!("unexpected reset output: {stdout:?}"));
    assert_eq!(reset_old, pid, "reset should name the outgoing daemon");
    assert_ne!(reset_new, pid, "the successor must be a different process");

    // The attached client re-attaches onto the successor with the same clock.
    let (new_pid, new_opened_at) = client.wait_connected_full();
    assert_eq!(new_pid, reset_new, "client must reconnect to the successor");
    assert_eq!(
        new_opened_at, opened_at,
        "open time (the uptime origin) must survive the handoff"
    );

    // The successor owns the canonical endpoint and the predecessor is gone.
    assert!(
        wait_until(Duration::from_secs(3), || {
            pid_file_pid(&home.pid_file()) == Some(new_pid)
        }),
        "successor must own the canonical pid file; log:\n{}",
        home.log()
    );
    assert!(
        wait_until(Duration::from_secs(3), || {
            !excoc::host::process_exists(pid)
        }),
        "the predecessor must exit once its clients drain; log:\n{}",
        home.log()
    );
    let _ = client.wait_uptime();
    assert!(
        status_output(&home).starts_with(&format!("running  pid={new_pid}")),
        "status should see the successor; log:\n{}",
        home.log()
    );

    // Last-client teardown still governs the successor.
    drop(client);
    assert!(
        wait_until(Duration::from_secs(3), || {
            !home.pid_file().exists() && status_output(&home) == "not running"
        }),
        "last disconnect must close the successor; log:\n{}",
        home.log()
    );
}

#[test]
fn reset_without_a_running_daemon_reports_not_running() {
    let home = TestHome::new();
    let output = home.command(&["reset"]).output().expect("excoc reset");
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "not running"
    );
    assert!(!home.pid_file().exists());
}

#[test]
fn status_does_not_keep_an_idle_daemon_alive() {
    let home = TestHome::new();
    assert_eq!(status_output(&home), "not running");
    assert!(!home.pid_file().exists());
}

#[test]
fn onboard_refuses_a_non_tty() {
    let output = Command::new(env!("CARGO_BIN_EXE_excoc"))
        .arg("onboard")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("excoc onboard");
    assert!(!output.status.success());
    let err = String::from_utf8_lossy(&output.stderr);
    assert!(
        err.contains("needs a terminal"),
        "expected a TTY error, got {err}"
    );
}

#[test]
fn onboard_skip_still_needs_a_terminal() {
    let output = Command::new(env!("CARGO_BIN_EXE_excoc"))
        .args(["onboard", "--skip"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("excoc onboard --skip");
    assert!(!output.status.success());
    let err = String::from_utf8_lossy(&output.stderr);
    assert!(
        err.contains("needs a terminal"),
        "expected a TTY error, got {err}"
    );
}

#[test]
fn onboard_rejects_unknown_flags_from_the_binary() {
    let output = Command::new(env!("CARGO_BIN_EXE_excoc"))
        .args(["onboard", "--fast"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("excoc onboard --fast");
    assert!(!output.status.success());
    let err = String::from_utf8_lossy(&output.stderr);
    assert!(
        err.contains("unknown onboard option"),
        "expected an unknown-option error, got {err}"
    );
}
