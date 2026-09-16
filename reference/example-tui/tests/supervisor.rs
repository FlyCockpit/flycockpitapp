//! End-to-end tests for the supervised design (`excoc supervise` / `worker` /
//! `up` / `upgrade`): a stable wrapper owns the socket while the worker rolls
//! forward on upgrade and is respawned on crash, all with a continuous clock.

use std::io::{BufRead, BufReader};
use std::path::PathBuf;
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
            "excoc-sup-test-{}-{}",
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

    fn sup_pid_file(&self) -> PathBuf {
        self.dir.join("excoc.sup.pid")
    }

    fn log(&self) -> String {
        std::fs::read_to_string(self.dir.join("excoc.log")).unwrap_or_default()
    }
}

impl Drop for TestHome {
    fn drop(&mut self) {
        // Stopping the supervisor (SIGTERM) drains its worker and clears
        // metadata; the worker also self-exits when the supervisor is gone.
        if let Some(pid) = read_pid(&self.sup_pid_file())
            && excoc::host::process_exists(pid)
        {
            excoc::host::terminate(pid);
        }
        std::thread::sleep(Duration::from_millis(200));
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// A long-lived `excoc up` process whose stdout lines are streamed to a channel.
struct UpProcess {
    child: Child,
    stdout: Receiver<String>,
    stderr: Receiver<String>,
}

impl UpProcess {
    fn spawn(home: &TestHome) -> Self {
        let mut child = home.command(&["up"]).spawn().expect("spawn excoc up");
        let stdout = take_lines(child.stdout.take().expect("up stdout"));
        let stderr = take_lines(child.stderr.take().expect("up stderr"));
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
                    "timed out waiting for up output\nstderr: {}",
                    err.join("\n")
                );
            }
        }
    }

    /// Next `connected pid=.. worker_v=.. gen=.. opened_at_ms=..` line.
    fn wait_connected(&self) -> Connected {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            assert!(
                !remaining.is_zero(),
                "timed out waiting for a connected line"
            );
            let line = self.wait_line(remaining);
            if let Some(parsed) = parse_connected(&line) {
                return parsed;
            }
        }
    }

    /// Next connected line whose pid differs from `old_pid` (i.e. after a swap).
    fn wait_reconnect(&self, old_pid: u32) -> Connected {
        let deadline = Instant::now() + Duration::from_secs(8);
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            assert!(!remaining.is_zero(), "timed out waiting for a reconnect");
            let line = self.wait_line(remaining);
            if let Some(parsed) = parse_connected(&line)
                && parsed.pid != old_pid
            {
                return parsed;
            }
        }
    }
}

impl Drop for UpProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Connected {
    pid: u32,
    worker_version: u32,
    generation: u32,
    opened_at_ms: u64,
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

fn parse_connected(line: &str) -> Option<Connected> {
    let rest = line.strip_prefix("connected pid=")?;
    let mut parts = rest.split_whitespace();
    let pid = parts.next()?.parse().ok()?;
    let worker_version = parts.next()?.strip_prefix("worker_v=")?.parse().ok()?;
    let generation = parts.next()?.strip_prefix("gen=")?.parse().ok()?;
    let opened_at_ms = parts.next()?.strip_prefix("opened_at_ms=")?.parse().ok()?;
    Some(Connected {
        pid,
        worker_version,
        generation,
        opened_at_ms,
    })
}

fn read_pid(path: &std::path::Path) -> Option<u32> {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|contents| contents.trim().parse().ok())
}

fn sup_status(home: &TestHome) -> String {
    let output = home.command(&["sup-status"]).output().expect("sup-status");
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

fn status_worker_pid(home: &TestHome) -> Option<u32> {
    let status = sup_status(home);
    let token = status
        .split_whitespace()
        .find_map(|t| t.strip_prefix("worker_pid="))?;
    token.parse().ok()
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

#[test]
fn up_starts_the_supervisor_and_counts() {
    let home = TestHome::new();
    assert_eq!(sup_status(&home), "not running");

    let up = UpProcess::spawn(&home);
    let connected = up.wait_connected();
    assert_eq!(connected.worker_version, 1, "first worker is v1");
    assert_eq!(connected.generation, 1, "first worker is generation 1");

    assert!(
        wait_until(Duration::from_secs(3), || status_worker_pid(&home)
            == Some(connected.pid)),
        "sup-status should report the live worker; log:\n{}",
        home.log()
    );
}

#[test]
fn upgrade_rolls_the_worker_without_losing_uptime() {
    let home = TestHome::new();
    let up = UpProcess::spawn(&home);
    let first = up.wait_connected();
    assert_eq!(first.worker_version, 1);

    let output = home.command(&["upgrade"]).output().expect("excoc upgrade");
    assert!(
        output.status.success(),
        "upgrade failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let upgrade_line = String::from_utf8_lossy(&output.stdout);
    assert!(
        upgrade_line.contains("worker v1->v2"),
        "unexpected upgrade output: {upgrade_line:?}"
    );

    // The attached client lands on the successor: a new pid, the next version
    // and generation, and — crucially — the same open time (continuous uptime).
    let next = up.wait_reconnect(first.pid);
    assert_eq!(next.worker_version, 2, "worker rolled to v2");
    assert_eq!(next.generation, 2, "generation advanced");
    assert_eq!(
        next.opened_at_ms, first.opened_at_ms,
        "the open clock must survive the upgrade"
    );

    assert!(
        wait_until(Duration::from_secs(3), || status_worker_pid(&home)
            == Some(next.pid)),
        "sup-status should report the rolled worker; log:\n{}",
        home.log()
    );
    assert!(
        wait_until(Duration::from_secs(3), || !excoc::host::process_exists(
            first.pid
        )),
        "the old worker must exit after draining; log:\n{}",
        home.log()
    );
}

#[test]
fn worker_crash_is_recovered_without_losing_uptime() {
    let home = TestHome::new();
    let up = UpProcess::spawn(&home);
    let first = up.wait_connected();

    // Simulate a hard crash of the worker; the supervisor should respawn it
    // independent of any client action.
    let killed = Command::new("kill")
        .args(["-9", &first.pid.to_string()])
        .status()
        .expect("kill -9 worker");
    assert!(killed.success(), "failed to SIGKILL the worker");

    let recovered = up.wait_reconnect(first.pid);
    assert_ne!(
        recovered.pid, first.pid,
        "a new worker process must take over"
    );
    assert!(
        recovered.generation > first.generation,
        "the respawn must advance the generation ({} -> {})",
        first.generation,
        recovered.generation
    );
    assert_eq!(
        recovered.worker_version, first.worker_version,
        "a crash respawn keeps the same worker version"
    );
    assert_eq!(
        recovered.opened_at_ms, first.opened_at_ms,
        "the open clock must survive the crash (supervisor owns it)"
    );

    assert!(
        wait_until(Duration::from_secs(3), || status_worker_pid(&home)
            == Some(recovered.pid)),
        "sup-status should report the respawned worker; log:\n{}",
        home.log()
    );
}

#[test]
fn upgrade_without_a_supervisor_reports_not_running() {
    let home = TestHome::new();
    let output = home.command(&["upgrade"]).output().expect("excoc upgrade");
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "not running"
    );
    assert!(!home.sup_pid_file().exists());
}

#[test]
fn sup_status_without_a_supervisor_reports_not_running() {
    let home = TestHome::new();
    assert_eq!(sup_status(&home), "not running");
    assert!(!home.sup_pid_file().exists());
}
