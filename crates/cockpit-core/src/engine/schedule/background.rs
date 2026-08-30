//! Background shell jobs (GOALS §22).
//!
//! A background job spawns a shell subprocess that runs to completion
//! without blocking the human. Its stdout+stderr stream line-by-line into
//! a bounded ring buffer so `background.tail` can show recent progress;
//! on exit, a budget-capped result injects into main context at the next
//! turn boundary via [`ScheduleEvent::Completed`].
//!
//! Output crossing to the model is budget-capped via
//! [`crate::intel::budget::BudgetedWriter`] (§10) — a `cargo build` can
//! dump megabytes; the model only ever sees the §22 token cap.

use std::collections::{HashMap, VecDeque};
use std::panic::AssertUnwindSafe;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::FutureExt;

use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::mpsc;

use crate::engine::agent::TurnEvent;
use crate::engine::schedule::authority::ScheduleEvent;
use crate::engine::schedule::spec::ScheduleKind;
use crate::intel::budget::BudgetedWriter;
use crate::redact::RedactionTable;
use crate::tools::shell_sandbox::{SandboxAvailability, SandboxGate};

use super::{
    ASYNC_RESULT_TOKEN_CAP, BACKGROUND_LINE_BYTE_CAP, BACKGROUND_RING_BYTE_CAP, TAIL_TOKEN_CAP,
};

/// Handle the authority keeps for a live background job. Lets it read the
/// tail ring and kill the process. `kill` is best-effort and idempotent.
pub struct BackgroundHandle {
    label: String,
    ring: Arc<Mutex<BoundedOutputRing>>,
    /// Set when the job is asked to die; the spawned task observes it.
    kill_tx: tokio::sync::watch::Sender<bool>,
}

#[derive(Debug, Clone)]
pub struct BackgroundLaunch {
    pub confine: bool,
    pub tmp_dir: Option<PathBuf>,
    pub workspace_scratch_dir: Option<PathBuf>,
    pub session_env: HashMap<String, String>,
    #[cfg(test)]
    test_sandbox_build: Option<TestSandboxBuild>,
}

impl BackgroundLaunch {
    pub fn unconfined(session_env: HashMap<String, String>) -> Self {
        Self {
            confine: false,
            tmp_dir: None,
            workspace_scratch_dir: None,
            session_env,
            #[cfg(test)]
            test_sandbox_build: None,
        }
    }

    pub fn confined(tmp_dir: Option<PathBuf>, session_env: HashMap<String, String>) -> Self {
        Self::confined_with_workspace_scratch(tmp_dir, None, session_env)
    }

    pub fn confined_with_workspace_scratch(
        tmp_dir: Option<PathBuf>,
        workspace_scratch_dir: Option<PathBuf>,
        session_env: HashMap<String, String>,
    ) -> Self {
        Self {
            confine: true,
            tmp_dir,
            workspace_scratch_dir,
            session_env,
            #[cfg(test)]
            test_sandbox_build: None,
        }
    }

    #[cfg(test)]
    fn with_test_sandbox_build(mut self, test_sandbox_build: TestSandboxBuild) -> Self {
        self.test_sandbox_build = Some(test_sandbox_build);
        self
    }
}

#[cfg(test)]
#[derive(Debug, Clone)]
enum TestSandboxBuild {
    ShellSuccess {
        calls: Arc<std::sync::atomic::AtomicUsize>,
    },
    Error(String),
}

pub fn background_launch_gate(sandbox_on: bool, availability: &SandboxAvailability) -> SandboxGate {
    crate::tools::shell_sandbox::gate_decision(sandbox_on, availability)
}

impl BackgroundHandle {
    /// Budget-capped tail of the last `lines` output lines, scrubbed for
    /// secrets. Returns an empty string when no output has been produced.
    pub fn tail(&self, lines: usize, _redact: &RedactionTable) -> String {
        let snapshot: Vec<String> = {
            let ring = self.ring.lock().unwrap();
            ring.snapshot_tail(lines)
        };
        let mut writer = BudgetedWriter::new(TAIL_TOKEN_CAP);
        // Tail: keep the most recent lines, so write from the end forward
        // and reverse — but BudgetedWriter is forward-only, so we just
        // write oldest→newest of the requested window and accept that an
        // over-cap window drops its *oldest* lines (the head of the
        // window), keeping the freshest output.
        let start = snapshot
            .len()
            .saturating_sub(window_that_fits(&snapshot, TAIL_TOKEN_CAP));
        for line in &snapshot[start..] {
            if !writer.writeln(line) {
                break;
            }
        }
        let body = writer.into_string();
        if body.is_empty() {
            format!("`{}` has produced no output yet", self.label)
        } else {
            body
        }
    }

    /// Signal the spawned task to kill the child. Idempotent.
    pub fn kill(&self) {
        let _ = self.kill_tx.send(true);
    }
}

/// Compute how many trailing lines of `lines` fit under `cap` tokens, so
/// `tail` keeps the freshest output rather than the oldest.
fn window_that_fits(lines: &[String], cap: usize) -> usize {
    let mut probe = BudgetedWriter::new(cap);
    let mut count = 0;
    for line in lines.iter().rev() {
        if probe.writeln(line) {
            count += 1;
        } else {
            break;
        }
    }
    count
}

#[derive(Debug)]
struct BoundedOutputRing {
    lines: VecDeque<String>,
    bytes: usize,
    dropped_lines: usize,
    dropped_bytes: usize,
    max_bytes: usize,
}

impl BoundedOutputRing {
    fn new(max_bytes: usize) -> Self {
        Self {
            lines: VecDeque::new(),
            bytes: 0,
            dropped_lines: 0,
            dropped_bytes: 0,
            max_bytes: max_bytes.max(1),
        }
    }

    fn push(&mut self, line: String) {
        let (line, truncated) = truncate_line(line, BACKGROUND_LINE_BYTE_CAP);
        self.push_one(line);
        if truncated {
            self.push_one(format!(
                "[background output line truncated at {BACKGROUND_LINE_BYTE_CAP} bytes]"
            ));
        }
    }

    fn push_one(&mut self, line: String) {
        let line_bytes = line.len();
        while self.bytes.saturating_add(line_bytes) > self.max_bytes {
            let Some(old) = self.lines.pop_front() else {
                break;
            };
            self.bytes = self.bytes.saturating_sub(old.len());
            self.dropped_lines = self.dropped_lines.saturating_add(1);
            self.dropped_bytes = self.dropped_bytes.saturating_add(old.len());
        }
        if line_bytes <= self.max_bytes {
            self.bytes = self.bytes.saturating_add(line_bytes);
            self.lines.push_back(line);
        } else {
            self.dropped_lines = self.dropped_lines.saturating_add(1);
            self.dropped_bytes = self.dropped_bytes.saturating_add(line_bytes);
        }
    }

    fn snapshot_all(&self) -> Vec<String> {
        let mut out = self.overflow_prefix();
        out.extend(self.lines.iter().cloned());
        out
    }

    fn snapshot_tail(&self, lines: usize) -> Vec<String> {
        let n = lines.min(self.lines.len());
        let mut out = self.overflow_prefix();
        out.extend(self.lines.iter().skip(self.lines.len() - n).cloned());
        out
    }

    fn overflow_prefix(&self) -> Vec<String> {
        if self.dropped_lines == 0 {
            Vec::new()
        } else {
            vec![format!(
                "[earlier background output discarded: {} bytes across {} line(s)]",
                self.dropped_bytes, self.dropped_lines
            )]
        }
    }
}

fn truncate_line(mut line: String, cap: usize) -> (String, bool) {
    if line.len() <= cap {
        return (line, false);
    }
    let mut end = cap;
    while !line.is_char_boundary(end) {
        end -= 1;
    }
    line.truncate(end);
    (line, true)
}

/// Spawn a background shell job. Returns the handle the authority keeps +
/// the task's [`tokio::task::JoinHandle`] (the authority takes its
/// `abort_handle` for cancellation).
pub fn spawn(
    BackgroundSpawn {
        job_id,
        label,
        command,
        cwd,
        launch,
        redact,
        turn_tx,
        event_tx,
    }: BackgroundSpawn,
) -> (BackgroundHandle, tokio::task::JoinHandle<()>) {
    let ring: Arc<Mutex<BoundedOutputRing>> =
        Arc::new(Mutex::new(BoundedOutputRing::new(BACKGROUND_RING_BYTE_CAP)));
    let (kill_tx, kill_rx) = tokio::sync::watch::channel(false);

    let handle = BackgroundHandle {
        label: label.clone(),
        ring: ring.clone(),
        kill_tx,
    };

    let task = spawn_guarded_background(
        run_background(
            job_id.clone(),
            label.clone(),
            command,
            cwd,
            launch,
            ring,
            redact,
            turn_tx,
            event_tx.clone(),
            kill_rx,
        ),
        event_tx,
        job_id,
        label,
    );
    (handle, task)
}

pub struct BackgroundSpawn {
    pub job_id: String,
    pub label: String,
    pub command: String,
    pub cwd: std::path::PathBuf,
    pub launch: BackgroundLaunch,
    pub redact: Arc<RedactionTable>,
    pub turn_tx: mpsc::Sender<TurnEvent>,
    pub event_tx: mpsc::Sender<ScheduleEvent>,
}

fn spawn_guarded_background<F>(
    fut: F,
    event_tx: mpsc::Sender<ScheduleEvent>,
    job_id: String,
    label: String,
) -> tokio::task::JoinHandle<()>
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    tokio::spawn(async move {
        if let Err(payload) = AssertUnwindSafe(fut).catch_unwind().await {
            let panic = panic_payload(payload.as_ref());
            let _ = event_tx
                .send(ScheduleEvent::Completed {
                    job_id,
                    label: label.clone(),
                    kind: ScheduleKind::Background,
                    result: format!("background `{label}` panicked: {panic}"),
                    failed: true,
                    requests: Vec::new(),
                })
                .await;
        }
    })
}

/// Extract a human-readable message from a caught panic payload. Shared with
/// the swarm runner's panic supervisor ([`super::authority`]).
pub(super) fn panic_payload(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "unknown panic".to_string()
    }
}

/// Maximum bytes a single background-output line may buffer while being read.
/// One byte past the display cap so a genuinely over-long line still reaches
/// the ring longer than [`BACKGROUND_LINE_BYTE_CAP`] and picks up the ring's
/// truncation note, while a hostile or buggy child that emits a huge
/// newline-free stream can never buffer without bound in the reader — the
/// excess is consumed and discarded up to the next newline.
const BACKGROUND_LINE_READ_CAP: usize = BACKGROUND_LINE_BYTE_CAP.saturating_add(1);

/// Strip a trailing `\r` (CRLF) then drain `pending` into an owned `String`
/// (lossy on invalid UTF-8, matching a hard byte cap that may split a char).
///
/// `strip_cr` peels a trailing `\r` ONLY for a complete, newline-terminated
/// line (a real CRLF terminator). It must be false for a cap-truncated head or
/// an unterminated final line, where a trailing `\r` is mid-line data: stripping
/// it there would both lose a byte and, at the `BACKGROUND_LINE_READ_CAP`
/// boundary, shrink the head to exactly `BACKGROUND_LINE_BYTE_CAP` so the ring
/// silently drops the truncation note. (Not stripping at EOF also matches
/// `tokio::io::Lines`, which strips `\r` only as part of `\r\n`.)
fn take_capped_line(pending: &mut Vec<u8>, strip_cr: bool) -> String {
    if strip_cr && pending.last() == Some(&b'\r') {
        pending.pop();
    }
    let bytes = std::mem::take(pending);
    String::from_utf8_lossy(&bytes).into_owned()
}

/// A `\n`-delimited line reader that never buffers more than `cap` bytes of a
/// single line: an over-cap physical line yields its first `cap` bytes and the
/// remainder is consumed and discarded up to the next newline. Drop-in shape
/// for `tokio::io::Lines` (`next_line() -> io::Result<Option<String>>`) and
/// cancel-safe: all partial state lives in `self` (the only await is
/// `fill_buf`, which consumes nothing), so a `select!` losing the race and
/// dropping the future keeps every already-read byte.
struct CappedLineReader<R> {
    reader: BufReader<R>,
    pending: Vec<u8>,
    cap: usize,
    /// True while discarding the tail of an over-cap physical line (whose capped
    /// head was already emitted) up to and including the next newline.
    discarding: bool,
}

impl<R: tokio::io::AsyncRead + Unpin> CappedLineReader<R> {
    fn new(reader: R, cap: usize) -> Self {
        Self {
            reader: BufReader::new(reader),
            pending: Vec::new(),
            cap: cap.max(1),
            discarding: false,
        }
    }

    async fn next_line(&mut self) -> std::io::Result<Option<String>> {
        loop {
            let chunk = self.reader.fill_buf().await?;
            if chunk.is_empty() {
                // EOF. A pending discard has already emitted its capped head, so
                // only its (dropped) tail remains — nothing more to yield.
                if self.discarding {
                    self.discarding = false;
                    self.pending.clear();
                    return Ok(None);
                }
                if self.pending.is_empty() {
                    return Ok(None);
                }
                // Unterminated final line: a trailing `\r` is data, not a CRLF.
                return Ok(Some(take_capped_line(&mut self.pending, false)));
            }
            match chunk.iter().position(|&b| b == b'\n') {
                Some(nl) => {
                    if self.discarding {
                        // The newline closes the discarded tail; resume normally.
                        self.reader.consume(nl + 1);
                        self.discarding = false;
                        continue;
                    }
                    let room = self.cap - self.pending.len();
                    let take = nl.min(room);
                    // The whole line fit within the cap iff we took all of it;
                    // only then is a trailing `\r` a genuine CRLF terminator.
                    let complete = take == nl;
                    self.pending.extend_from_slice(&chunk[..take]);
                    // Consume through the newline, dropping any bytes in
                    // `chunk[take..nl]` that overflowed the cap.
                    self.reader.consume(nl + 1);
                    return Ok(Some(take_capped_line(&mut self.pending, complete)));
                }
                None => {
                    let len = chunk.len();
                    if self.discarding {
                        self.reader.consume(len);
                        continue;
                    }
                    let room = self.cap - self.pending.len();
                    let take = len.min(room);
                    self.pending.extend_from_slice(&chunk[..take]);
                    // No newline in this chunk: the whole chunk belongs to the
                    // current line, so consume all of it (bytes past `take` are
                    // the start of the discarded over-cap tail).
                    self.reader.consume(len);
                    if self.pending.len() >= self.cap {
                        self.discarding = true;
                        // Cap-truncated head, no newline: never strip a `\r`.
                        return Ok(Some(take_capped_line(&mut self.pending, false)));
                    }
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_background(
    job_id: String,
    label: String,
    command: String,
    cwd: std::path::PathBuf,
    launch: BackgroundLaunch,
    ring: Arc<Mutex<BoundedOutputRing>>,
    _redact: Arc<RedactionTable>,
    turn_tx: mpsc::Sender<TurnEvent>,
    event_tx: mpsc::Sender<ScheduleEvent>,
    mut kill_rx: tokio::sync::watch::Receiver<bool>,
) {
    let mut cmd = match build_background_command(&command, &cwd, &launch).await {
        Ok(cmd) => cmd,
        Err(e) => {
            let _ = event_tx
                .send(ScheduleEvent::Completed {
                    job_id,
                    label,
                    kind: ScheduleKind::Background,
                    result: format!("failed to spawn: {e}"),
                    failed: true,
                    requests: Vec::new(),
                })
                .await;
            return;
        }
    };

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            let _ = event_tx
                .send(ScheduleEvent::Completed {
                    job_id,
                    label,
                    kind: ScheduleKind::Background,
                    result: format!("failed to spawn: {e}"),
                    failed: true,
                    requests: Vec::new(),
                })
                .await;
            return;
        }
    };

    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    // Capped readers so a child emitting a huge newline-free stream cannot
    // buffer without bound (the ring's per-line cap only applies AFTER a full
    // line is read, which is too late for memory safety).
    let mut out_lines =
        CappedLineReader::new(stdout.expect("stdout piped"), BACKGROUND_LINE_READ_CAP);
    let mut err_lines =
        CappedLineReader::new(stderr.expect("stderr piped"), BACKGROUND_LINE_READ_CAP);

    let push = |ring: &Arc<Mutex<BoundedOutputRing>>, line: String| {
        ring.lock().unwrap().push(line);
    };

    let mut stdout_done = false;
    let mut stderr_done = false;
    let mut killed = false;
    // Once the sole kill sender (owned by the authority) is dropped,
    // `kill_rx.changed()` returns `Err` immediately and permanently. Without a
    // guard the `select!` would keep selecting that always-ready arm while
    // stdout/stderr are pending, spinning the task at 100% CPU. Disarm the arm
    // on close so the loop only awaits real output afterwards.
    let mut kill_watch_closed = false;

    loop {
        tokio::select! {
            // Kill request from the authority / `background.cancel`.
            changed = kill_rx.changed(), if !kill_watch_closed => {
                match changed {
                    Ok(()) => {
                        if *kill_rx.borrow() {
                            killed = true;
                            let pid = child.id();
                            cockpit_host::process::terminate_group_async(
                                &mut child,
                                pid,
                                Duration::from_millis(200),
                            )
                            .await;
                            break;
                        }
                    }
                    // Sender gone: no kill can ever arrive. Stop polling this
                    // branch and keep draining the child's output.
                    Err(_) => kill_watch_closed = true,
                }
            }
            line = out_lines.next_line(), if !stdout_done => {
                match line {
                    Ok(Some(l)) => {
                        push(&ring, l);
                        let _ = turn_tx.try_send(TurnEvent::ScheduleProgress {
                            job_id: job_id.clone(),
                        });
                    }
                    _ => stdout_done = true,
                }
            }
            line = err_lines.next_line(), if !stderr_done => {
                match line {
                    Ok(Some(l)) => {
                        push(&ring, l);
                        let _ = turn_tx.try_send(TurnEvent::ScheduleProgress {
                            job_id: job_id.clone(),
                        });
                    }
                    _ => stderr_done = true,
                }
            }
            else => break,
        }
        if stdout_done && stderr_done {
            break;
        }
    }

    let status = child.wait().await;
    let exit = status.as_ref().ok().and_then(|s| s.code());
    let success = status.as_ref().map(|s| s.success()).unwrap_or(false);

    // Build the budget-capped result from the ring's freshest output.
    let snapshot: Vec<String> = {
        let r = ring.lock().unwrap();
        r.snapshot_all()
    };
    let mut writer = BudgetedWriter::new(ASYNC_RESULT_TOKEN_CAP);
    let fit = window_that_fits(&snapshot, ASYNC_RESULT_TOKEN_CAP);
    let start = snapshot.len().saturating_sub(fit);
    if fit < snapshot.len() {
        let _ = writer.writeln(&format!(
            "[earlier output elided — {} of {} line(s) shown]",
            fit,
            snapshot.len()
        ));
    }
    for line in &snapshot[start..] {
        if !writer.writeln(line) {
            break;
        }
    }
    let body = writer.into_string();

    let (result, failed) = if killed {
        (format!("background `{label}` was cancelled"), false)
    } else {
        let header = match exit {
            Some(0) => format!("background `{label}` finished (exit 0)\n"),
            Some(code) => format!("background `{label}` finished (exit {code})\n"),
            None => format!("background `{label}` terminated by signal\n"),
        };
        (format!("{header}{body}"), !success)
    };

    let _ = event_tx
        .send(ScheduleEvent::Completed {
            job_id,
            label,
            kind: ScheduleKind::Background,
            result,
            failed,
            requests: Vec::new(),
        })
        .await;
}

async fn build_background_command(
    command: &str,
    cwd: &std::path::Path,
    launch: &BackgroundLaunch,
) -> anyhow::Result<Command> {
    let mut cmd = if launch.confine {
        build_confined_background_command(command, cwd, launch).await?
    } else {
        let mut cmd = Command::new("sh");
        cmd.arg("-c").arg(command).current_dir(cwd);
        scrub_env(&mut cmd);
        cmd
    };
    configure_background_command(&mut cmd);
    Ok(cmd)
}

async fn build_confined_background_command(
    command: &str,
    cwd: &std::path::Path,
    launch: &BackgroundLaunch,
) -> anyhow::Result<Command> {
    #[cfg(test)]
    if let Some(test) = &launch.test_sandbox_build {
        match test {
            TestSandboxBuild::ShellSuccess { calls } => {
                calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let mut cmd = Command::new("sh");
                cmd.arg("-c").arg(command).current_dir(cwd);
                return Ok(cmd);
            }
            TestSandboxBuild::Error(message) => anyhow::bail!("{message}"),
        }
    }

    crate::tools::shell_sandbox::build_sandboxed_command_with_workspace_scratch(
        command,
        cwd,
        launch.tmp_dir.as_deref(),
        launch.workspace_scratch_dir.as_deref(),
        &scrub_overrides(&launch.session_env),
        &launch.session_env,
        &[],
        None,
    )
    .await
}

fn configure_background_command(cmd: &mut Command) {
    BACKGROUND_COMMAND_CONFIG.apply(cmd);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BackgroundCommandConfig {
    null_stdin: bool,
    pipe_stdout: bool,
    pipe_stderr: bool,
    kill_on_drop: bool,
}

const BACKGROUND_COMMAND_CONFIG: BackgroundCommandConfig = BackgroundCommandConfig {
    null_stdin: true,
    pipe_stdout: true,
    pipe_stderr: true,
    kill_on_drop: true,
};

impl BackgroundCommandConfig {
    fn apply(self, cmd: &mut Command) {
        if self.null_stdin {
            cmd.stdin(Stdio::null());
        }
        if self.pipe_stdout {
            cmd.stdout(Stdio::piped());
        }
        if self.pipe_stderr {
            cmd.stderr(Stdio::piped());
        }
        // If the authority aborts this task, kill the child too — a leaked
        // subprocess would outlive its job (anti-runaway).
        cmd.kill_on_drop(self.kill_on_drop);
        #[cfg(unix)]
        cmd.process_group(0);
    }
}

/// Same env-injection scrub as the `bash` tool: strip injection-vector
/// vars and secret-shaped keys.
fn scrub_env(cmd: &mut Command) {
    const FIXED_REMOVE: &[&str] = &[
        "BASH_ENV",
        "ENV",
        "PROMPT_COMMAND",
        "NODE_OPTIONS",
        "SHELLOPTS",
        "BASHOPTS",
        "GREP_OPTIONS",
        "GREP_COLORS",
    ];
    for var in FIXED_REMOVE {
        cmd.env_remove(var);
    }
    // vars_os: never panic on non-Unicode ambient values (unlike vars()).
    for (k, _v) in std::env::vars_os() {
        let Some(k) = k.to_str() else {
            continue;
        };
        if crate::redact::env_scrub_patterns(k) || k.starts_with("SEALED_") {
            cmd.env_remove(k);
        }
    }
}

fn scrub_overrides(session_env: &HashMap<String, String>) -> Vec<(String, String)> {
    session_env
        .keys()
        .cloned()
        .chain([
            "BASH_ENV".to_string(),
            "ENV".to_string(),
            "PROMPT_COMMAND".to_string(),
            "NODE_OPTIONS".to_string(),
            "SHELLOPTS".to_string(),
            "BASHOPTS".to_string(),
            "GREP_OPTIONS".to_string(),
            "GREP_COLORS".to_string(),
            "AWS_ACCESS_KEY_ID".to_string(),
            "AWS_SECRET_ACCESS_KEY".to_string(),
        ])
        .filter(|k| crate::redact::env_scrub_patterns(k))
        .map(|k| (k, String::new()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spawn_test_job(
        label: &str,
        command: &str,
        cwd: std::path::PathBuf,
        launch: BackgroundLaunch,
        redact: Arc<RedactionTable>,
        turn_tx: mpsc::Sender<TurnEvent>,
        event_tx: mpsc::Sender<ScheduleEvent>,
    ) -> (BackgroundHandle, tokio::task::JoinHandle<()>) {
        spawn(BackgroundSpawn {
            job_id: "job-1".to_string(),
            label: label.to_string(),
            command: command.to_string(),
            cwd,
            launch,
            redact,
            turn_tx,
            event_tx,
        })
    }

    #[test]
    fn window_that_fits_keeps_freshest() {
        let lines: Vec<String> = (0..50).map(|i| format!("line number {i}")).collect();
        // A tiny cap fits only a couple of trailing lines.
        let fit = window_that_fits(&lines, 6);
        assert!(fit >= 1 && fit < lines.len());
    }

    #[test]
    fn async_result_cap_keeps_result_above_old_2k_budget() {
        let lines: Vec<String> = (0..3_000).map(|_| "x".to_string()).collect();
        let joined = lines.join("\n");
        assert!(
            crate::tokens::count(&joined) > 2_000,
            "fixture must exceed the old async result budget"
        );
        assert!(
            crate::tokens::count(&joined) < ASYNC_RESULT_TOKEN_CAP,
            "fixture must fit under the raised async result budget"
        );

        let mut writer = BudgetedWriter::new(ASYNC_RESULT_TOKEN_CAP);
        for line in &lines {
            assert!(writer.writeln(line), "line should fit under raised cap");
        }
        assert!(!writer.is_truncated());
    }

    #[test]
    fn output_line_cap_truncates_with_note() {
        let mut ring = BoundedOutputRing::new(BACKGROUND_RING_BYTE_CAP);
        ring.push("x".repeat(BACKGROUND_LINE_BYTE_CAP + 100));
        let snapshot = ring.snapshot_all();
        assert_eq!(snapshot[0].len(), BACKGROUND_LINE_BYTE_CAP);
        assert!(snapshot[1].contains("line truncated"));
    }

    #[tokio::test]
    async fn capped_line_reader_splits_lines_and_strips_crlf() {
        let data = b"alpha\r\nbeta\ngamma";
        let mut r = CappedLineReader::new(&data[..], 100);
        assert_eq!(r.next_line().await.unwrap().as_deref(), Some("alpha"));
        assert_eq!(r.next_line().await.unwrap().as_deref(), Some("beta"));
        // A trailing line with no newline is flushed at EOF.
        assert_eq!(r.next_line().await.unwrap().as_deref(), Some("gamma"));
        assert_eq!(r.next_line().await.unwrap(), None);
    }

    #[tokio::test]
    async fn capped_line_reader_bounds_overlong_newline_free_line() {
        // A line far larger than the read cap AND larger than BufReader's
        // internal buffer (forcing the multi-chunk discard path) is capped to
        // the read cap; the following line is still read intact.
        let cap = 8usize;
        let mut data = vec![b'x'; 64 * 1024];
        data.push(b'\n');
        data.extend_from_slice(b"next\n");
        let mut r = CappedLineReader::new(&data[..], cap);
        let first = r.next_line().await.unwrap().unwrap();
        assert_eq!(first.len(), cap, "overlong line capped at the read cap");
        assert!(first.bytes().all(|b| b == b'x'));
        assert_eq!(r.next_line().await.unwrap().as_deref(), Some("next"));
        assert_eq!(r.next_line().await.unwrap(), None);
    }

    #[tokio::test]
    async fn overlong_line_still_gets_ring_truncation_note() {
        // End-to-end: a line past the READ cap, once pushed to the ring, still
        // exceeds the display cap and picks up the truncation note — bounding
        // reader memory does not lose the existing "[truncated]" behavior.
        let mut data = vec![b'x'; BACKGROUND_LINE_BYTE_CAP + 5_000];
        data.push(b'\n');
        let mut r = CappedLineReader::new(&data[..], BACKGROUND_LINE_READ_CAP);
        let line = r.next_line().await.unwrap().unwrap();
        assert_eq!(
            line.len(),
            BACKGROUND_LINE_READ_CAP,
            "reader caps at READ cap"
        );
        assert!(line.len() > BACKGROUND_LINE_BYTE_CAP);
        let mut ring = BoundedOutputRing::new(BACKGROUND_RING_BYTE_CAP);
        ring.push(line);
        let snapshot = ring.snapshot_all();
        assert_eq!(snapshot[0].len(), BACKGROUND_LINE_BYTE_CAP);
        assert!(snapshot[1].contains("line truncated"));
    }

    #[tokio::test]
    async fn overlong_line_with_cr_at_cap_keeps_truncation_note() {
        // Regression: the byte landing at the read-cap boundary is a `\r`. It is
        // mid-line data (not a CRLF terminator), so it must NOT be stripped —
        // otherwise the head shrinks to exactly the display cap and the ring
        // silently drops the "[…line truncated…]" note.
        let mut data = vec![b'a'; BACKGROUND_LINE_BYTE_CAP];
        data.push(b'\r'); // index BACKGROUND_LINE_BYTE_CAP → the READ_CAP-th byte
        data.extend(std::iter::repeat_n(b'z', 5_000));
        data.push(b'\n');
        let mut r = CappedLineReader::new(&data[..], BACKGROUND_LINE_READ_CAP);
        let line = r.next_line().await.unwrap().unwrap();
        assert_eq!(
            line.len(),
            BACKGROUND_LINE_READ_CAP,
            "the \\r at the cap boundary must be kept, not stripped"
        );
        assert!(line.ends_with('\r'));
        let mut ring = BoundedOutputRing::new(BACKGROUND_RING_BYTE_CAP);
        ring.push(line);
        let snapshot = ring.snapshot_all();
        assert_eq!(snapshot[0].len(), BACKGROUND_LINE_BYTE_CAP);
        assert!(
            snapshot[1].contains("line truncated"),
            "truncation note must survive a \\r at the cap boundary"
        );
    }

    #[tokio::test]
    async fn eof_while_discarding_yields_capped_head_then_none() {
        // Over-cap, newline-free line at end of stream: the capped head is
        // emitted, the tail discarded, and EOF then yields None (exercises the
        // EOF-while-discarding branch).
        let cap = 8usize;
        let data = vec![b'x'; 64 * 1024]; // no trailing newline
        let mut r = CappedLineReader::new(&data[..], cap);
        let first = r.next_line().await.unwrap().unwrap();
        assert_eq!(first.len(), cap);
        assert!(first.bytes().all(|b| b == b'x'));
        assert_eq!(r.next_line().await.unwrap(), None);
    }

    #[tokio::test]
    async fn empty_lines_yield_empty_strings() {
        let data = b"\n\nx\n";
        let mut r = CappedLineReader::new(&data[..], 8);
        assert_eq!(r.next_line().await.unwrap().as_deref(), Some(""));
        assert_eq!(r.next_line().await.unwrap().as_deref(), Some(""));
        assert_eq!(r.next_line().await.unwrap().as_deref(), Some("x"));
        assert_eq!(r.next_line().await.unwrap(), None);
    }

    #[tokio::test]
    async fn exactly_cap_line_is_not_split() {
        // A line of exactly `cap` bytes followed by '\n' yields one cap-length
        // line, not a cap-length line plus a phantom empty line.
        let data = b"xxxxxxxx\nnext\n"; // 8 x's, cap = 8
        let mut r = CappedLineReader::new(&data[..], 8);
        assert_eq!(r.next_line().await.unwrap().as_deref(), Some("xxxxxxxx"));
        assert_eq!(r.next_line().await.unwrap().as_deref(), Some("next"));
        assert_eq!(r.next_line().await.unwrap(), None);
    }

    #[test]
    fn output_ring_cap_discards_oldest_with_note() {
        let mut ring = BoundedOutputRing::new(12);
        ring.push("first".to_string());
        ring.push("second".to_string());
        ring.push("third".to_string());
        let snapshot = ring.snapshot_all();
        assert!(snapshot[0].contains("earlier background output discarded"));
        assert!(!snapshot.iter().any(|line| line == "first"));
        assert!(snapshot.iter().any(|line| line == "third"));
    }

    #[test]
    fn background_gate_unconfined_when_sandbox_off() {
        let availability = SandboxAvailability::Available;

        assert_eq!(
            background_launch_gate(false, &availability),
            SandboxGate::Unconfined
        );
    }

    #[test]
    fn background_gate_confines_when_sandbox_available() {
        let availability = SandboxAvailability::Available;

        assert_eq!(
            background_launch_gate(true, &availability),
            SandboxGate::Confine
        );
    }

    #[test]
    fn background_gate_refuses_when_sandbox_unavailable() {
        let availability = SandboxAvailability::Unavailable {
            reason: "bwrap absent".to_string(),
            fix_command: None,
        };

        assert_eq!(
            background_launch_gate(true, &availability),
            SandboxGate::Refuse {
                reason: "bwrap absent".to_string()
            }
        );
    }

    #[test]
    fn background_command_config_keeps_stdio_and_kill_on_drop_for_all_launch_paths() {
        assert_eq!(
            BACKGROUND_COMMAND_CONFIG,
            BackgroundCommandConfig {
                null_stdin: true,
                pipe_stdout: true,
                pipe_stderr: true,
                kill_on_drop: true,
            }
        );
    }

    #[tokio::test]
    async fn background_gate_confined_launch_uses_sandboxed_command() {
        let cfg = crate::config::extended::RedactConfig::default();
        let tmp = tempfile::tempdir().unwrap();
        let redact = Arc::new(RedactionTable::build(&cfg, tmp.path()).unwrap());
        let calls = Arc::new(AtomicUsize::new(0));
        let launch = BackgroundLaunch::confined(Some(tmp.path().join("tmp")), HashMap::new())
            .with_test_sandbox_build(TestSandboxBuild::ShellSuccess {
                calls: calls.clone(),
            });
        let (turn_tx, _turn_rx) = mpsc::channel(1);
        let (event_tx, mut event_rx) = mpsc::channel(1);
        let (_handle, task) = spawn_test_job(
            "confined",
            "printf 'sandboxed\\n'",
            tmp.path().to_path_buf(),
            launch,
            redact,
            turn_tx,
            event_tx,
        );

        let completed = event_rx
            .recv()
            .await
            .expect("confined test job should complete");
        task.await.unwrap();

        assert_eq!(calls.load(Ordering::SeqCst), 1);
        match completed {
            ScheduleEvent::Completed { result, failed, .. } => {
                assert!(!failed, "got {result}");
                assert!(result.contains("sandboxed"), "got {result}");
            }
            other => panic!("expected Completed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn background_gate_sandbox_build_error_fails_the_job() {
        let cfg = crate::config::extended::RedactConfig::default();
        let tmp = tempfile::tempdir().unwrap();
        let redact = Arc::new(RedactionTable::build(&cfg, tmp.path()).unwrap());
        let launch = BackgroundLaunch::confined(Some(tmp.path().join("tmp")), HashMap::new())
            .with_test_sandbox_build(TestSandboxBuild::Error("sandbox build failed".to_string()));
        let (turn_tx, _turn_rx) = mpsc::channel(1);
        let (event_tx, mut event_rx) = mpsc::channel(1);
        let (_handle, task) = spawn_test_job(
            "confined",
            "printf should-not-run",
            tmp.path().to_path_buf(),
            launch,
            redact,
            turn_tx,
            event_tx,
        );

        let completed = event_rx
            .recv()
            .await
            .expect("sandbox build error should complete the job");
        task.await.unwrap();

        match completed {
            ScheduleEvent::Completed { result, failed, .. } => {
                assert!(failed);
                assert!(result.contains("sandbox build failed"), "got {result}");
            }
            other => panic!("expected Completed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn guarded_background_panic_sends_terminal_failure() {
        let (event_tx, mut event_rx) = mpsc::channel(1);
        let task = spawn_guarded_background(
            async {
                panic!("detached failure");
            },
            event_tx,
            "job-1".to_string(),
            "panic".to_string(),
        );
        let completed = tokio::time::timeout(Duration::from_secs(5), event_rx.recv())
            .await
            .expect("panic cleanup should send terminal event")
            .unwrap();
        task.await.unwrap();
        match completed {
            ScheduleEvent::Completed { result, failed, .. } => {
                assert!(failed);
                assert!(result.contains("detached failure"), "got {result}");
            }
            other => panic!("expected Completed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn kill_after_fast_exit_does_not_hide_terminal_completion() {
        let cfg = crate::config::extended::RedactConfig::default();
        let tmp = tempfile::tempdir().unwrap();
        let redact = Arc::new(RedactionTable::build(&cfg, tmp.path()).unwrap());
        let (turn_tx, _turn_rx) = mpsc::channel(1);
        let (event_tx, mut event_rx) = mpsc::channel(1);
        let (handle, task) = spawn_test_job(
            "fast",
            "printf 'done\n'",
            tmp.path().to_path_buf(),
            BackgroundLaunch::unconfined(HashMap::new()),
            redact,
            turn_tx,
            event_tx,
        );
        let completed = tokio::time::timeout(Duration::from_secs(5), event_rx.recv())
            .await
            .expect("fast job should complete")
            .unwrap();
        handle.kill();
        task.await.unwrap();
        match completed {
            ScheduleEvent::Completed { result, failed, .. } => {
                assert!(!failed, "got {result}");
                assert!(result.contains("done"), "got {result}");
            }
            other => panic!("expected Completed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn dropped_kill_handle_does_not_wedge_running_job() {
        // Regression: dropping the kill handle (its watch sender) while the job
        // is still running must NOT spin the task. `kill_rx.changed()` then
        // returns Err immediately and permanently; without disarming that
        // `select!` arm the loop selects it forever, never polls stdout/stderr,
        // and burns 100% CPU while the job never completes. With the fix the arm
        // is disarmed and the job drains its output and completes normally.
        let cfg = crate::config::extended::RedactConfig::default();
        let tmp = tempfile::tempdir().unwrap();
        let redact = Arc::new(RedactionTable::build(&cfg, tmp.path()).unwrap());
        let (turn_tx, _turn_rx) = mpsc::channel(4);
        let (event_tx, mut event_rx) = mpsc::channel(4);
        let (handle, task) = spawn_test_job(
            "spin",
            "sleep 0.3; printf 'done\n'",
            tmp.path().to_path_buf(),
            BackgroundLaunch::unconfined(HashMap::new()),
            redact,
            turn_tx,
            event_tx,
        );
        // Drop the sole kill sender while the child is still sleeping.
        drop(handle);

        let completed = tokio::time::timeout(Duration::from_secs(5), event_rx.recv())
            .await
            .expect("job must complete after the kill handle is dropped (no busy-spin)")
            .unwrap();
        task.await.unwrap();
        match completed {
            ScheduleEvent::Completed { result, failed, .. } => {
                assert!(!failed, "got {result}");
                assert!(result.contains("done"), "got {result}");
            }
            other => panic!("expected Completed, got {other:?}"),
        }
    }

    /// A background job that emits progress then sleeps: `tail` shows the
    /// emitted lines while it's still running, and `cancel` (via the kill
    /// handle) kills it and yields a cancelled completion.
    #[cfg(unix)]
    #[tokio::test]
    async fn background_command_teardown_kills_grandchildren() {
        let cfg = crate::config::extended::RedactConfig::default();
        let tmp = tempfile::tempdir().unwrap();
        let pid_file = tmp.path().join("grandchild.pid");
        let redact = Arc::new(RedactionTable::build(&cfg, tmp.path()).unwrap());
        let (turn_tx, _turn_rx) = mpsc::channel(4);
        let (event_tx, mut event_rx) = mpsc::channel(4);
        let command = format!("sleep 30 & echo $! > {}; wait", pid_file.display());
        let (handle, task) = spawn_test_job(
            "tree",
            &command,
            tmp.path().to_path_buf(),
            BackgroundLaunch::unconfined(HashMap::new()),
            redact,
            turn_tx,
            event_tx,
        );
        tokio::time::timeout(Duration::from_secs(5), async {
            while !pid_file.exists() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        let pid: i32 = std::fs::read_to_string(&pid_file)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        handle.kill();
        let _ = event_rx.recv().await;
        task.await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_ne!(
            unsafe { libc::kill(pid, 0) },
            0,
            "grandchild survived cancellation"
        );
    }

    #[tokio::test]
    async fn tail_shows_progress_then_cancel_kills() {
        let cfg = crate::config::extended::RedactConfig::default();
        let tmp = tempfile::tempdir().unwrap();
        let redact = Arc::new(RedactionTable::build(&cfg, tmp.path()).unwrap());
        let (turn_tx, _turn_rx) = mpsc::channel(64);
        let (event_tx, mut event_rx) = mpsc::channel(64);
        let (handle, _task) = spawn_test_job(
            "slow",
            // Emit two lines, then sleep long enough that we can tail + kill.
            "printf 'progress one\\nprogress two\\n'; sleep 30",
            tmp.path().to_path_buf(),
            BackgroundLaunch::unconfined(HashMap::new()),
            redact.clone(),
            turn_tx,
            event_tx,
        );

        // Wait until both lines land in the ring (poll the tail).
        let mut waited = 0;
        loop {
            let t = handle.tail(40, &redact);
            if t.contains("progress two") {
                assert!(t.contains("progress one"));
                break;
            }
            assert!(waited < 100, "lines never appeared in tail: {t}");
            tokio::time::sleep(Duration::from_millis(20)).await;
            waited += 1;
        }

        // Cancel kills the still-sleeping child.
        handle.kill();
        let completed = tokio::time::timeout(Duration::from_secs(10), event_rx.recv())
            .await
            .expect("cancel should complete the job")
            .unwrap();
        match completed {
            ScheduleEvent::Completed { result, failed, .. } => {
                assert!(!failed, "a cancelled scheduled task isn't a failure");
                assert!(result.contains("cancelled"), "got {result}");
            }
            other => panic!("expected Completed, got {other:?}"),
        }
    }

    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;
}
