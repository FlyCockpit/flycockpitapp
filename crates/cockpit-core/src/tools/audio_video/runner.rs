//! Injected argv runner for A/V tools.
//!
//! Production uses a system runner with a cleared env allowlist, closed
//! stdin, capped pipes, deadline kill-and-reap, and private temp paths.
//! Tests inject [`FakeAvArgvRunner`] — required CI suites never spawn a
//! real process or sleep.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Result, bail};
use async_trait::async_trait;
use tokio_util::sync::CancellationToken;

use super::{MAX_PROCESS_STDERR_BYTES, MAX_PROCESS_STDOUT_BYTES, ProcessSpec};

const PROCESS_TREE_CLEANUP_TIMEOUT: Duration = Duration::from_secs(2);

/// Output of one argv invocation.
#[derive(Debug, Clone, Default)]
pub struct AvRunnerOutput {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub killed: bool,
    pub timed_out: bool,
    pub cleaned_temp_paths: Vec<PathBuf>,
}

/// Injected argv runner used by A/V tools. Callers never spawn ffmpeg
/// themselves.
#[async_trait]
pub trait AvArgvRunner: Send + Sync {
    fn requires_approved_runtime(&self) -> bool {
        false
    }

    async fn run(&self, spec: &ProcessSpec, cancel: &CancellationToken) -> Result<AvRunnerOutput>;
}

/// System ffmpeg/ffprobe runner. Required CI tests never construct this.
pub struct SystemAvArgvRunner;

#[async_trait]
impl AvArgvRunner for SystemAvArgvRunner {
    fn requires_approved_runtime(&self) -> bool {
        true
    }

    async fn run(&self, spec: &ProcessSpec, cancel: &CancellationToken) -> Result<AvRunnerOutput> {
        run_system_process(spec, cancel).await
    }
}

async fn run_system_process(
    spec: &ProcessSpec,
    cancel: &CancellationToken,
) -> Result<AvRunnerOutput> {
    use std::process::Stdio;
    use tokio::io::AsyncReadExt as _;

    struct TempPathGuard<'a>(&'a [PathBuf]);
    impl Drop for TempPathGuard<'_> {
        fn drop(&mut self) {
            cleanup_temp_paths(self.0);
        }
    }
    let _temp_guard = TempPathGuard(&spec.temp_paths);

    if cancel.is_cancelled() {
        bail!("cancelled");
    }
    if !spec.program.is_absolute() {
        bail!("media_runtime_unavailable");
    }
    let mut command = tokio::process::Command::new(&spec.program);
    command
        .args(&spec.argv)
        .env_clear()
        .kill_on_drop(true)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let containment = cockpit_host::process::ProcessTreeGuard::prepare(&mut command)?;
    if spec.stdin_closed {
        command.stdin(Stdio::null());
    } else {
        command.stdin(Stdio::null());
    }
    for (key, value) in &spec.environment {
        command.env(key, value);
    }
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            return Err(error.into());
        }
    };
    if let Err(error) = containment.attach(&child) {
        let child_pid = child.id();
        let _ = terminate_process_tree(&mut child, child_pid, &containment).await?;
        return Err(error);
    }
    let child_pid = child.id();
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let stdout_limit = spec.stdout_limit.max(1);
    let stderr_limit = spec.stderr_limit.max(1);
    let (cap_tx, mut cap_rx) = tokio::sync::mpsc::channel::<()>(2);
    let stdout_cap_tx = cap_tx.clone();
    let mut read_stdout = tokio::spawn(async move {
        let mut out = Vec::new();
        if let Some(pipe) = stdout {
            pipe.take(stdout_limit as u64 + 1)
                .read_to_end(&mut out)
                .await?;
        }
        if out.len() > stdout_limit {
            let _ = stdout_cap_tx.send(()).await;
            bail!("resource_limit");
        }
        Ok::<_, anyhow::Error>(out)
    });
    let stderr_cap_tx = cap_tx;
    let mut read_stderr = tokio::spawn(async move {
        let mut err = Vec::new();
        if let Some(pipe) = stderr {
            pipe.take(stderr_limit as u64 + 1)
                .read_to_end(&mut err)
                .await?;
        }
        if err.len() > stderr_limit {
            let _ = stderr_cap_tx.send(()).await;
            bail!("resource_limit");
        }
        Ok::<_, anyhow::Error>(err)
    });
    // One absolute deadline covers both the direct child and pipe EOF. A child
    // can exit after spawning a descendant that inherited stdout/stderr; those
    // drains must not become an unbounded post-exit await.
    let deadline = tokio::time::Instant::now() + spec.deadline;
    let observed_status = tokio::select! {
        biased;
        Some(()) = cap_rx.recv() => {
            let cleanup = terminate_process_tree(&mut child, child_pid, &containment).await;
            abort_unjoined_pipe_readers(&mut read_stdout, false, &mut read_stderr, false).await;
            let _ = cleanup?;
            bail!("resource_limit");
        }
        _ = cancel.cancelled() => {
            let cleanup = terminate_process_tree(&mut child, child_pid, &containment).await;
            abort_unjoined_pipe_readers(&mut read_stdout, false, &mut read_stderr, false).await;
            let _ = cleanup?;
            bail!("cancelled");
        }
        _ = tokio::time::sleep_until(deadline) => {
            let cleanup = terminate_process_tree(&mut child, child_pid, &containment).await;
            abort_unjoined_pipe_readers(&mut read_stdout, false, &mut read_stderr, false).await;
            let _ = cleanup?;
            bail!("deadline_exceeded");
        }
        result = observe_child_exit(&mut child, child_pid) => {
            let status = match result {
                Ok(value) => value,
                Err(error) => {
                    // Observation failure must not skip group SIGKILL: `child`
                    // is `kill_on_drop` and is declared after the guard, so
                    // returning here would reap the leader before Drop could
                    // terminate. Signal while the pin still holds.
                    let cleanup = terminate_process_tree(&mut child, child_pid, &containment).await;
                    abort_unjoined_pipe_readers(&mut read_stdout, false, &mut read_stderr, false).await;
                    let _ = cleanup;
                    return Err(error.into());
                }
            };
            status
        }
    };
    enum DrainOutcome {
        Complete(Result<(Vec<u8>, Vec<u8>)>),
        ResourceLimit,
        Cancelled,
        Deadline,
    }
    let mut stdout_joined = false;
    let mut stderr_joined = false;
    let drain_outcome = {
        let drains = async {
            let stdout = (&mut read_stdout).await;
            stdout_joined = true;
            let stdout = stdout.map_err(anyhow::Error::from)??;
            let stderr = (&mut read_stderr).await;
            stderr_joined = true;
            let stderr = stderr.map_err(anyhow::Error::from)??;
            Ok::<_, anyhow::Error>((stdout, stderr))
        };
        tokio::pin!(drains);
        tokio::select! {
            biased;
            Some(()) = cap_rx.recv() => DrainOutcome::ResourceLimit,
            _ = cancel.cancelled() => DrainOutcome::Cancelled,
            _ = tokio::time::sleep_until(deadline) => DrainOutcome::Deadline,
            result = &mut drains => DrainOutcome::Complete(result),
        }
    };
    let (stdout, stderr) = match drain_outcome {
        DrainOutcome::Complete(Ok(output)) => output,
        DrainOutcome::Complete(Err(error)) => {
            let cleanup = terminate_process_tree(&mut child, child_pid, &containment).await;
            abort_unjoined_pipe_readers(
                &mut read_stdout,
                stdout_joined,
                &mut read_stderr,
                stderr_joined,
            )
            .await;
            let _ = cleanup?;
            return Err(error);
        }
        DrainOutcome::ResourceLimit => {
            let cleanup = terminate_process_tree(&mut child, child_pid, &containment).await;
            abort_unjoined_pipe_readers(
                &mut read_stdout,
                stdout_joined,
                &mut read_stderr,
                stderr_joined,
            )
            .await;
            let _ = cleanup?;
            bail!("resource_limit");
        }
        DrainOutcome::Cancelled => {
            let cleanup = terminate_process_tree(&mut child, child_pid, &containment).await;
            abort_unjoined_pipe_readers(
                &mut read_stdout,
                stdout_joined,
                &mut read_stderr,
                stderr_joined,
            )
            .await;
            let _ = cleanup?;
            bail!("cancelled");
        }
        DrainOutcome::Deadline => {
            let cleanup = terminate_process_tree(&mut child, child_pid, &containment).await;
            abort_unjoined_pipe_readers(
                &mut read_stdout,
                stdout_joined,
                &mut read_stderr,
                stderr_joined,
            )
            .await;
            let _ = cleanup?;
            bail!("deadline_exceeded");
        }
    };
    // Pipe EOF proves only that descendants closed or redirected these two
    // descriptors, not that the process group is empty. On Unix the leader is
    // intentionally still unreaped here, pinning the group identity while
    // containment terminates residual descendants. Reap only afterward.
    let cleanup_status = terminate_process_tree(&mut child, child_pid, &containment).await?;
    let status = observed_status
        .or(cleanup_status)
        .ok_or_else(|| anyhow::anyhow!("child exit status missing"))?;
    if !status.success() {
        bail!("media_process_failed: {}", String::from_utf8_lossy(&stderr));
    }
    Ok(AvRunnerOutput {
        stdout,
        stderr,
        killed: false,
        timed_out: false,
        cleaned_temp_paths: spec.temp_paths.clone(),
    })
}

async fn terminate_process_tree(
    child: &mut tokio::process::Child,
    pid: Option<u32>,
    containment: &cockpit_host::process::ProcessTreeGuard,
) -> Result<Option<std::process::ExitStatus>> {
    let containment_termination = containment.terminate();
    #[cfg(unix)]
    {
        containment_termination?;
        let status = if let Ok(status) = tokio::time::timeout(
            PROCESS_TREE_CLEANUP_TIMEOUT,
            cockpit_host::process::terminate_group_and_reap_status_async(
                child,
                pid,
                Duration::from_millis(100),
            ),
        )
        .await
        {
            Some(status?)
        } else {
            let _ = child.start_kill();
            Some(
                tokio::time::timeout(PROCESS_TREE_CLEANUP_TIMEOUT, child.wait())
                    .await
                    .map_err(|_| anyhow::anyhow!("process_cleanup_deadline_exceeded"))??,
            )
        };
        Ok(status)
    }
    #[cfg(windows)]
    {
        let _ = pid;
        let termination_failed = containment_termination.is_err();
        let mut close_failed = false;
        if termination_failed {
            // TerminateJobObject can fail even though kill-on-close remains
            // usable. Close the job and also kill the direct child so either
            // mechanism can make progress before the bounded reap.
            close_failed = containment.close_job().is_err();
            let _ = child.start_kill();
        }
        if wait_for_child_bounded(child).await.is_err() {
            close_failed |= containment.close_job().is_err();
            let _ = child.start_kill();
            wait_for_child_bounded(child).await?;
        }
        if termination_failed && close_failed {
            bail!("process_tree_termination_failed");
        }
        Ok(None)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (child, pid, containment_termination);
        Ok(None)
    }
}

#[cfg(unix)]
async fn observe_child_exit(
    _child: &mut tokio::process::Child,
    pid: Option<u32>,
) -> Result<Option<std::process::ExitStatus>> {
    let pid = pid.ok_or_else(|| anyhow::anyhow!("child identity missing"))?;
    cockpit_host::process::wait_for_exit_without_reaping(pid).await?;
    Ok(None)
}

#[cfg(not(unix))]
async fn observe_child_exit(
    child: &mut tokio::process::Child,
    _pid: Option<u32>,
) -> Result<Option<std::process::ExitStatus>> {
    Ok(Some(child.wait().await?))
}

#[cfg(windows)]
async fn wait_for_child_bounded(child: &mut tokio::process::Child) -> Result<()> {
    tokio::time::timeout(PROCESS_TREE_CLEANUP_TIMEOUT, child.wait())
        .await
        .map_err(|_| anyhow::anyhow!("process_cleanup_deadline_exceeded"))??;
    Ok(())
}

/// A drain future may already have joined one handle before the other fails.
/// A completed `JoinHandle` must never be awaited a second time. Track which
/// readers the drain future actually joined, then abort and join every reader
/// whose handle has not yet been consumed (including an already-finished task).
async fn abort_unjoined_pipe_readers(
    stdout: &mut tokio::task::JoinHandle<Result<Vec<u8>>>,
    stdout_joined: bool,
    stderr: &mut tokio::task::JoinHandle<Result<Vec<u8>>>,
    stderr_joined: bool,
) {
    if !stdout_joined {
        if !stdout.is_finished() {
            stdout.abort();
        }
        let _ = stdout.await;
    }
    if !stderr_joined {
        if !stderr.is_finished() {
            stderr.abort();
        }
        let _ = stderr.await;
    }
}

fn cleanup_temp_paths(paths: &[PathBuf]) {
    for path in paths {
        let _ = std::fs::remove_file(path);
        if path.is_dir() {
            let _ = std::fs::remove_dir_all(path);
        }
        if let Some(parent) = path.parent()
            && parent
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("cockpit-av-"))
        {
            let _ = std::fs::remove_dir(parent);
        }
    }
}

/// Recorded invocation for fake-process suites.
#[derive(Debug, Clone)]
pub struct RecordedAvRun {
    pub program: String,
    pub argv: Vec<String>,
    pub environment: Vec<(String, String)>,
    pub stdin_closed: bool,
    pub stdout_limit: usize,
    pub stderr_limit: usize,
    pub deadline: Duration,
}

/// Scripted fake runner. Never execs, never sleeps, never mutates process env.
#[derive(Clone)]
pub struct FakeAvArgvRunner {
    inner: Arc<FakeAvArgvRunnerInner>,
}

struct FakeAvArgvRunnerInner {
    calls: Mutex<Vec<RecordedAvRun>>,
    stdout_by_program: Mutex<HashMap<String, Vec<u8>>>,
    stderr_by_program: Mutex<HashMap<String, Vec<u8>>>,
    force_timeout: Mutex<bool>,
    force_cancel: Mutex<bool>,
    bomb_stdout: Mutex<Option<usize>>,
    corrupt: Mutex<bool>,
    fail_program_call: Mutex<Option<(String, usize)>>,
    cleaned: Mutex<Vec<PathBuf>>,
    staged_inputs: Mutex<Vec<Vec<u8>>>,
    reaped_processes: Mutex<usize>,
}

impl FakeAvArgvRunner {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(FakeAvArgvRunnerInner {
                calls: Mutex::new(Vec::new()),
                stdout_by_program: Mutex::new(HashMap::new()),
                stderr_by_program: Mutex::new(HashMap::new()),
                force_timeout: Mutex::new(false),
                force_cancel: Mutex::new(false),
                bomb_stdout: Mutex::new(None),
                corrupt: Mutex::new(false),
                fail_program_call: Mutex::new(None),
                cleaned: Mutex::new(Vec::new()),
                staged_inputs: Mutex::new(Vec::new()),
                reaped_processes: Mutex::new(0),
            }),
        }
    }

    pub fn with_probe_json(self, json: impl Into<Vec<u8>>) -> Self {
        self.inner
            .stdout_by_program
            .lock()
            .expect("probe json lock")
            .insert("ffprobe".into(), json.into());
        self
    }

    pub fn with_ffmpeg_bytes(self, bytes: impl Into<Vec<u8>>) -> Self {
        self.inner
            .stdout_by_program
            .lock()
            .expect("ffmpeg bytes lock")
            .insert("ffmpeg".into(), bytes.into());
        self
    }

    pub fn force_timeout(&self) {
        *self.inner.force_timeout.lock().expect("timeout lock") = true;
    }

    pub fn force_cancel(&self) {
        *self.inner.force_cancel.lock().expect("cancel lock") = true;
    }

    pub fn bomb_stdout(&self, bytes: usize) {
        *self.inner.bomb_stdout.lock().expect("bomb lock") = Some(bytes);
    }

    pub fn corrupt(&self) {
        *self.inner.corrupt.lock().expect("corrupt lock") = true;
    }

    pub fn fail_program_on_call(&self, program: &str, call: usize) {
        *self
            .inner
            .fail_program_call
            .lock()
            .expect("program failure lock") = Some((program.to_owned(), call));
    }

    pub fn calls(&self) -> Vec<RecordedAvRun> {
        self.inner.calls.lock().expect("calls lock").clone()
    }

    pub fn cleaned_paths(&self) -> Vec<PathBuf> {
        self.inner.cleaned.lock().expect("cleaned lock").clone()
    }

    pub fn staged_inputs(&self) -> Vec<Vec<u8>> {
        self.inner
            .staged_inputs
            .lock()
            .expect("staged inputs lock")
            .clone()
    }

    pub fn reaped_processes(&self) -> usize {
        *self.inner.reaped_processes.lock().expect("reaped lock")
    }
}

impl Default for FakeAvArgvRunner {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl AvArgvRunner for FakeAvArgvRunner {
    async fn run(&self, spec: &ProcessSpec, cancel: &CancellationToken) -> Result<AvRunnerOutput> {
        let program_name = spec
            .program
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default()
            .to_owned();
        if let Some(bytes) = spec
            .argv
            .iter()
            .find_map(|argument| std::fs::read(argument).ok())
        {
            self.inner
                .staged_inputs
                .lock()
                .expect("staged inputs lock")
                .push(bytes);
        }
        let program_call = {
            let mut calls = self.inner.calls.lock().expect("calls lock");
            calls.push(RecordedAvRun {
                program: spec.program.to_string_lossy().into_owned(),
                argv: spec.argv.clone(),
                environment: spec
                    .environment
                    .iter()
                    .map(|(k, v)| ((*k).to_string(), v.clone()))
                    .collect(),
                stdin_closed: spec.stdin_closed,
                stdout_limit: spec.stdout_limit,
                stderr_limit: spec.stderr_limit,
                deadline: spec.deadline,
            });
            calls
                .iter()
                .filter(|call| {
                    Path::new(&call.program)
                        .file_name()
                        .and_then(|name| name.to_str())
                        == Some(program_name.as_str())
                })
                .count()
        };
        if cancel.is_cancelled() || *self.inner.force_cancel.lock().expect("cancel lock") {
            cleanup_recorded(self, spec);
            bail!("cancelled");
        }
        if *self.inner.force_timeout.lock().expect("timeout lock") {
            cleanup_recorded(self, spec);
            bail!("deadline_exceeded");
        }
        if self
            .inner
            .fail_program_call
            .lock()
            .expect("program failure lock")
            .as_ref()
            .is_some_and(|(program, call)| program == &program_name && *call == program_call)
        {
            cleanup_recorded(self, spec);
            bail!("media_process_failed: injected nth program failure");
        }
        if *self.inner.corrupt.lock().expect("corrupt lock") {
            cleanup_recorded(self, spec);
            return Ok(AvRunnerOutput {
                stdout: b"{not json".to_vec(),
                stderr: b"invalid_media".to_vec(),
                killed: false,
                timed_out: false,
                cleaned_temp_paths: spec.temp_paths.clone(),
            });
        }
        if let Some(size) = *self.inner.bomb_stdout.lock().expect("bomb lock") {
            cleanup_recorded(self, spec);
            if size > spec.stdout_limit {
                bail!("resource_limit");
            }
            return Ok(AvRunnerOutput {
                stdout: vec![0u8; size],
                stderr: Vec::new(),
                killed: false,
                timed_out: false,
                cleaned_temp_paths: spec.temp_paths.clone(),
            });
        }
        let stdout = self
            .inner
            .stdout_by_program
            .lock()
            .expect("stdout lock")
            .get(
                spec.program
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or_default(),
            )
            .cloned()
            .unwrap_or_else(default_stdout_for);
        let stderr = self
            .inner
            .stderr_by_program
            .lock()
            .expect("stderr lock")
            .get(
                spec.program
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or_default(),
            )
            .cloned()
            .unwrap_or_default();
        if stdout.len() > spec.stdout_limit || stderr.len() > spec.stderr_limit {
            cleanup_recorded(self, spec);
            bail!("resource_limit");
        }
        cleanup_recorded(self, spec);
        Ok(AvRunnerOutput {
            stdout,
            stderr,
            killed: false,
            timed_out: false,
            cleaned_temp_paths: spec.temp_paths.clone(),
        })
    }
}

fn cleanup_recorded(runner: &FakeAvArgvRunner, spec: &ProcessSpec) {
    cleanup_temp_paths(&spec.temp_paths);
    runner.inner.cleaned.lock().expect("cleaned lock").extend(
        spec.temp_paths
            .iter()
            .filter(|path| !path.exists())
            .cloned(),
    );
    *runner.inner.reaped_processes.lock().expect("reaped lock") += 1;
}

fn default_stdout_for() -> Vec<u8> {
    DEFAULT_FFPROBE_JSON.as_bytes().to_vec()
}

pub const DEFAULT_FFPROBE_JSON: &str = r#"{
  "format": {"duration": "2.000"},
  "streams": [
    {
      "index": 0,
      "codec_type": "audio",
      "codec_name": "aac",
      "sample_rate": "44100",
      "channels": 2,
      "disposition": {"default": 1}
    },
    {
      "index": 1,
      "codec_type": "video",
      "codec_name": "h264",
      "width": 1280,
      "height": 720,
      "avg_frame_rate": "24/1",
      "time_base": "1/1000",
      "disposition": {"default": 1}
    }
  ],
  "frames": [
    {"media_type": "video", "stream_index": 1, "best_effort_timestamp": "0", "pts_time": "0.000"},
    {"media_type": "video", "stream_index": 1, "best_effort_timestamp": "40", "pts_time": "0.040"},
    {"media_type": "video", "stream_index": 1, "best_effort_timestamp": "80", "pts_time": "0.080"},
    {"media_type": "video", "stream_index": 1, "best_effort_timestamp": "120", "pts_time": "0.120"}
  ]
}"#;

pub const DEFAULT_WAV_BYTES: &[u8] = b"RIFF\x24\x00\x00\x00WAVEfmt ";
pub const DEFAULT_MP4_BYTES: &[u8] = b"\0\0\0\x18ftypisom";
/// Valid 1x1 grayscale+alpha PNG used by storyboard/provider handoff tests.
pub const DEFAULT_PNG_BYTES: &[u8] = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x04\x00\x00\x00\xb5\x1c\x0c\x02\x00\x00\x00\x0bIDATx\xda\x63\x64\xf8\x0f\x00\x01\x05\x01\x01\x27\x18\xe3\x66\x00\x00\x00\x00IEND\xaeB\x60\x82";

/// Write retained bytes to a private temp path for file-based argv.
pub fn write_private_temp(bytes: &[u8], suffix: &str) -> Result<PathBuf> {
    if bytes.is_empty() || bytes.len() > MAX_PROCESS_STDOUT_BYTES {
        bail!("resource_limit");
    }
    let dir = tempfile::Builder::new().prefix("cockpit-av-").tempdir()?;
    let path = dir.path().join(format!("source{suffix}"));
    std::fs::write(&path, bytes)?;
    // Transfer ownership only after the complete source write succeeds. On a
    // write error the TempDir guard removes the private directory.
    let _persisted_dir = dir.keep();
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_util::sync::CancellationToken;

    #[tokio::test]
    async fn audio_video_fake_process_lifecycle_runner_boundary() {
        let runner = FakeAvArgvRunner::new().with_probe_json(br#"{"format":{"duration":"1.000"},"streams":[{"index":0,"codec_type":"audio","codec_name":"aac"}]}"#.to_vec());
        let spec = super::super::probe_process("/held/a.wav");
        let out = runner
            .run(&spec, &CancellationToken::new())
            .await
            .expect("fake run");
        assert!(!out.stdout.is_empty());
        let recorded = runner.calls();
        assert_eq!(recorded.len(), 1);
        assert!(recorded[0].stdin_closed);
        assert!(recorded[0].stderr_limit <= MAX_PROCESS_STDERR_BYTES);
        assert!(!recorded[0].argv.iter().any(|arg| arg == "--"));

        runner.force_timeout();
        let err = runner
            .run(&spec, &CancellationToken::new())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("deadline_exceeded"));

        let cancel = CancellationToken::new();
        cancel.cancel();
        let err = runner.run(&spec, &cancel).await.unwrap_err();
        assert!(err.to_string().contains("cancelled"));

        let bomb = FakeAvArgvRunner::new();
        bomb.bomb_stdout(MAX_PROCESS_STDOUT_BYTES + 1);
        let err = bomb
            .run(&spec, &CancellationToken::new())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("resource_limit"));
    }
}

pub fn input_path_from_handle(
    handle: &crate::tool_media_authority::AdmittedHandle,
) -> Result<(String, Vec<PathBuf>)> {
    use crate::tool_media_authority::AdmittedHandle;
    match handle {
        AdmittedHandle::Local(local) => {
            use std::io::{Read as _, Seek as _, SeekFrom};

            // Stage from the authority-held no-follow descriptor. The
            // canonical spelling is evidence only and is never reopened.
            let mut held = local
                .held_file()
                .ok_or_else(|| anyhow::anyhow!("media_source_handle_missing"))?
                .lock()
                .map_err(|_| anyhow::anyhow!("media_source_handle_poisoned"))?;
            held.seek(SeekFrom::Start(0))?;
            let declared = held.metadata()?.len();
            if declared == 0 || declared > MAX_PROCESS_STDOUT_BYTES as u64 {
                bail!("resource_limit");
            }
            let mut bytes = Vec::with_capacity(declared as usize);
            (&mut *held)
                .take(MAX_PROCESS_STDOUT_BYTES as u64 + 1)
                .read_to_end(&mut bytes)?;
            if bytes.len() as u64 != declared || bytes.len() > MAX_PROCESS_STDOUT_BYTES {
                bail!("resource_limit");
            }
            let path = write_private_temp(&bytes, ".bin")?;
            let parent = path.parent().unwrap_or(Path::new(".")).to_path_buf();
            Ok((path.to_string_lossy().into_owned(), vec![path, parent]))
        }
        AdmittedHandle::RetainedHttps(source) => {
            let path = write_private_temp(source.content(), ".bin")?;
            let parent = path.parent().unwrap_or(Path::new(".")).to_path_buf();
            Ok((path.to_string_lossy().into_owned(), vec![path, parent]))
        }
        AdmittedHandle::Attachment(_) => {
            bail!("attachment_bytes_unavailable");
        }
    }
}
