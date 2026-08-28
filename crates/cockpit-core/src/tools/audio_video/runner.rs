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

/// Output of one argv invocation.
#[derive(Debug, Clone, Default)]
pub struct AvRunnerOutput {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub killed: bool,
    pub timed_out: bool,
    pub cleaned_temp_paths: Vec<PathBuf>,
    pub captured_files: Vec<(PathBuf, Vec<u8>)>,
}

/// Injected argv runner used by A/V tools. Callers never spawn ffmpeg
/// themselves.
#[async_trait]
pub trait AvArgvRunner: Send + Sync {
    async fn run(&self, spec: &ProcessSpec, cancel: &CancellationToken) -> Result<AvRunnerOutput>;
}

/// System ffmpeg/ffprobe runner. Required CI tests never construct this.
pub struct SystemAvArgvRunner;

#[async_trait]
impl AvArgvRunner for SystemAvArgvRunner {
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

    if cancel.is_cancelled() {
        cleanup_temp_paths(&spec.temp_paths);
        bail!("cancelled");
    }
    let mut command = tokio::process::Command::new(spec.program);
    command
        .args(&spec.argv)
        .env_clear()
        .kill_on_drop(true)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if spec.stdin_closed {
        command.stdin(Stdio::null());
    } else {
        command.stdin(Stdio::null());
    }
    for (key, value) in &spec.environment {
        command.env(key, value);
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;

        // Enforce the output-file ceiling in the child kernel boundary, not
        // only when collecting the file after ffmpeg exits.
        unsafe {
            command.as_std_mut().pre_exec(|| {
                let ceiling = libc::rlimit {
                    rlim_cur: MAX_PROCESS_STDOUT_BYTES as libc::rlim_t,
                    rlim_max: MAX_PROCESS_STDOUT_BYTES as libc::rlim_t,
                };
                if libc::setrlimit(libc::RLIMIT_FSIZE, &ceiling) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            cleanup_temp_paths(&spec.temp_paths);
            return Err(error.into());
        }
    };
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let stdout_limit = spec.stdout_limit.max(1);
    let stderr_limit = spec.stderr_limit.max(1);
    let read_stdout = tokio::spawn(async move {
        let mut out = Vec::new();
        if let Some(pipe) = stdout {
            pipe.take(stdout_limit as u64 + 1)
                .read_to_end(&mut out)
                .await?;
        }
        if out.len() > stdout_limit {
            bail!("resource_limit");
        }
        Ok::<_, anyhow::Error>(out)
    });
    let read_stderr = tokio::spawn(async move {
        let mut err = Vec::new();
        if let Some(pipe) = stderr {
            pipe.take(stderr_limit as u64 + 1)
                .read_to_end(&mut err)
                .await?;
        }
        if err.len() > stderr_limit {
            bail!("resource_limit");
        }
        Ok::<_, anyhow::Error>(err)
    });
    let deadline = spec.deadline;
    tokio::select! {
        _ = cancel.cancelled() => {
            let _ = child.start_kill();
            let _ = child.wait().await;
            cleanup_temp_paths(&spec.temp_paths);
            bail!("cancelled");
        }
        _ = tokio::time::sleep(deadline) => {
            let _ = child.start_kill();
            let _ = child.wait().await;
            cleanup_temp_paths(&spec.temp_paths);
            bail!("deadline_exceeded");
        }
        result = child.wait() => {
            let status = match result {
                Ok(value) => value,
                Err(error) => {
                    let _ = child.start_kill();
                    let _ = child.wait().await;
                    cleanup_temp_paths(&spec.temp_paths);
                    return Err(error.into());
                }
            };
            let stdout = read_stdout.await.map_err(anyhow::Error::from)??;
            let stderr = read_stderr.await.map_err(anyhow::Error::from)??;
            if !status.success() {
                cleanup_temp_paths(&spec.temp_paths);
                bail!("media_process_failed: {}", String::from_utf8_lossy(&stderr));
            }
            let captured_files = capture_files(&spec.capture_files, stdout_limit);
            cleanup_temp_paths(&spec.temp_paths);
            let captured_files = captured_files?;
            Ok(AvRunnerOutput {
                stdout,
                stderr,
                killed: !status.success(),
                timed_out: false,
                cleaned_temp_paths: spec.temp_paths.clone(),
                captured_files,
            })
        }
    }
}

fn cleanup_temp_paths(paths: &[PathBuf]) {
    for path in paths {
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_dir_all(path);
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
    cleaned: Mutex<Vec<PathBuf>>,
    staged_inputs: Mutex<Vec<Vec<u8>>>,
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
                cleaned: Mutex::new(Vec::new()),
                staged_inputs: Mutex::new(Vec::new()),
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
}

impl Default for FakeAvArgvRunner {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl AvArgvRunner for FakeAvArgvRunner {
    async fn run(&self, spec: &ProcessSpec, cancel: &CancellationToken) -> Result<AvRunnerOutput> {
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
        self.inner
            .calls
            .lock()
            .expect("calls lock")
            .push(RecordedAvRun {
                program: spec.program.to_string(),
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
        if cancel.is_cancelled() || *self.inner.force_cancel.lock().expect("cancel lock") {
            cleanup_recorded(self, spec);
            bail!("cancelled");
        }
        if *self.inner.force_timeout.lock().expect("timeout lock") {
            cleanup_recorded(self, spec);
            bail!("deadline_exceeded");
        }
        if *self.inner.corrupt.lock().expect("corrupt lock") {
            cleanup_recorded(self, spec);
            return Ok(AvRunnerOutput {
                stdout: b"{not json".to_vec(),
                stderr: b"invalid_media".to_vec(),
                killed: false,
                timed_out: false,
                cleaned_temp_paths: spec.temp_paths.clone(),
                captured_files: Vec::new(),
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
                captured_files: Vec::new(),
            });
        }
        let stdout = self
            .inner
            .stdout_by_program
            .lock()
            .expect("stdout lock")
            .get(spec.program)
            .cloned()
            .unwrap_or_else(default_stdout_for);
        let stderr = self
            .inner
            .stderr_by_program
            .lock()
            .expect("stderr lock")
            .get(spec.program)
            .cloned()
            .unwrap_or_default();
        if stdout.len() > spec.stdout_limit || stderr.len() > spec.stderr_limit {
            cleanup_recorded(self, spec);
            bail!("resource_limit");
        }
        cleanup_recorded(self, spec);
        let captured_files = spec
            .capture_files
            .iter()
            .cloned()
            .map(|path| (path, stdout.clone()))
            .collect();
        Ok(AvRunnerOutput {
            stdout,
            stderr,
            killed: false,
            timed_out: false,
            cleaned_temp_paths: spec.temp_paths.clone(),
            captured_files,
        })
    }
}

fn cleanup_recorded(runner: &FakeAvArgvRunner, spec: &ProcessSpec) {
    runner
        .inner
        .cleaned
        .lock()
        .expect("cleaned lock")
        .extend(spec.temp_paths.iter().cloned());
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

/// Write retained bytes to a private temp path for file-based argv.
pub fn write_private_temp(bytes: &[u8], suffix: &str) -> Result<PathBuf> {
    if bytes.is_empty() || bytes.len() > MAX_PROCESS_STDOUT_BYTES {
        bail!("resource_limit");
    }
    let dir = tempfile::Builder::new()
        .prefix("cockpit-av-")
        .tempdir()?
        .keep();
    let path = dir.join(format!("source{suffix}"));
    std::fs::write(&path, bytes)?;
    Ok(path)
}

pub fn private_output_path(suffix: &str) -> Result<(PathBuf, PathBuf)> {
    let dir = tempfile::Builder::new()
        .prefix("cockpit-av-")
        .tempdir()?
        .keep();
    Ok((dir.join(format!("derivative.{suffix}")), dir))
}

fn capture_files(paths: &[PathBuf], limit: usize) -> Result<Vec<(PathBuf, Vec<u8>)>> {
    paths
        .iter()
        .map(|path| {
            use std::io::Read as _;

            let file = std::fs::File::open(path)
                .map_err(|_| anyhow::anyhow!("media_derivative_missing"))?;
            let declared = file
                .metadata()
                .map_err(|_| anyhow::anyhow!("media_derivative_missing"))?
                .len();
            if declared == 0 || declared > limit as u64 {
                bail!("resource_limit");
            }
            let mut bytes = Vec::with_capacity(declared as usize);
            file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
            if bytes.is_empty() || bytes.len() > limit {
                bail!("resource_limit");
            }
            Ok((path.clone(), bytes))
        })
        .collect()
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
            held.take(MAX_PROCESS_STDOUT_BYTES as u64 + 1)
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
