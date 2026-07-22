//! Shared child-process helpers.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::task::JoinHandle;

/// Default retained bytes per child-process pipe.
pub const CHILD_PIPE_CAPTURE_BYTES: usize = 256 * 1024;
/// Head budget for command tools that need both the beginning and end of output.
pub const CHILD_PIPE_CAPTURE_HEAD_BYTES: usize = CHILD_PIPE_CAPTURE_BYTES / 2;
/// Tail budget for command tools that need both the beginning and end of output.
pub const CHILD_PIPE_CAPTURE_TAIL_BYTES: usize =
    CHILD_PIPE_CAPTURE_BYTES - CHILD_PIPE_CAPTURE_HEAD_BYTES;

const PIPE_DRAIN_CHUNK_BYTES: usize = 8 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundedPipeCapture {
    pub bytes: Vec<u8>,
    pub dropped_bytes: usize,
}

#[derive(Debug)]
pub struct BoundedPipeDrain {
    task: JoinHandle<()>,
    state: Arc<Mutex<BoundedPipeDrainState>>,
}

impl BoundedPipeDrain {
    pub fn abort(&self) {
        self.task.abort();
    }

    pub fn snapshot(&self) -> BoundedPipeCapture {
        drain_state_snapshot(&self.state)
    }

    pub async fn join(self) -> BoundedPipeCapture {
        let _ = self.task.await;
        drain_state_snapshot(&self.state)
    }

    pub async fn join_lossy(self) -> String {
        String::from_utf8_lossy(&self.join().await.bytes).into_owned()
    }
}

#[derive(Debug)]
struct BoundedPipeDrainState {
    head_bytes: usize,
    tail_bytes: usize,
    head: Vec<u8>,
    tail: Vec<u8>,
    total_read: usize,
}

impl BoundedPipeDrainState {
    fn new(head_bytes: usize, tail_bytes: usize) -> Self {
        Self {
            head_bytes,
            tail_bytes,
            head: Vec::with_capacity(head_bytes.min(PIPE_DRAIN_CHUNK_BYTES)),
            tail: Vec::with_capacity(tail_bytes.min(PIPE_DRAIN_CHUNK_BYTES)),
            total_read: 0,
        }
    }

    fn append(&mut self, bytes: &[u8]) {
        self.total_read = self.total_read.saturating_add(bytes.len());
        let mut remaining = bytes;
        if self.head.len() < self.head_bytes {
            let take = (self.head_bytes - self.head.len()).min(remaining.len());
            self.head.extend_from_slice(&remaining[..take]);
            remaining = &remaining[take..];
            if self.head.len() == self.head_bytes {
                let keep = utf8_prefix_boundary(&self.head, self.head.len());
                if keep < self.head.len() {
                    let overflow = self.head.split_off(keep);
                    self.push_tail(&overflow);
                }
            }
        }
        self.push_tail(remaining);
    }

    fn push_tail(&mut self, bytes: &[u8]) {
        if self.tail_bytes == 0 || bytes.is_empty() {
            return;
        }
        self.tail.extend_from_slice(bytes);
        if self.tail.len() > self.tail_bytes {
            let excess = self.tail.len() - self.tail_bytes;
            let cut = utf8_suffix_boundary(&self.tail, excess);
            self.tail.drain(..cut);
        }
    }

    fn snapshot(&self) -> BoundedPipeCapture {
        let mut bytes = Vec::with_capacity(self.head.len() + self.tail.len());
        bytes.extend_from_slice(&self.head);
        bytes.extend_from_slice(&self.tail);
        BoundedPipeCapture {
            dropped_bytes: self.total_read.saturating_sub(bytes.len()),
            bytes,
        }
    }
}

pub fn spawn_bounded_pipe_drain<R>(
    reader: Option<R>,
    head_bytes: usize,
    tail_bytes: usize,
) -> BoundedPipeDrain
where
    R: AsyncRead + Unpin + Send + 'static,
{
    let state = Arc::new(Mutex::new(BoundedPipeDrainState::new(
        head_bytes, tail_bytes,
    )));
    let task_state = Arc::clone(&state);
    let task = tokio::spawn(async move {
        let Some(mut reader) = reader else {
            return;
        };
        let mut chunk = [0u8; PIPE_DRAIN_CHUNK_BYTES];
        loop {
            match reader.read(&mut chunk).await {
                Ok(0) => break,
                Ok(n) => {
                    lock_drain_state(&task_state).append(&chunk[..n]);
                }
                Err(_) => break,
            }
        }
    });
    BoundedPipeDrain { task, state }
}

fn drain_state_snapshot(state: &Arc<Mutex<BoundedPipeDrainState>>) -> BoundedPipeCapture {
    lock_drain_state(state).snapshot()
}

fn lock_drain_state(
    state: &Arc<Mutex<BoundedPipeDrainState>>,
) -> std::sync::MutexGuard<'_, BoundedPipeDrainState> {
    state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn utf8_prefix_boundary(buf: &[u8], idx: usize) -> usize {
    let idx = idx.min(buf.len());
    match std::str::from_utf8(&buf[..idx]) {
        Ok(_) => idx,
        Err(error) => error.valid_up_to(),
    }
}

fn utf8_suffix_boundary(buf: &[u8], idx: usize) -> usize {
    let mut i = idx.min(buf.len());
    while i < buf.len() && (buf[i] & 0b1100_0000) == 0b1000_0000 {
        i += 1;
    }
    i
}

#[cfg(unix)]
fn signal_group(pgid: i32, sig: libc::c_int) -> std::io::Result<()> {
    // SAFETY: `libc::kill` with a negative pid signals the process
    // group; passing a valid pgid (== the leader pid, since callers set
    // `process_group(0)`) is sound.
    let rc = unsafe { libc::kill(-pgid, sig) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(unix)]
fn is_esrch(error: &std::io::Error) -> bool {
    error.raw_os_error() == Some(libc::ESRCH)
}

pub(crate) async fn terminate_group_async(
    child: &mut tokio::process::Child,
    pid: Option<u32>,
    grace: Duration,
) {
    #[cfg(unix)]
    {
        if let Some(pid) = pid.and_then(|pid| i32::try_from(pid).ok()) {
            match signal_group(pid, libc::SIGTERM) {
                Ok(()) => {}
                Err(error) if is_esrch(&error) => {
                    let _ = child.wait().await;
                    return;
                }
                Err(_) => {}
            }
            tokio::select! {
                _ = child.wait() => return,
                _ = tokio::time::sleep(grace) => {
                    let _ = signal_group(pid, libc::SIGKILL);
                }
            }
        } else {
            let _ = child.kill().await;
        }
        let _ = child.wait().await;
    }
    #[cfg(not(unix))]
    {
        let _ = grace;
        let _ = pid;
        let _ = child.kill().await;
        let _ = child.wait().await;
    }
}

pub fn terminate_group_sync(child: &mut std::process::Child, grace: Duration) {
    #[cfg(unix)]
    {
        let pgid = child.id() as i32;
        if pgid > 0 {
            match signal_group(pgid, libc::SIGTERM) {
                Ok(()) => {}
                Err(error) if is_esrch(&error) => {
                    let _ = child.wait();
                    return;
                }
                Err(_) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return;
                }
            }
            let started = std::time::Instant::now();
            while started.elapsed() < grace {
                match child.try_wait() {
                    Ok(Some(_)) => return,
                    Ok(None) => std::thread::sleep(Duration::from_millis(10).min(grace)),
                    Err(_) => break,
                }
            }
            let _ = signal_group(pgid, libc::SIGKILL);
            let _ = child.wait();
            return;
        }
    }
    #[cfg(not(unix))]
    {
        let _ = grace;
    }
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn bounded_drain_short_output_is_byte_identical_with_zero_dropped() {
        let input = b"hello\nworld\n".to_vec();

        let capture = spawn_bounded_pipe_drain(Some(std::io::Cursor::new(input.clone())), 8, 8)
            .join()
            .await;

        assert_eq!(capture.bytes, input);
        assert_eq!(capture.dropped_bytes, 0);
    }

    #[tokio::test]
    async fn bounded_drain_output_exactly_at_budget_drops_nothing() {
        let input = b"abcdefghijklmnop".to_vec();

        let capture = spawn_bounded_pipe_drain(Some(std::io::Cursor::new(input.clone())), 8, 8)
            .join()
            .await;

        assert_eq!(capture.bytes, input);
        assert_eq!(capture.dropped_bytes, 0);
    }

    #[tokio::test]
    async fn bounded_drain_keeps_head_and_tail_and_reports_exact_dropped_count() {
        let input = b"aaaabbbbccccdddd".to_vec();

        let capture = spawn_bounded_pipe_drain(Some(std::io::Cursor::new(input)), 4, 4)
            .join()
            .await;

        assert_eq!(capture.bytes, b"aaaadddd");
        assert_eq!(capture.dropped_bytes, 8);
    }

    #[tokio::test]
    async fn bounded_drain_tail_only_mode_matches_harness_semantics() {
        let input = b"0123456789abcdef".to_vec();

        let capture = spawn_bounded_pipe_drain(Some(std::io::Cursor::new(input)), 0, 6)
            .join()
            .await;

        assert_eq!(capture.bytes, b"abcdef");
        assert_eq!(capture.dropped_bytes, 10);
    }

    #[tokio::test]
    async fn bounded_drain_memory_stays_bounded_for_huge_input() {
        let input = vec![b'x'; CHILD_PIPE_CAPTURE_BYTES * 16 + 123];

        let capture = spawn_bounded_pipe_drain(
            Some(std::io::Cursor::new(input.clone())),
            CHILD_PIPE_CAPTURE_HEAD_BYTES,
            CHILD_PIPE_CAPTURE_TAIL_BYTES,
        )
        .join()
        .await;

        assert!(capture.bytes.len() <= CHILD_PIPE_CAPTURE_BYTES);
        assert_eq!(capture.dropped_bytes, input.len() - capture.bytes.len());
    }

    #[tokio::test]
    async fn bounded_drain_cuts_on_utf8_boundary_without_panic() {
        let input = "αβγδεζηθικλμ".as_bytes().to_vec();

        let capture = spawn_bounded_pipe_drain(Some(std::io::Cursor::new(input.clone())), 5, 5)
            .join()
            .await;

        assert!(std::str::from_utf8(&capture.bytes).is_ok());
        assert!(capture.bytes.len() <= 10);
        assert_eq!(capture.dropped_bytes, input.len() - capture.bytes.len());
    }

    #[tokio::test]
    async fn bounded_drain_stdout_and_stderr_budgets_are_independent() {
        let stdout =
            spawn_bounded_pipe_drain(Some(std::io::Cursor::new(b"aaaabbbb".to_vec())), 2, 2)
                .join()
                .await;
        let stderr =
            spawn_bounded_pipe_drain(Some(std::io::Cursor::new(b"ccccdddd".to_vec())), 2, 2)
                .join()
                .await;

        assert_eq!(stdout.bytes, b"aabb");
        assert_eq!(stdout.dropped_bytes, 4);
        assert_eq!(stderr.bytes, b"ccdd");
        assert_eq!(stderr.dropped_bytes, 4);
    }

    #[tokio::test]
    async fn bounded_drain_aborted_drain_returns_bytes_captured_so_far() {
        let (mut writer, reader) = tokio::io::duplex(64);
        let drain = spawn_bounded_pipe_drain(Some(reader), 8, 8);
        writer.write_all(b"partial").await.unwrap();
        for _ in 0..100 {
            if !drain.snapshot().bytes.is_empty() {
                break;
            }
            tokio::task::yield_now().await;
        }

        drain.abort();
        let capture = drain.join().await;

        assert_eq!(capture.bytes, b"partial");
        assert_eq!(capture.dropped_bytes, 0);
    }

    #[test]
    fn bounded_drain_gate_keeps_touched_child_pipe_paths_on_shared_helper() {
        let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let touched_files = [
            manifest_dir.join("src/harness/spawn.rs"),
            manifest_dir.join("src/tools/bash/mod.rs"),
            manifest_dir.join("src/tools/custom.rs"),
        ];
        let bad_read = ["read", "_to_end"].concat();
        let bad_output = [".", "output()"].concat();
        for path in touched_files {
            let source = std::fs::read_to_string(&path).unwrap();
            assert!(
                !source.contains(&bad_read),
                "{} still has an unbounded pipe read",
                path.display()
            );
            assert!(
                !source.contains(&bad_output),
                "{} still has Command::output capture",
                path.display()
            );
        }
    }

    #[cfg(unix)]
    fn wait_for_file(path: &std::path::Path) {
        let start = std::time::Instant::now();
        while !path.exists() {
            assert!(
                start.elapsed() < Duration::from_secs(3),
                "timed out waiting for {}",
                path.display()
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn terminate_group_async_kills_descendant_process_group() {
        let tmp = tempfile::tempdir().unwrap();
        let heartbeat = tmp.path().join("heartbeat");
        let ready = tmp.path().join("ready");
        let script = format!(
            "( while true; do touch '{}'; sleep 0.1; done ) & touch '{}'; sleep 30",
            heartbeat.display(),
            ready.display()
        );
        let mut cmd = tokio::process::Command::new("sh");
        cmd.arg("-c")
            .arg(script)
            .current_dir(tmp.path())
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .process_group(0);
        let mut child = cmd.spawn().unwrap();
        let pid = child.id();
        wait_for_file(&ready);
        wait_for_file(&heartbeat);

        terminate_group_async(&mut child, pid, Duration::from_millis(200)).await;

        tokio::time::sleep(Duration::from_millis(600)).await;
        let mtime_after_kill = std::fs::metadata(&heartbeat)
            .ok()
            .and_then(|m| m.modified().ok());
        tokio::time::sleep(Duration::from_millis(400)).await;
        let mtime_later = std::fs::metadata(&heartbeat)
            .ok()
            .and_then(|m| m.modified().ok());
        assert_eq!(
            mtime_after_kill, mtime_later,
            "descendant heartbeat kept updating after process-group termination"
        );
    }
}
