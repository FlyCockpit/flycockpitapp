//! Shared child-process helpers.

use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use tokio::{
    io::{AsyncRead, AsyncReadExt},
    task::JoinHandle,
};

/// Default retained bytes per child-process pipe.
pub const CHILD_PIPE_CAPTURE_BYTES: usize = 256 * 1024;
/// Head budget for command tools that need both the beginning and end of output.
pub const CHILD_PIPE_CAPTURE_HEAD_BYTES: usize = CHILD_PIPE_CAPTURE_BYTES / 2;
/// Tail budget for command tools that need both the beginning and end of output.
pub const CHILD_PIPE_CAPTURE_TAIL_BYTES: usize =
    CHILD_PIPE_CAPTURE_BYTES - CHILD_PIPE_CAPTURE_HEAD_BYTES;

const PIPE_DRAIN_CHUNK_BYTES: usize = 8 * 1024;

/// A descendant-containment boundary prepared before spawn and attached
/// before child code is allowed to execute. Unix uses a fresh process group.
/// Windows uses a pre-created kill-on-close Job Object and a suspended child,
/// then assigns the process before resuming its primary thread. Other targets
/// fail closed instead of pretending a direct-child kill contains descendants.
pub struct ProcessTreeGuard {
    #[cfg(windows)]
    job: Mutex<Option<windows_sys::Win32::Foundation::HANDLE>>,
}

// The Job Object handle is an owned kernel handle. Its operations are
// thread-safe, and this type never exposes or aliases the raw handle.
#[cfg(windows)]
unsafe impl Send for ProcessTreeGuard {}
#[cfg(windows)]
unsafe impl Sync for ProcessTreeGuard {}

impl ProcessTreeGuard {
    pub fn prepare(command: &mut tokio::process::Command) -> anyhow::Result<Self> {
        #[cfg(unix)]
        {
            command.process_group(0);
            Ok(Self {})
        }
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt as _;
            use windows_sys::Win32::System::{
                JobObjects::{
                    CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
                    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
                    SetInformationJobObject,
                },
                Threading::CREATE_SUSPENDED,
            };

            let job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
            if job.is_null() {
                return Err(std::io::Error::last_os_error().into());
            }
            let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
            limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            let configured = unsafe {
                SetInformationJobObject(
                    job,
                    JobObjectExtendedLimitInformation,
                    (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                    u32::try_from(std::mem::size_of_val(&limits)).unwrap_or(u32::MAX),
                )
            };
            if configured == 0 {
                unsafe { windows_sys::Win32::Foundation::CloseHandle(job) };
                return Err(std::io::Error::last_os_error().into());
            }
            command.as_std_mut().creation_flags(CREATE_SUSPENDED);
            Ok(Self {
                job: Mutex::new(Some(job)),
            })
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = command;
            anyhow::bail!("descendant_process_containment_unavailable")
        }
    }

    pub fn attach(&self, child: &tokio::process::Child) -> anyhow::Result<()> {
        #[cfg(unix)]
        {
            let _ = child;
            Ok(())
        }
        #[cfg(windows)]
        {
            use windows_sys::Win32::{
                Foundation::{CloseHandle, INVALID_HANDLE_VALUE},
                System::{
                    Diagnostics::ToolHelp::{
                        CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First,
                        Thread32Next,
                    },
                    JobObjects::AssignProcessToJobObject,
                    Threading::{OpenThread, ResumeThread, THREAD_SUSPEND_RESUME},
                },
            };

            let pid = child
                .id()
                .ok_or_else(|| anyhow::anyhow!("child identity missing"))?;
            let process = child
                .raw_handle()
                .ok_or_else(|| anyhow::anyhow!("child process handle missing"))?
                as windows_sys::Win32::Foundation::HANDLE;
            let job = self
                .job
                .lock()
                .map_err(|_| anyhow::anyhow!("process tree job lock poisoned"))?
                .ok_or_else(|| anyhow::anyhow!("process tree job already closed"))?;
            if unsafe { AssignProcessToJobObject(job, process) } == 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
            if snapshot == INVALID_HANDLE_VALUE {
                return Err(std::io::Error::last_os_error().into());
            }
            let mut entry: THREADENTRY32 = unsafe { std::mem::zeroed() };
            entry.dwSize = u32::try_from(std::mem::size_of::<THREADENTRY32>()).unwrap_or(u32::MAX);
            let mut found = None;
            let mut more = unsafe { Thread32First(snapshot, &mut entry) } != 0;
            while more {
                if entry.th32OwnerProcessID == pid {
                    found = Some(entry.th32ThreadID);
                    break;
                }
                more = unsafe { Thread32Next(snapshot, &mut entry) } != 0;
            }
            unsafe { CloseHandle(snapshot) };
            let thread_id = found.ok_or_else(|| anyhow::anyhow!("child thread missing"))?;
            let thread = unsafe { OpenThread(THREAD_SUSPEND_RESUME, 0, thread_id) };
            if thread.is_null() {
                return Err(std::io::Error::last_os_error().into());
            }
            let resumed = unsafe { ResumeThread(thread) };
            unsafe { CloseHandle(thread) };
            if resumed == u32::MAX {
                return Err(std::io::Error::last_os_error().into());
            }
            Ok(())
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = child;
            anyhow::bail!("descendant_process_containment_unavailable")
        }
    }

    pub fn terminate(&self) -> anyhow::Result<()> {
        #[cfg(windows)]
        {
            let job = self
                .job
                .lock()
                .map_err(|_| anyhow::anyhow!("process tree job lock poisoned"))?
                .ok_or_else(|| anyhow::anyhow!("process tree job already closed"))?;
            if unsafe { windows_sys::Win32::System::JobObjects::TerminateJobObject(job, 1) } == 0 {
                return Err(std::io::Error::last_os_error().into());
            }
        }
        Ok(())
    }

    /// Close the owned Windows job as the kill-on-close fallback. The handle is
    /// taken exactly once so Drop cannot double-close it.
    #[cfg(windows)]
    pub fn close_job(&self) -> anyhow::Result<()> {
        let job = self
            .job
            .lock()
            .map_err(|_| anyhow::anyhow!("process tree job lock poisoned"))?
            .take();
        if let Some(job) = job
            && unsafe { windows_sys::Win32::Foundation::CloseHandle(job) } == 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(())
    }
}

/// Wait until a Unix child has exited without reaping it.
///
/// `WNOWAIT` deliberately leaves the group leader as a zombie, pinning its PID
/// and therefore the process-group identity until descendant containment has
/// been applied. The caller must subsequently reap the child.
#[cfg(unix)]
pub async fn wait_for_exit_without_reaping(pid: u32) -> std::io::Result<()> {
    let pid = libc::pid_t::try_from(pid)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid child pid"))?;
    loop {
        // `siginfo_t` must not survive to the await below: on Darwin it carries
        // an `si_addr: *mut c_void`, which would make this future non-Send and
        // break every `#[async_trait]` caller. Confine it to this block so it is
        // dropped before the suspension point.
        let exited = {
            let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
            // SAFETY: `info` points to writable initialized storage. `P_PID`
            // restricts observation to the exact child identity, and `WNOWAIT`
            // guarantees the observation cannot release that identity for reuse.
            let result = unsafe {
                libc::waitid(
                    libc::P_PID,
                    pid as libc::id_t,
                    &mut info,
                    libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                )
            };
            if result != 0 {
                return Err(std::io::Error::last_os_error());
            }
            // SAFETY: waitid initialized the SIGCHLD fields in `info`; a zero
            // PID is the specified WNOHANG result when the child has not exited.
            let observed_pid = unsafe { info.si_pid() };
            observed_pid != 0
        };
        if exited {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
}

#[cfg(windows)]
impl Drop for ProcessTreeGuard {
    fn drop(&mut self) {
        let _ = self.close_job();
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundedPipeCapture {
    pub bytes: Vec<u8>,
    pub dropped_bytes: usize,
    /// Byte length of the retained HEAD within `bytes`: `bytes[..head_len]` is the
    /// head, `bytes[head_len..]` is the tail. `head_len` lands on a char boundary
    /// of the original stream (the drainer snapped the head there), so when
    /// `dropped_bytes > 0` this is exactly the head→omitted-middle→tail junction a
    /// redaction-aware consumer must treat as a boundary. Equals `bytes.len()`
    /// when nothing was pushed to the tail (small output; no junction).
    pub head_len: usize,
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
            head_len: self.head.len(),
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
fn unix_group_signal_target(pgid: i32) -> i32 {
    -pgid
}

#[cfg(unix)]
fn signal_group(pgid: i32, sig: libc::c_int) -> std::io::Result<()> {
    // SAFETY: `libc::kill` with a negative pid signals the process
    // group; passing a valid pgid (== the leader pid, since callers set
    // `process_group(0)`) is sound.
    let rc = unsafe { libc::kill(unix_group_signal_target(pgid), sig) };
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

#[cfg(unix)]
fn group_exists(pgid: i32) -> bool {
    // SAFETY: signal 0 performs existence/permission checking only. The
    // negative pid addresses the process group created by `process_group(0)`.
    let rc = unsafe { libc::kill(unix_group_signal_target(pgid), 0) };
    rc == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

/// Terminate a caller-created Unix process group and reap its leader.
///
/// On non-Unix targets this is only a direct-child compatibility helper. Code
/// that promises descendant containment must prepare and retain a
/// [`ProcessTreeGuard`] and call its `terminate` method before reaping.
pub async fn terminate_group_async(
    child: &mut tokio::process::Child,
    pid: Option<u32>,
    grace: Duration,
) {
    let _ = terminate_group_and_reap_status_async(child, pid, grace).await;
}

/// Terminate a caller-created process group and return the reaped leader
/// status. Unix keeps the leader identity unreaped until all group signaling
/// has completed, so a recycled PID can never become a signal target.
pub async fn terminate_group_and_reap_status_async(
    child: &mut tokio::process::Child,
    pid: Option<u32>,
    grace: Duration,
) -> std::io::Result<std::process::ExitStatus> {
    #[cfg(unix)]
    {
        // Tokio clears `Child::id()` after a reap. Never use a separately
        // cached numeric PID once the child no longer proves that identity.
        let live_pid = pid
            .filter(|pid| child.id() == Some(*pid))
            .and_then(|pid| i32::try_from(pid).ok());
        if let Some(pid) = live_pid {
            match signal_group(pid, libc::SIGTERM) {
                Ok(()) => {}
                Err(error) if is_esrch(&error) => {
                    return child.wait().await;
                }
                Err(_) => {
                    let _ = child.start_kill();
                    return child.wait().await;
                }
            }
            if !grace.is_zero() {
                tokio::select! {
                    status = child.wait() => return status,
                    _ = tokio::time::sleep(grace) => {}
                }
            }
            if group_exists(pid) {
                let _ = signal_group(pid, libc::SIGKILL);
            }
        } else {
            let _ = child.kill().await;
        }
        child.wait().await
    }
    #[cfg(not(unix))]
    {
        let _ = grace;
        let _ = pid;
        let _ = child.kill().await;
        child.wait().await
    }
}

/// SIGTERM a Unix process group whose leader pid is `pgid` (spawned with
/// `process_group(0)`). Does not reap and does not require a live `Child`,
/// so a handle can group-kill after the runner task has been aborted.
/// No-op on non-Unix targets (no process groups).
pub fn terminate_process_group(pgid: u32) {
    #[cfg(unix)]
    {
        if let Ok(pid) = i32::try_from(pgid) {
            let _ = signal_group(pid, libc::SIGTERM);
        }
    }
    #[cfg(not(unix))]
    {
        let _ = pgid;
    }
}

/// SIGKILL a Unix process group whose leader pid is `pgid`. Does not reap.
/// No-op on non-Unix targets.
pub fn kill_process_group(pgid: u32) {
    #[cfg(unix)]
    {
        if let Ok(pid) = i32::try_from(pgid) {
            let _ = signal_group(pid, libc::SIGKILL);
        }
    }
    #[cfg(not(unix))]
    {
        let _ = pgid;
    }
}

/// Begin terminating a Tokio child and, on Unix, every process in the child
/// process group. This is the non-async counterpart used from `Drop` paths
/// that can finish cleanup later; callers that can await should use
/// [`terminate_group_async`] so a stubborn group also receives SIGKILL after
/// its grace period. Callers whose later `Drop` impls restore files or
/// release locks must use [`terminate_group_kill_wait`] instead so
/// descendants cannot keep mutating after this returns.
pub fn terminate_group_start(child: &mut tokio::process::Child) {
    #[cfg(unix)]
    {
        if let Some(pid) = child.id().and_then(|pid| i32::try_from(pid).ok()) {
            match signal_group(pid, libc::SIGTERM) {
                Ok(()) => return,
                Err(error) if is_esrch(&error) => return,
                Err(_) => {}
            }
        }
    }
    let _ = child.start_kill();
}

/// SIGKILL a Tokio child and, on Unix, every process in its process group,
/// then block until the group is gone or `timeout` elapses.
///
/// Drop cannot await [`terminate_group_async`]'s SIGTERM grace, and
/// [`terminate_group_start`] returns after SIGTERM without reaping. Use this
/// when the next destructor restores a tree or releases an exclusive lock:
/// `kill_on_drop` is SIGKILL of the leader PID only. Callers must spawn with
/// `process_group(0)` on Unix. Windows has no process groups; only the
/// leader is killed and waited.
pub fn terminate_group_kill_wait(child: &mut tokio::process::Child, timeout: Duration) {
    if child.try_wait().ok().flatten().is_some() {
        return;
    }
    let deadline = Instant::now() + timeout;
    #[cfg(unix)]
    {
        if let Some(pgid) = child.id().and_then(|pid| i32::try_from(pid).ok()) {
            match signal_group(pgid, libc::SIGKILL) {
                Err(error) if is_esrch(&error) => {
                    let _ = child.try_wait();
                    return;
                }
                _ => {}
            }
            while Instant::now() < deadline {
                let _ = child.try_wait();
                match signal_group(pgid, 0) {
                    Err(error) if is_esrch(&error) => return,
                    _ => std::thread::sleep(Duration::from_millis(1)),
                }
            }
        }
    }
    let _ = child.start_kill();
    while Instant::now() < deadline {
        match child.try_wait() {
            Ok(Some(_)) => return,
            Ok(None) => std::thread::sleep(Duration::from_millis(1)),
            Err(_) => return,
        }
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
        let core_src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../cockpit-core/src");
        let touched_files = [
            core_src.join("harness/spawn.rs"),
            core_src.join("tools/bash/mod.rs"),
            core_src.join("tools/custom.rs"),
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
        let mut command = tokio::process::Command::new("sh");
        command
            .arg("-c")
            .arg(script)
            .current_dir(tmp.path())
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .process_group(0);
        let mut child = command.spawn().unwrap();
        let pid = child.id();
        wait_for_file(&ready);
        wait_for_file(&heartbeat);

        terminate_group_async(&mut child, pid, Duration::from_millis(200)).await;

        tokio::time::sleep(Duration::from_millis(600)).await;
        let mtime_after_kill = std::fs::metadata(&heartbeat)
            .ok()
            .and_then(|metadata| metadata.modified().ok());
        tokio::time::sleep(Duration::from_millis(400)).await;
        let mtime_later = std::fs::metadata(&heartbeat)
            .ok()
            .and_then(|metadata| metadata.modified().ok());
        assert_eq!(
            mtime_after_kill, mtime_later,
            "descendant heartbeat kept updating after process-group termination"
        );
    }

    #[cfg(unix)]
    #[test]
    fn unix_process_tree_guard_configures_a_fresh_group_without_spawning() {
        let mut command = tokio::process::Command::new("prohibited-real-process");
        let guard = ProcessTreeGuard::prepare(&mut command);
        assert!(guard.is_ok());
        assert_eq!(unix_group_signal_target(41), -41);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn exit_observation_pins_group_identity_until_termination_reaps_leader() {
        let mut command = tokio::process::Command::new("sh");
        command
            .arg("-c")
            .arg("exit 0")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .process_group(0);
        let mut child = command.spawn().unwrap();
        let pid = child.id().unwrap();

        wait_for_exit_without_reaping(pid).await.unwrap();
        assert_eq!(child.id(), Some(pid), "exit observation must not reap");

        let status = terminate_group_and_reap_status_async(&mut child, Some(pid), Duration::ZERO)
            .await
            .unwrap();
        assert!(status.success());
        assert_eq!(child.id(), None, "termination must finish by reaping once");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn terminate_group_kill_wait_reaps_term_ignoring_descendants_before_return() {
        let tmp = tempfile::tempdir().unwrap();
        let heartbeat = tmp.path().join("heartbeat");
        let ready = tmp.path().join("ready");
        let script = format!(
            "trap '' TERM; ( trap '' TERM; while true; do touch '{}'; sleep 0.05; done ) & touch '{}'; sleep 30",
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
        wait_for_file(&ready);
        wait_for_file(&heartbeat);

        let started = std::time::Instant::now();
        terminate_group_kill_wait(&mut child, Duration::from_secs(2));
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "group SIGKILL wait should reap well under its timeout cap"
        );

        let mtime_after_kill = std::fs::metadata(&heartbeat)
            .ok()
            .and_then(|m| m.modified().ok());
        tokio::time::sleep(Duration::from_millis(200)).await;
        let mtime_later = std::fs::metadata(&heartbeat)
            .ok()
            .and_then(|m| m.modified().ok());
        assert_eq!(
            mtime_after_kill, mtime_later,
            "descendant heartbeat kept updating after terminate_group_kill_wait returned"
        );
    }
}
