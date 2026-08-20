//! Daemon-only resolution of command-backed named secrets.
//!
//! A command-backed named secret stores a **spec** (an argv vector) as vault
//! metadata. Its *resolved* value — the trimmed stdout of running that argv —
//! is a secret that lives ONLY in this daemon-process cache. The resolved
//! output is never written to SQLite, a file, a log, or a wire response. It is
//! surfaced only by injecting it into the in-memory redaction table and into a
//! session-local credential view whose `$secret:` header expansion produces a
//! redacted outbound provider header.
//!
//! Invariants enforced here (see `command-backed-secret-refs-daemon`):
//! - Execution is `tokio::process::Command::new(argv[0]).args(argv[1..])`,
//!   NEVER `sh -c`. Stdin is null. A fixed 30s timeout (not configurable).
//! - Stdout is capped at 8 KiB, stderr at 4 KiB. Crossing either bound kills
//!   and reaps the child PROMPTLY (it does not wait for the other pipe or the
//!   timeout) and yields a sanitized `output_too_large` / `stderr_too_large`
//!   status carrying NO payload bytes.
//! - Only the trailing `\n` / `\r\n` is trimmed from stdout; interior bytes are
//!   preserved verbatim.
//! - The executor is an injectable seam so tests never spawn a real process
//!   unless they explicitly opt into the unix real-script path.
//! - The cache is single-flight per name: N concurrent resolves of one name
//!   invoke the executor exactly once and every waiter observes the same
//!   completion. A sync lookup NEVER executes — an unresolved name is missing.
//! - Invalidation generation-fences an in-flight resolve: a completion from a
//!   superseded flight is discarded and can never overwrite a newer value.
//!
//! This module contains ZERO provider-specific preset strings: a preset that
//! maps a product toggle to a concrete argv lives in the UI layer, never here.

use std::collections::HashMap;
use std::process::Stdio;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::io::AsyncReadExt;
use tokio::sync::OnceCell;

/// Fixed subprocess timeout. Not configurable by design: a credential command
/// that hangs must never wedge a session indefinitely.
pub const COMMAND_SECRET_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
/// Hard cap on captured stdout. Crossing it is a sanitized failure with no
/// payload bytes retained.
pub const COMMAND_SECRET_STDOUT_CAP: usize = 8 * 1024;
/// Hard cap on captured stderr.
pub const COMMAND_SECRET_STDERR_CAP: usize = 4 * 1024;
/// Upper bound on the sanitized stderr excerpt attached to a non-zero exit.
const STDERR_EXCERPT_CHARS: usize = 200;

/// A distinct, sanitized reason a command-secret resolution failed. Carries no
/// resolved-output bytes. Rendered as a stable code so it can appear in an
/// inventory / test-resolve response without leaking the token or the raw
/// stderr payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandSecretError {
    /// `argv[0]` could not be spawned (not found / not executable).
    NotFound,
    /// Child exited non-zero. Carries a sanitized, truncated stderr excerpt
    /// (control characters stripped) — never the resolved token (that is
    /// stdout, which is discarded on failure).
    NonZeroExit {
        code: Option<i32>,
        stderr_excerpt: String,
    },
    /// Child exited zero but produced no output after trimming.
    EmptyOutput,
    /// Child did not complete within [`COMMAND_SECRET_TIMEOUT`].
    Timeout,
    /// Stdout exceeded [`COMMAND_SECRET_STDOUT_CAP`]; the child was killed and
    /// reaped and NO output bytes are retained.
    OutputTooLarge,
    /// Stderr exceeded [`COMMAND_SECRET_STDERR_CAP`]; the child was killed and
    /// reaped and NO stderr bytes are retained.
    StderrTooLarge,
    /// The spec was empty (no argv). A well-formed spec always has a program.
    EmptySpec,
    /// An I/O error while spawning or reaping the child. The message is a
    /// static `io::ErrorKind` label, never a path or payload.
    Io(String),
}

impl CommandSecretError {
    /// Stable machine code. Safe to log / return over the wire.
    pub fn code(&self) -> &'static str {
        match self {
            Self::NotFound => "not_found",
            Self::NonZeroExit { .. } => "non_zero_exit",
            Self::EmptyOutput => "empty_output",
            Self::Timeout => "timeout",
            Self::OutputTooLarge => "output_too_large",
            Self::StderrTooLarge => "stderr_too_large",
            Self::EmptySpec => "empty_spec",
            Self::Io(_) => "io_error",
        }
    }
}

impl std::fmt::Display for CommandSecretError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NonZeroExit {
                code,
                stderr_excerpt,
            } => {
                if stderr_excerpt.is_empty() {
                    write!(f, "command exited with status {code:?}")
                } else {
                    write!(f, "command exited with status {code:?}: {stderr_excerpt}")
                }
            }
            Self::Io(kind) => write!(f, "command i/o error ({kind})"),
            other => f.write_str(other.code()),
        }
    }
}

/// The outcome of a resolution attempt held in the cache. `Resolved` carries a
/// secret, so this type deliberately does NOT derive `Debug`/`Display`: its
/// manual `Debug` redacts the value, and there is no `Display`. Nothing here is
/// ever serialized, logged, or returned — the value is only injected into the
/// redaction table and the session-local secret view.
pub enum CommandResolution {
    Resolved(String),
    Failed(CommandSecretError),
}

impl CommandResolution {
    pub fn is_resolved(&self) -> bool {
        matches!(self, Self::Resolved(_))
    }

    /// Sanitized status code (never the value).
    pub fn status_code(&self) -> &'static str {
        match self {
            Self::Resolved(_) => "resolved",
            Self::Failed(error) => error.code(),
        }
    }

    /// A sanitized, value-free status snapshot for inventory / test-resolve.
    pub fn status(&self) -> CommandResolutionStatus {
        match self {
            Self::Resolved(_) => CommandResolutionStatus::Resolved,
            Self::Failed(error) => CommandResolutionStatus::Failed(error.clone()),
        }
    }
}

impl std::fmt::Debug for CommandResolution {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // NEVER print the resolved value: a stray `{:?}`, panic, or test
        // diagnostic must not leak the token.
        match self {
            Self::Resolved(_) => f.write_str("CommandResolution::Resolved(<redacted>)"),
            Self::Failed(error) => f
                .debug_tuple("CommandResolution::Failed")
                .field(error)
                .finish(),
        }
    }
}

/// Injectable execution seam. The production implementation spawns a real
/// subprocess; tests inject a counting fake so no test ever spawns a process
/// unless it explicitly uses [`SubprocessCommandExecutor`].
#[async_trait::async_trait]
pub trait CommandSecretExecutor: Send + Sync {
    /// Run `argv` and return the trimmed stdout on success, or a sanitized
    /// error. Implementations MUST enforce the stdin-null / timeout / caps
    /// contract and MUST NOT shell out through `sh -c`.
    async fn run(&self, argv: &[String]) -> Result<String, CommandSecretError>;
}

/// Production executor: `tokio::process::Command` with the full safety
/// contract.
#[derive(Debug, Default, Clone)]
pub struct SubprocessCommandExecutor;

#[async_trait::async_trait]
impl CommandSecretExecutor for SubprocessCommandExecutor {
    async fn run(&self, argv: &[String]) -> Result<String, CommandSecretError> {
        run_subprocess(argv).await
    }
}

async fn run_subprocess(argv: &[String]) -> Result<String, CommandSecretError> {
    run_subprocess_inner(argv, COMMAND_SECRET_TIMEOUT).await
}

/// The subprocess runner with an injectable timeout. Production always uses the
/// fixed [`COMMAND_SECRET_TIMEOUT`] via [`run_subprocess`]; the timeout param
/// exists ONLY so a test can exercise the hang path without waiting 30s. It is
/// not exposed as a configurable knob.
async fn run_subprocess_inner(
    argv: &[String],
    timeout: std::time::Duration,
) -> Result<String, CommandSecretError> {
    let (program, rest) = argv.split_first().ok_or(CommandSecretError::EmptySpec)?;

    let mut command = tokio::process::Command::new(program);
    command
        .args(rest)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    let mut child = match command.spawn() {
        Ok(child) => child,
        // NotFound (missing argv[0]) and PermissionDenied (non-executable
        // argv[0]) both read as "cannot run this program"; fold both into
        // NotFound so callers get one "cannot spawn" signal without a path.
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied
            ) =>
        {
            return Err(CommandSecretError::NotFound);
        }
        Err(error) => return Err(CommandSecretError::Io(io_kind_label(error.kind()))),
    };

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| CommandSecretError::Io("stdout_unavailable".to_string()))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| CommandSecretError::Io("stderr_unavailable".to_string()))?;

    // Drain both pipes in independent tasks and RACE them: the first task to
    // cross its cap (or error) short-circuits so we can kill+reap immediately
    // instead of waiting for the other pipe's EOF or the 30s timeout.
    let mut out_task = tokio::spawn(read_capped_owned(stdout, COMMAND_SECRET_STDOUT_CAP));
    let mut err_task = tokio::spawn(read_capped_owned(stderr, COMMAND_SECRET_STDERR_CAP));

    let deadline = tokio::time::Instant::now() + timeout;

    // Either both pipes drained to (stdout, stderr), or a cap/IO error short-circuited.
    type DrainedStreams = Result<(Vec<u8>, Vec<u8>), CommandSecretError>;
    let drained: Result<DrainedStreams, _> = tokio::time::timeout_at(deadline, async {
        let mut out_bytes: Option<Vec<u8>> = None;
        let mut err_bytes: Option<Vec<u8>> = None;
        loop {
            tokio::select! {
                res = &mut out_task, if out_bytes.is_none() => match res {
                    Ok(DrainOutcome::Ok(bytes)) => out_bytes = Some(bytes),
                    Ok(DrainOutcome::Overflow) => {
                        return Err(CommandSecretError::OutputTooLarge);
                    }
                    Ok(DrainOutcome::Io(kind)) => return Err(CommandSecretError::Io(kind)),
                    Err(_join) => {
                        return Err(CommandSecretError::Io("stdout_drain_panicked".to_string()));
                    }
                },
                res = &mut err_task, if err_bytes.is_none() => match res {
                    Ok(DrainOutcome::Ok(bytes)) => err_bytes = Some(bytes),
                    Ok(DrainOutcome::Overflow) => {
                        return Err(CommandSecretError::StderrTooLarge);
                    }
                    Ok(DrainOutcome::Io(kind)) => return Err(CommandSecretError::Io(kind)),
                    Err(_join) => {
                        return Err(CommandSecretError::Io("stderr_drain_panicked".to_string()));
                    }
                },
            }
            if out_bytes.is_some() && err_bytes.is_some() {
                return Ok((out_bytes.take().unwrap(), err_bytes.take().unwrap()));
            }
        }
    })
    .await;

    let (out_bytes, err_bytes) = match drained {
        Ok(Ok(pair)) => pair,
        Ok(Err(cap_or_io)) => {
            // A cap was crossed (or a drain errored): kill+reap NOW and return
            // the distinct error. The abandoned drain task ends on its own once
            // the killed child closes its pipe.
            kill_and_reap(&mut child).await;
            return Err(cap_or_io);
        }
        Err(_elapsed) => {
            kill_and_reap(&mut child).await;
            return Err(CommandSecretError::Timeout);
        }
    };

    // Both pipes hit EOF within cap: the child has closed its streams. Reap it
    // under the same deadline.
    let status = match tokio::time::timeout_at(deadline, child.wait()).await {
        Ok(Ok(status)) => status,
        Ok(Err(error)) => return Err(CommandSecretError::Io(io_kind_label(error.kind()))),
        Err(_elapsed) => {
            kill_and_reap(&mut child).await;
            return Err(CommandSecretError::Timeout);
        }
    };

    if !status.success() {
        return Err(CommandSecretError::NonZeroExit {
            code: status.code(),
            stderr_excerpt: sanitize_stderr(&err_bytes),
        });
    }

    let value = String::from_utf8(trim_trailing_newline(&out_bytes))
        .map_err(|_| CommandSecretError::Io("output_not_utf8".to_string()))?;
    if value.is_empty() {
        return Err(CommandSecretError::EmptyOutput);
    }
    Ok(value)
}

/// The outcome of draining one capped pipe. On `Overflow` no bytes are
/// returned — the payload is discarded so a cap error is byte-free.
enum DrainOutcome {
    Ok(Vec<u8>),
    Overflow,
    Io(String),
}

/// Read from an owned `reader` until EOF or until strictly more than `cap`
/// bytes have been read. Each read is bounded to the remaining capacity plus
/// one, so the buffer never grows past `cap + 1`; on overflow it is dropped
/// entirely.
async fn read_capped_owned<R>(mut reader: R, cap: usize) -> DrainOutcome
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        // Invariant at the top of the loop: buf.len() <= cap.
        let want = (cap - buf.len()) + 1;
        let to_read = want.min(chunk.len());
        let n = match reader.read(&mut chunk[..to_read]).await {
            Ok(n) => n,
            Err(error) => return DrainOutcome::Io(io_kind_label(error.kind())),
        };
        if n == 0 {
            return DrainOutcome::Ok(buf);
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > cap {
            return DrainOutcome::Overflow;
        }
    }
}

async fn kill_and_reap(child: &mut tokio::process::Child) {
    let _ = child.start_kill();
    let _ = child.wait().await;
}

fn io_kind_label(kind: std::io::ErrorKind) -> String {
    // A stable label, never a path or payload.
    format!("{kind:?}")
}

/// Strip exactly one trailing `\n` or `\r\n` (decision: "multi-line stdout
/// minus trailing newlines is the value"). Interior newlines are preserved.
fn trim_trailing_newline(bytes: &[u8]) -> Vec<u8> {
    let mut end = bytes.len();
    if end > 0 && bytes[end - 1] == b'\n' {
        end -= 1;
        if end > 0 && bytes[end - 1] == b'\r' {
            end -= 1;
        }
    }
    bytes[..end].to_vec()
}

/// Produce a bounded, control-character-stripped excerpt of stderr for a
/// non-zero exit. This is the command's own diagnostic text (not the token,
/// which is stdout and is discarded on failure), sanitized so it is safe to
/// surface at a redacted trace or a test-resolve error.
fn sanitize_stderr(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    let cleaned: String = text
        .chars()
        .map(|ch| if ch.is_control() { ' ' } else { ch })
        .collect();
    let trimmed = cleaned.trim();
    if trimmed.chars().count() > STDERR_EXCERPT_CHARS {
        let truncated: String = trimmed.chars().take(STDERR_EXCERPT_CHARS).collect();
        format!("{truncated}…")
    } else {
        trimmed.to_string()
    }
}

type ResolutionCell = Arc<OnceCell<Arc<CommandResolution>>>;

/// One name's cache slot: a single-flight cell plus a generation counter that
/// [`CommandSecretCache::invalidate`] bumps so a superseded in-flight resolve
/// can be discarded.
struct CacheEntry {
    generation: u64,
    cell: ResolutionCell,
}

/// Daemon-process cache of resolved command-backed secrets, single-flight per
/// name. Owned as an `Arc` and shared across sessions and the daemon-startup /
/// provider-update resolution paths.
pub struct CommandSecretCache {
    executor: Arc<dyn CommandSecretExecutor>,
    entries: Mutex<HashMap<String, CacheEntry>>,
    exec_count: AtomicUsize,
}

impl std::fmt::Debug for CommandSecretCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print resolved values.
        f.debug_struct("CommandSecretCache")
            .field("exec_count", &self.exec_count.load(Ordering::SeqCst))
            .finish_non_exhaustive()
    }
}

impl CommandSecretCache {
    pub fn new(executor: Arc<dyn CommandSecretExecutor>) -> Arc<Self> {
        Arc::new(Self {
            executor,
            entries: Mutex::new(HashMap::new()),
            exec_count: AtomicUsize::new(0),
        })
    }

    /// Production cache backed by the real subprocess executor.
    pub fn with_subprocess_executor() -> Arc<Self> {
        Self::new(Arc::new(SubprocessCommandExecutor))
    }

    /// Number of times the executor has actually been invoked. Test
    /// observability for single-flight / invalidation assertions.
    pub fn exec_count(&self) -> usize {
        self.exec_count.load(Ordering::SeqCst)
    }

    fn cell_for(&self, name: &str) -> (u64, ResolutionCell) {
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let entry = entries
            .entry(name.to_string())
            .or_insert_with(|| CacheEntry {
                generation: 0,
                cell: Arc::new(OnceCell::new()),
            });
        (entry.generation, Arc::clone(&entry.cell))
    }

    fn generation(&self, name: &str) -> Option<u64> {
        let entries = self
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        entries.get(name).map(|entry| entry.generation)
    }

    /// Resolve `name` from `argv`, executing at most once across all concurrent
    /// callers. Waiters share the first completion. If the flight is superseded
    /// by an [`invalidate`](Self::invalidate) mid-resolution, its result is
    /// discarded and the resolve retries against the current cell, so a stale
    /// value can never be returned to a caller (or injected downstream).
    pub async fn ensure_resolved(&self, name: &str, argv: &[String]) -> Arc<CommandResolution> {
        loop {
            let (generation, cell) = self.cell_for(name);
            let resolution = cell
                .get_or_init(|| async {
                    self.exec_count.fetch_add(1, Ordering::SeqCst);
                    let outcome = match self.executor.run(argv).await {
                        Ok(value) => CommandResolution::Resolved(value),
                        Err(error) => CommandResolution::Failed(error),
                    };
                    Arc::new(outcome)
                })
                .await;
            if self.generation(name) == Some(generation) {
                return Arc::clone(resolution);
            }
            // Superseded: a concurrent invalidate installed a fresh cell. Loop
            // and resolve against it; this flight's value is discarded.
        }
    }

    /// Synchronous, execution-free lookup of a previously resolved output. An
    /// unresolved (or failed) name returns `None` — this is the seam the sync
    /// `$secret:` header expansion uses, and it MUST NEVER execute.
    pub fn resolved_output(&self, name: &str) -> Option<String> {
        let cell = self.current_cell(name)?;
        match cell.get()?.as_ref() {
            CommandResolution::Resolved(value) => Some(value.clone()),
            CommandResolution::Failed(_) => None,
        }
    }

    /// Current sanitized status for `name`: `None` when never attempted, else a
    /// completed status. Never carries the value.
    pub fn status(&self, name: &str) -> Option<CommandResolutionStatus> {
        let cell = self.current_cell(name)?;
        cell.get().map(|resolution| resolution.status())
    }

    fn current_cell(&self, name: &str) -> Option<ResolutionCell> {
        let entries = self
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        entries.get(name).map(|entry| Arc::clone(&entry.cell))
    }

    /// Drop any cached resolution (in-flight or complete) for `name`, so the
    /// next [`ensure_resolved`](Self::ensure_resolved) re-executes. Bumps the
    /// name's generation and installs a fresh cell, generation-fencing any
    /// in-flight resolve so its completion is discarded. Used on provider/secret
    /// update and on a credentials-rejected rebuild.
    pub fn invalidate(&self, name: &str) {
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(entry) = entries.get_mut(name) {
            entry.generation += 1;
            entry.cell = Arc::new(OnceCell::new());
        }
    }

    /// Run `argv` once, out of band from the cache, returning only a sanitized
    /// status. Used by the owner test-resolve RPC: it proves resolvability
    /// without ever caching or returning the token.
    pub async fn test_resolve(&self, argv: &[String]) -> CommandResolutionStatus {
        self.exec_count.fetch_add(1, Ordering::SeqCst);
        match self.executor.run(argv).await {
            Ok(_value) => CommandResolutionStatus::Resolved,
            Err(error) => CommandResolutionStatus::Failed(error),
        }
    }
}

/// A resolution status stripped of any value bytes. Safe to place in an
/// inventory row or a test-resolve response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandResolutionStatus {
    Resolved,
    Failed(CommandSecretError),
}

impl CommandResolutionStatus {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Resolved => "resolved",
            Self::Failed(error) => error.code(),
        }
    }

    pub fn is_resolved(&self) -> bool {
        matches!(self, Self::Resolved)
    }

    /// A sanitized human message for a failure (never the token).
    pub fn message(&self) -> Option<String> {
        match self {
            Self::Resolved => None,
            Self::Failed(error) => Some(error.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::oneshot;

    /// Counting fake: records every invocation and returns a canned outcome
    /// immediately.
    struct FakeExecutor {
        outcome: Result<String, CommandSecretError>,
        calls: AtomicUsize,
    }

    impl FakeExecutor {
        fn ok(value: &str) -> Arc<Self> {
            Arc::new(Self {
                outcome: Ok(value.to_string()),
                calls: AtomicUsize::new(0),
            })
        }

        fn failing(error: CommandSecretError) -> Arc<Self> {
            Arc::new(Self {
                outcome: Err(error),
                calls: AtomicUsize::new(0),
            })
        }
    }

    #[async_trait::async_trait]
    impl CommandSecretExecutor for FakeExecutor {
        async fn run(&self, _argv: &[String]) -> Result<String, CommandSecretError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.outcome.clone()
        }
    }

    /// Blocks the FIRST invocation until released, so a single-flight test can
    /// observe that only one caller entered the executor WHILE the rest are
    /// still contending on the shared in-flight cell.
    struct BlockingFake {
        value: String,
        calls: Arc<AtomicUsize>,
        entered_tx: Mutex<Option<oneshot::Sender<()>>>,
        release_rx: Mutex<Option<oneshot::Receiver<()>>>,
    }

    #[async_trait::async_trait]
    impl CommandSecretExecutor for BlockingFake {
        async fn run(&self, _argv: &[String]) -> Result<String, CommandSecretError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if let Some(tx) = self.entered_tx.lock().unwrap().take() {
                let _ = tx.send(());
            }
            let rx = self.release_rx.lock().unwrap().take();
            if let Some(rx) = rx {
                let _ = rx.await;
            }
            Ok(self.value.clone())
        }
    }

    /// Returns values by call order; blocks ONLY the first call until released.
    struct SequencedExecutor {
        values: Vec<String>,
        next: AtomicUsize,
        entered_first_tx: Mutex<Option<oneshot::Sender<()>>>,
        release_first_rx: Mutex<Option<oneshot::Receiver<()>>>,
    }

    #[async_trait::async_trait]
    impl CommandSecretExecutor for SequencedExecutor {
        async fn run(&self, _argv: &[String]) -> Result<String, CommandSecretError> {
            let index = self.next.fetch_add(1, Ordering::SeqCst);
            if index == 0 {
                if let Some(tx) = self.entered_first_tx.lock().unwrap().take() {
                    let _ = tx.send(());
                }
                let rx = self.release_first_rx.lock().unwrap().take();
                if let Some(rx) = rx {
                    let _ = rx.await;
                }
            }
            Ok(self
                .values
                .get(index)
                .cloned()
                .unwrap_or_else(|| "unexpected-extra-call".to_string()))
        }
    }

    #[test]
    fn trims_only_trailing_newline() {
        assert_eq!(trim_trailing_newline(b"token\n"), b"token");
        assert_eq!(trim_trailing_newline(b"token\r\n"), b"token");
        assert_eq!(trim_trailing_newline(b"a\nb\n"), b"a\nb");
        assert_eq!(trim_trailing_newline(b"token\n\n"), b"token\n");
        assert_eq!(trim_trailing_newline(b"token"), b"token");
    }

    #[test]
    fn sanitize_stderr_strips_control_and_bounds() {
        let excerpt = sanitize_stderr(b"boom\n\x07danger\ttab");
        assert!(!excerpt.contains('\n'));
        assert!(!excerpt.contains('\x07'));
        assert!(excerpt.contains("boom"));
        let long = vec![b'x'; 10_000];
        let bounded = sanitize_stderr(&long);
        assert!(bounded.chars().count() <= STDERR_EXCERPT_CHARS + 1);
    }

    #[test]
    fn resolved_debug_does_not_leak_token() {
        let token = "sk-super-secret-value-should-not-print-123456";
        let resolution = CommandResolution::Resolved(token.to_string());
        let rendered = format!("{resolution:?}");
        assert!(
            !rendered.contains(token),
            "Debug leaked the token: {rendered}"
        );
        assert!(rendered.contains("redacted"));
        // A failure's Debug is fine (sanitized error, no token).
        let failed = CommandResolution::Failed(CommandSecretError::Timeout);
        assert!(format!("{failed:?}").contains("Timeout"));
    }

    #[tokio::test]
    async fn single_flight_shares_one_in_flight_execution() {
        // The single flight BLOCKS in the executor; while it is blocked we prove
        // only one caller entered, then release and confirm all share it.
        let calls = Arc::new(AtomicUsize::new(0));
        let (entered_tx, entered_rx) = oneshot::channel();
        let (release_tx, release_rx) = oneshot::channel();
        let fake = Arc::new(BlockingFake {
            value: "shared-token".to_string(),
            calls: calls.clone(),
            entered_tx: Mutex::new(Some(entered_tx)),
            release_rx: Mutex::new(Some(release_rx)),
        });
        let cache = CommandSecretCache::new(fake);
        let argv = vec!["prog".to_string()];

        let mut handles = Vec::new();
        for _ in 0..16 {
            let cache = cache.clone();
            let argv = argv.clone();
            handles.push(tokio::spawn(async move {
                cache.ensure_resolved("shared", &argv).await
            }));
        }

        // Wait until the single in-flight resolve has entered the executor.
        entered_rx.await.unwrap();
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "only one caller may enter the executor while 16 contend on one name"
        );

        release_tx.send(()).unwrap();
        for handle in handles {
            let resolution = handle.await.unwrap();
            match resolution.as_ref() {
                CommandResolution::Resolved(value) => assert_eq!(value, "shared-token"),
                other => panic!("expected resolved, got {other:?}"),
            }
        }
        assert_eq!(
            cache.exec_count(),
            1,
            "single-flight must exec exactly once"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn invalidate_forces_reexecution() {
        let executor = FakeExecutor::ok("v");
        let cache = CommandSecretCache::new(executor);
        let argv = vec!["prog".to_string()];
        cache.ensure_resolved("n", &argv).await;
        cache.ensure_resolved("n", &argv).await;
        assert_eq!(cache.exec_count(), 1, "a cached name must not re-exec");
        cache.invalidate("n");
        cache.ensure_resolved("n", &argv).await;
        assert_eq!(cache.exec_count(), 2, "invalidate must force one re-exec");
    }

    #[tokio::test]
    async fn superseded_flight_never_overwrites_post_invalidate_value() {
        // Flight A enters and blocks. We invalidate while A is in flight, then
        // let flight B resolve "fresh". When A is released it must NOT reinstate
        // "stale": it is generation-fenced, so it discards its result and
        // re-resolves to the current "fresh".
        let (entered_tx, entered_rx) = oneshot::channel();
        let (release_tx, release_rx) = oneshot::channel();
        let executor = Arc::new(SequencedExecutor {
            values: vec!["stale".to_string(), "fresh".to_string()],
            next: AtomicUsize::new(0),
            entered_first_tx: Mutex::new(Some(entered_tx)),
            release_first_rx: Mutex::new(Some(release_rx)),
        });
        let cache = CommandSecretCache::new(executor);
        let argv = vec!["prog".to_string()];

        let flight_a = {
            let cache = cache.clone();
            let argv = argv.clone();
            tokio::spawn(async move { cache.ensure_resolved("n", &argv).await })
        };

        // Wait until flight A (call 0) has entered the executor and is blocked.
        entered_rx.await.unwrap();
        // Supersede it, then resolve a fresh value with flight B (call 1).
        cache.invalidate("n");
        let b = cache.ensure_resolved("n", &argv).await;
        assert!(matches!(b.as_ref(), CommandResolution::Resolved(v) if v == "fresh"));
        assert_eq!(cache.resolved_output("n").as_deref(), Some("fresh"));

        // Release the superseded flight A; it must not overwrite "fresh".
        release_tx.send(()).unwrap();
        let a = flight_a.await.unwrap();
        assert!(
            matches!(a.as_ref(), CommandResolution::Resolved(v) if v == "fresh"),
            "a superseded flight must re-resolve to the current value, not the stale one"
        );
        assert_eq!(
            cache.resolved_output("n").as_deref(),
            Some("fresh"),
            "a superseded flight must never overwrite the post-invalidate value"
        );
        assert_eq!(cache.exec_count(), 2);
    }

    #[tokio::test]
    async fn failed_resolution_is_cached_until_invalidation() {
        let executor = FakeExecutor::failing(CommandSecretError::NotFound);
        let cache = CommandSecretCache::new(executor);
        let argv = vec!["prog".to_string()];
        cache.ensure_resolved("n", &argv).await;
        cache.ensure_resolved("n", &argv).await;
        assert_eq!(cache.exec_count(), 1, "a cached failure must not re-exec");
        assert_eq!(cache.resolved_output("n"), None);
        assert!(matches!(
            cache.status("n"),
            Some(CommandResolutionStatus::Failed(
                CommandSecretError::NotFound
            ))
        ));
        cache.invalidate("n");
        cache.ensure_resolved("n", &argv).await;
        assert_eq!(
            cache.exec_count(),
            2,
            "invalidate must re-exec a failed name"
        );
    }

    #[tokio::test]
    async fn sync_lookup_never_executes() {
        let executor = FakeExecutor::ok("v");
        let cache = CommandSecretCache::new(executor);
        assert_eq!(cache.resolved_output("n"), None);
        assert_eq!(cache.status("n"), None);
        assert_eq!(cache.exec_count(), 0, "a sync lookup must never exec");
    }

    #[cfg(unix)]
    fn write_script(dir: &std::path::Path, name: &str, body: &str) -> String {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join(name);
        std::fs::write(&path, body).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path.to_string_lossy().into_owned()
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn unix_real_script_resolution_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let argv = vec![write_script(
            dir.path(),
            "emit-token.sh",
            "#!/bin/sh\nprintf 'real-secret-token\\n'\n",
        )];
        let value = run_subprocess(&argv).await.unwrap();
        assert_eq!(value, "real-secret-token");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn unix_stdout_over_cap_is_output_too_large() {
        let dir = tempfile::tempdir().unwrap();
        let argv = vec![write_script(
            dir.path(),
            "flood.sh",
            "#!/bin/sh\nhead -c 9000 /dev/zero | tr '\\0' 'A'\n",
        )];
        assert_eq!(
            run_subprocess(&argv).await.unwrap_err(),
            CommandSecretError::OutputTooLarge
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn unix_stderr_over_cap_on_nonzero_is_stderr_too_large() {
        let dir = tempfile::tempdir().unwrap();
        let argv = vec![write_script(
            dir.path(),
            "fail-loud.sh",
            "#!/bin/sh\nhead -c 5000 /dev/zero | tr '\\0' 'E' 1>&2\nexit 3\n",
        )];
        assert_eq!(
            run_subprocess(&argv).await.unwrap_err(),
            CommandSecretError::StderrTooLarge
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn unix_stdout_over_cap_kills_promptly_while_stderr_held_open() {
        // >8 KiB stdout, then the child SLEEPS holding stderr open. The old
        // join-both drain would wait for stderr EOF / the 30s timeout; the race
        // must kill+reap and return OutputTooLarge well under the timeout.
        let dir = tempfile::tempdir().unwrap();
        let argv = vec![write_script(
            dir.path(),
            "flood-then-hang.sh",
            "#!/bin/sh\nhead -c 9000 /dev/zero | tr '\\0' 'A'\nsleep 60\n",
        )];
        let start = std::time::Instant::now();
        assert_eq!(
            run_subprocess(&argv).await.unwrap_err(),
            CommandSecretError::OutputTooLarge
        );
        assert!(
            start.elapsed() < std::time::Duration::from_secs(10),
            "cap overflow must kill promptly, not wait for the 30s timeout"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn unix_stderr_over_cap_kills_promptly_while_stdout_held_open() {
        let dir = tempfile::tempdir().unwrap();
        let argv = vec![write_script(
            dir.path(),
            "errflood-then-hang.sh",
            "#!/bin/sh\nhead -c 5000 /dev/zero | tr '\\0' 'E' 1>&2\nsleep 60\n",
        )];
        let start = std::time::Instant::now();
        assert_eq!(
            run_subprocess(&argv).await.unwrap_err(),
            CommandSecretError::StderrTooLarge
        );
        assert!(
            start.elapsed() < std::time::Duration::from_secs(10),
            "stderr cap overflow must kill promptly"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn unix_hang_times_out_and_reaps() {
        // A child that never exits must time out (with a short injected timeout
        // so the test does not wait 30s) and be reaped.
        let dir = tempfile::tempdir().unwrap();
        let argv = vec![write_script(dir.path(), "hang.sh", "#!/bin/sh\nsleep 60\n")];
        let start = std::time::Instant::now();
        let error = run_subprocess_inner(&argv, std::time::Duration::from_millis(300))
            .await
            .unwrap_err();
        assert_eq!(error, CommandSecretError::Timeout);
        assert!(
            start.elapsed() < std::time::Duration::from_secs(10),
            "a hung child must time out promptly at the injected deadline"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn unix_nonzero_exit_carries_sanitized_stderr_not_stdout() {
        let dir = tempfile::tempdir().unwrap();
        let argv = vec![write_script(
            dir.path(),
            "fail.sh",
            "#!/bin/sh\nprintf 'SECRET-STDOUT'\nprintf 'diagnostic-line\\n' 1>&2\nexit 7\n",
        )];
        match run_subprocess(&argv).await.unwrap_err() {
            CommandSecretError::NonZeroExit {
                code,
                stderr_excerpt,
            } => {
                assert_eq!(code, Some(7));
                assert!(stderr_excerpt.contains("diagnostic-line"));
                assert!(
                    !stderr_excerpt.contains("SECRET-STDOUT"),
                    "stdout (the token) must never appear in the error"
                );
            }
            other => panic!("expected non-zero exit, got {other:?}"),
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn unix_empty_output_is_distinct() {
        let dir = tempfile::tempdir().unwrap();
        let argv = vec![write_script(
            dir.path(),
            "empty.sh",
            "#!/bin/sh\nprintf '\\n'\n",
        )];
        assert_eq!(
            run_subprocess(&argv).await.unwrap_err(),
            CommandSecretError::EmptyOutput
        );
    }

    #[tokio::test]
    async fn missing_program_is_not_found() {
        let argv = vec!["definitely-not-a-real-program-xyzzy".to_string()];
        assert_eq!(
            run_subprocess(&argv).await.unwrap_err(),
            CommandSecretError::NotFound
        );
    }

    #[tokio::test]
    async fn empty_spec_is_rejected() {
        assert_eq!(
            run_subprocess(&[]).await.unwrap_err(),
            CommandSecretError::EmptySpec
        );
    }

    #[tokio::test]
    async fn read_capped_owned_enforces_the_boundary() {
        use std::io::Cursor;
        // Exactly `cap` bytes fits and is returned.
        match read_capped_owned(Cursor::new(vec![b'x'; 100]), 100).await {
            DrainOutcome::Ok(bytes) => assert_eq!(bytes.len(), 100),
            DrainOutcome::Overflow => panic!("exactly cap must not overflow"),
            DrainOutcome::Io(kind) => panic!("unexpected io error: {kind}"),
        }
        // `cap + 1` overflows and retains no payload.
        assert!(matches!(
            read_capped_owned(Cursor::new(vec![b'x'; 101]), 100).await,
            DrainOutcome::Overflow
        ));
        // A huge input still stops at the boundary — the buffer is bounded to
        // cap + 1 regardless of how much the source holds.
        assert!(matches!(
            read_capped_owned(Cursor::new(vec![b'x'; 1_000_000]), 100).await,
            DrainOutcome::Overflow
        ));
    }
}
