//! Spawn a harness subprocess and drain both pipes concurrently with a
//! bounded tail, honoring a wall-clock timeout.
//!
//! Concurrency is the whole point: a child that writes more than the pipe
//! buffer (~64 KiB) blocks on `write(2)` while the parent blocks on
//! `wait()`, deadlocking. We spawn drain tasks for stdout and stderr
//! *before* waiting, so the pipes keep flowing. Each drainer keeps only a
//! bounded byte tail ([`HARNESS_OUTPUT_TAIL_BYTES`]) — a runaway harness
//! can't blow out memory.

use std::path::Path;

use anyhow::{Context, Result};
use tempfile::NamedTempFile;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

use super::prepare::PromptDelivery;

/// Bounded byte tail kept per stream. 256 KiB is generous for diagnostics
/// while bounding a runaway harness's output; the structured-result path
/// further caps what reaches the model.
pub const HARNESS_OUTPUT_TAIL_BYTES: usize = crate::process::CHILD_PIPE_CAPTURE_BYTES;

/// Captured output of one harness invocation.
#[derive(Debug, Clone)]
pub struct HarnessOutput {
    /// Stdout tail (UTF-8 lossy, bounded).
    pub stdout: String,
    /// Stderr tail (UTF-8 lossy, bounded).
    pub stderr: String,
    /// Process exit code, or `None` when killed by a signal.
    pub exit_code: Option<i32>,
}

/// The terminal outcome of a spawn: the child completed (with output), or
/// the timeout elapsed and we killed it (best-effort output still
/// captured).
#[derive(Debug)]
pub enum RunOutcome {
    /// The child exited on its own. `success` is `exit_code == Some(0)`.
    Completed {
        output: HarnessOutput,
        success: bool,
    },
    /// The timeout elapsed; the child (and its process group on Unix) was
    /// killed. Partial output captured before the kill is included.
    TimedOut { output: HarnessOutput },
}

/// Spawn `command args` in `cwd` with the given env additions and
/// [`PromptDelivery`] side-channel, drain both pipes concurrently with a
/// bounded tail, and wait up to `timeout`. On Unix the child runs in its
/// own process group so a timeout kill reaches grandchildren.
pub async fn run_to_completion(
    command: &str,
    args: &[String],
    env: &[(String, String)],
    cwd: &Path,
    delivery: PromptDelivery,
    timeout: std::time::Duration,
) -> Result<RunOutcome> {
    let mut cmd = Command::new(command);
    cmd.args(args)
        .current_dir(cwd)
        .env_clear()
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        // A dropped Child reaps the subprocess rather than orphaning it
        // (defense-in-depth: every path here reaches wait()).
        .kill_on_drop(true);

    match &delivery {
        PromptDelivery::Stdin(_) => {
            cmd.stdin(std::process::Stdio::piped());
        }
        PromptDelivery::Argv | PromptDelivery::TempFile(_) => {
            cmd.stdin(std::process::Stdio::null());
        }
    }

    for (k, v) in env {
        cmd.env(k, v);
    }

    // Unix-only: own process group so the timeout kill fans out to any
    // grandchildren the harness spawned. Gated behind cfg per the
    // cross-platform requirement.
    #[cfg(unix)]
    {
        cmd.process_group(0);
    }

    let mut child = cmd
        .spawn()
        .with_context(|| format!("spawning harness `{command}`"))?;

    // The TempFile handle must outlive the child (its path is in argv).
    let _tempfile_guard: Option<NamedTempFile> = match delivery {
        PromptDelivery::Stdin(bytes) => {
            if let Some(mut stdin) = child.stdin.take() {
                // Tolerate BrokenPipe: a harness that ignores stdin or
                // exits early closes the pipe before we finish writing —
                // legitimate, not a failure.
                if let Err(e) = stdin.write_all(&bytes).await
                    && e.kind() != std::io::ErrorKind::BrokenPipe
                {
                    return Err(anyhow::Error::new(e).context("writing prompt to child stdin"));
                }
                if let Err(e) = stdin.shutdown().await
                    && e.kind() != std::io::ErrorKind::BrokenPipe
                {
                    return Err(anyhow::Error::new(e).context("closing child stdin"));
                }
            }
            None
        }
        PromptDelivery::TempFile(tmp) => Some(tmp),
        PromptDelivery::Argv => None,
    };

    // Spawn the concurrent drainers immediately.
    let stdout_task =
        crate::process::spawn_bounded_pipe_drain(child.stdout.take(), 0, HARNESS_OUTPUT_TAIL_BYTES);
    let stderr_task =
        crate::process::spawn_bounded_pipe_drain(child.stderr.take(), 0, HARNESS_OUTPUT_TAIL_BYTES);

    tokio::select! {
        status = child.wait() => {
            let status = status.context("waiting for harness child")?;
            let stdout = stdout_task.join_lossy().await;
            let stderr = stderr_task.join_lossy().await;
            let success = status.success();
            Ok(RunOutcome::Completed {
                output: HarnessOutput { stdout, stderr, exit_code: status.code() },
                success,
            })
        }
        _ = tokio::time::sleep(timeout) => {
            let child_pid = child.id();
            crate::process::terminate_group_async(
                &mut child,
                child_pid,
                std::time::Duration::from_millis(200),
            )
            .await;
            let stdout = stdout_task.join_lossy().await;
            let stderr = stderr_task.join_lossy().await;
            Ok(RunOutcome::TimedOut {
                output: HarnessOutput { stdout, stderr, exit_code: None },
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn captures_stdout_and_exit_zero() {
        let out = run_to_completion(
            "sh",
            &["-c".to_string(), "printf 'hello'".to_string()],
            &[],
            std::env::temp_dir().as_path(),
            PromptDelivery::Argv,
            Duration::from_secs(10),
        )
        .await
        .unwrap();
        match out {
            RunOutcome::Completed { output, success } => {
                assert!(success);
                assert_eq!(output.exit_code, Some(0));
                assert_eq!(output.stdout, "hello");
            }
            other => panic!("expected completed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn nonzero_exit_is_failure() {
        let out = run_to_completion(
            "sh",
            &["-c".to_string(), "exit 3".to_string()],
            &[],
            std::env::temp_dir().as_path(),
            PromptDelivery::Argv,
            Duration::from_secs(10),
        )
        .await
        .unwrap();
        match out {
            RunOutcome::Completed { output, success } => {
                assert!(!success);
                assert_eq!(output.exit_code, Some(3));
            }
            other => panic!("expected completed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn stdin_delivery_reaches_child() {
        let out = run_to_completion(
            "cat",
            &[],
            &[],
            std::env::temp_dir().as_path(),
            PromptDelivery::Stdin(b"piped body".to_vec()),
            Duration::from_secs(10),
        )
        .await
        .unwrap();
        match out {
            RunOutcome::Completed { output, .. } => assert_eq!(output.stdout, "piped body"),
            other => panic!("expected completed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn timeout_kills_and_reports() {
        let out = run_to_completion(
            "sh",
            &["-c".to_string(), "sleep 30".to_string()],
            &[],
            std::env::temp_dir().as_path(),
            PromptDelivery::Argv,
            Duration::from_millis(200),
        )
        .await
        .unwrap();
        assert!(matches!(out, RunOutcome::TimedOut { .. }));
    }

    #[tokio::test]
    async fn large_output_is_bounded() {
        // Emit ~1 MB; the captured tail must be bounded and not deadlock.
        let out = run_to_completion(
            "sh",
            &[
                "-c".to_string(),
                "yes ABCDEFGH | head -c 1000000".to_string(),
            ],
            &[],
            std::env::temp_dir().as_path(),
            PromptDelivery::Argv,
            Duration::from_secs(20),
        )
        .await
        .unwrap();
        match out {
            RunOutcome::Completed { output, success } => {
                assert!(success);
                assert!(output.stdout.len() <= HARNESS_OUTPUT_TAIL_BYTES);
                assert!(!output.stdout.is_empty());
            }
            other => panic!("expected completed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn child_receives_only_curated_env() {
        let env = crate::test_env::lock_async().await;
        env.set_var("SECRET_API_KEY", "hidden");
        env.set_var("ALLOWED_AUTH_TOKEN", "visible");
        let cfg = crate::config::extended::HarnessConfig {
            command: "sh".to_string(),
            args: vec![],
            prompt_input: crate::config::extended::PromptInputMode::Stdin,
            argv_overflow: crate::config::extended::ArgvOverflowBehavior::SpillToTempfile,
            model_args: vec![],
            default_model: None,
            models: vec![],
            model_list_args: vec![],
            supports_json_output: false,
            json_output_args: vec![],
            supports_agent_file: false,
            agent_file_args: vec![],
            agent_file_env: None,
            auth_env_vars: vec!["ALLOWED_AUTH_TOKEN".to_string()],
            auth_probe_args: vec![],
            always_allow: false,
            timeout_secs: 60,
        };
        let env = crate::harness::env::harness_child_env(&cfg, None);
        let out = run_to_completion(
            "sh",
            &[
                "-c".to_string(),
                "printf 'secret=%s\\nauth=%s\\n' \"${SECRET_API_KEY-unset}\" \"$ALLOWED_AUTH_TOKEN\""
                    .to_string(),
            ],
            &env,
            std::env::temp_dir().as_path(),
            PromptDelivery::Argv,
            Duration::from_secs(10),
        )
        .await
        .unwrap();
        match out {
            RunOutcome::Completed { output, success } => {
                assert!(success);
                assert!(output.stdout.contains("secret=unset"), "{}", output.stdout);
                assert!(output.stdout.contains("auth=visible"), "{}", output.stdout);
            }
            other => panic!("expected completed, got {other:?}"),
        }
    }
}
