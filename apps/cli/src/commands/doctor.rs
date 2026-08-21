//! `cockpit doctor` diagnostics snapshot.
//!
//! The daemon owns the diagnostics snapshot (`GetDoctorSnapshot`), assembling
//! it against the store it owns. When no persistent daemon is running, this
//! command uses a private ephemeral daemon and reaps it after the snapshot.
//! The
//! `--dependencies-json` view reports the host dependency projection, which is
//! a filesystem/binary probe (like `RefreshHostCapabilities`) that opens no
//! SQLite; it is computed locally because the snapshot RPC returns only the
//! rendered text plus the failure flag.

use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, Result};
use serde::Deserialize;
use tokio::io::AsyncReadExt as _;
use tokio::process::{ChildStdout, Command};

#[derive(Debug, thiserror::Error)]
#[error("doctor checks failed")]
pub struct DoctorChecksFailed;

#[derive(Debug, thiserror::Error)]
#[error("doctor itself could not run: {0:#}")]
pub struct DoctorCouldNotRun(#[source] pub anyhow::Error);

use crate::cli::DoctorArgs;
use crate::daemon::client::{LifecycleMode, probe_or_spawn};
use crate::daemon::ephemeral_guard::EphemeralDaemonGuard;
use crate::daemon::proto::{Request, Response};

const DIAGNOSTIC_SNAPSHOT_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_DIAGNOSTIC_SNAPSHOT_BYTES: usize = 1024 * 1024;

/// The private worker's deliberately small, bounded wire contract. It is not
/// a public CLI API: `doctor` is the only caller and retains responsibility for
/// rendering and exit-code semantics.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DiagnosticSnapshotWorkerOutput {
    rendered: String,
    has_failures: bool,
    database_bootstrap_failure: bool,
}

pub async fn run(args: DoctorArgs, no_sandbox: bool) -> Result<()> {
    if args.dependencies_json {
        return dependencies_json(&args, no_sandbox).await;
    }

    // `probe_or_spawn` attaches to a persistent daemon when one is available,
    // otherwise it starts an isolated ephemeral daemon. Only the latter can
    // need the one-shot worker: never replace a failure to contact a live
    // daemon with an unrelated local diagnostic.
    let ephemeral_boot_attempted = !matches!(
        crate::daemon::discover().await.status,
        crate::daemon::DaemonStatus::Running
            | crate::daemon::DaemonStatus::IncompatibleProtocol
            | crate::daemon::DaemonStatus::LivePidSocketUnreachable
            | crate::daemon::DaemonStatus::UnverifiedPid
    );
    let daemon = match probe_or_spawn(LifecycleMode::AttachOrEphemeral).await {
        Ok(daemon) => daemon,
        Err(daemon_error) if ephemeral_boot_attempted => {
            return recover_ephemeral_database_boot_failure(&args, no_sandbox, daemon_error).await;
        }
        Err(daemon_error) => return Err(DoctorCouldNotRun(daemon_error).into()),
    };
    // A diagnostic-only invocation must never auto-promote a persistent
    // daemon. The guard owns only a daemon this command spawned, and reaps it
    // on every return path after the socket RPC has been attempted.
    let guard = daemon
        .owns_daemon
        .then(|| EphemeralDaemonGuard::new(daemon.socket.clone()));
    let response = daemon
        .client
        .request(build_doctor_request(&args, no_sandbox))
        .await
        .map_err(DoctorCouldNotRun)?
        .map_err(|error| {
            DoctorCouldNotRun(anyhow::anyhow!("daemon rejected doctor snapshot: {error}"))
        });
    if let Some(guard) = &guard {
        guard.shutdown();
    }
    let Response::DoctorSnapshot {
        rendered,
        has_failures,
    } = response?
    else {
        return Err(DoctorCouldNotRun(anyhow::anyhow!(
            "daemon returned unexpected response to doctor snapshot"
        ))
        .into());
    };
    finish_snapshot(rendered, has_failures)
}

/// Preserve normal daemon-RPC ownership, but make a failed database bootstrap
/// actionable. The subprocess uses the same executable and configuration
/// context, yet does not start the normal daemon server, so it can inspect and
/// report a database that prevented that server from booting. Any other worker
/// failure or classification returns the original daemon error unchanged.
async fn recover_ephemeral_database_boot_failure(
    args: &DoctorArgs,
    no_sandbox: bool,
    daemon_error: anyhow::Error,
) -> Result<()> {
    let worker = match diagnostic_snapshot_worker(args, no_sandbox).await {
        Ok(worker) => worker,
        Err(_) => return Err(DoctorCouldNotRun(daemon_error).into()),
    };
    if !worker.database_bootstrap_failure {
        return Err(DoctorCouldNotRun(daemon_error).into());
    }
    finish_snapshot(worker.rendered, worker.has_failures)
}

fn finish_snapshot(rendered: String, has_failures: bool) -> Result<()> {
    print!("{rendered}");
    if has_failures {
        return Err(DoctorChecksFailed.into());
    }
    Ok(())
}

/// Run the hidden daemon-owned worker with a bounded stdout contract. Stderr
/// is intentionally discarded: forwarding an internal bootstrap error could
/// expose credential-bearing configuration text, while the worker's rendered
/// snapshot is designed to be secret-free.
async fn diagnostic_snapshot_worker(
    args: &DoctorArgs,
    no_sandbox: bool,
) -> anyhow::Result<DiagnosticSnapshotWorkerOutput> {
    let executable = std::env::current_exe().context("locating cockpit executable")?;
    let mut command = Command::new(executable);
    command
        .arg("daemon")
        .arg("diagnostic-snapshot")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    if let Some(path) = &args.path {
        command.arg("--path").arg(path);
    }
    if args.offline {
        command.arg("--offline");
    }
    if no_sandbox {
        command.arg("--no-sandbox");
    }

    let mut child = command
        .spawn()
        .context("starting diagnostic snapshot worker")?;
    let stdout = child
        .stdout
        .take()
        .context("diagnostic snapshot worker stdout was not captured")?;
    let completed = tokio::time::timeout(DIAGNOSTIC_SNAPSHOT_TIMEOUT, async {
        tokio::try_join!(read_bounded_stdout(stdout), async {
            Ok::<_, anyhow::Error>(child.wait().await?)
        },)
    })
    .await;
    let (stdout, status) = match completed {
        Ok(result) => result?,
        Err(_) => {
            let _ = child.kill().await;
            anyhow::bail!("diagnostic snapshot worker timed out")
        }
    };
    if !status.success() {
        anyhow::bail!("diagnostic snapshot worker exited unsuccessfully")
    }
    serde_json::from_slice(&stdout).context("parsing diagnostic snapshot worker output")
}

async fn read_bounded_stdout(mut stdout: ChildStdout) -> anyhow::Result<Vec<u8>> {
    let mut output = Vec::new();
    let mut chunk = [0_u8; 8192];
    loop {
        let read = stdout.read(&mut chunk).await?;
        if read == 0 {
            return Ok(output);
        }
        let new_len = output
            .len()
            .checked_add(read)
            .context("diagnostic snapshot worker output length overflow")?;
        if new_len > MAX_DIAGNOSTIC_SNAPSHOT_BYTES {
            anyhow::bail!("diagnostic snapshot worker output exceeded its size limit")
        }
        output.extend_from_slice(&chunk[..read]);
    }
}

/// Assemble the daemon request for the default doctor snapshot. Extracted so
/// the exact path/sandbox/offline inputs remain covered without opening a DB
/// from the CLI process.
fn build_doctor_request(args: &DoctorArgs, no_sandbox: bool) -> Request {
    Request::GetDoctorSnapshot {
        project_root: args.path.as_ref().map(|path| path.display().to_string()),
        no_sandbox,
        offline: args.offline,
    }
}

async fn dependencies_json(args: &DoctorArgs, no_sandbox: bool) -> Result<()> {
    let cwd = match &args.path {
        Some(path) => path.clone(),
        None => std::env::current_dir().map_err(|error| DoctorCouldNotRun(error.into()))?,
    };
    // The projection probe blocks (bounded by its own deadline); run it off the
    // async worker so it never stalls the reactor.
    let dependencies = tokio::task::spawn_blocking(move || {
        crate::diagnostics::dependency_projection_with_deadline_for_run(
            cwd,
            Duration::from_secs(2),
            !no_sandbox,
        )
    })
    .await
    .map_err(|error| DoctorCouldNotRun(anyhow::Error::new(error)))?
    .map_err(DoctorCouldNotRun)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&dependencies)
            .map_err(|error| DoctorCouldNotRun(anyhow::Error::new(error)))?
    );
    if dependencies.has_required_failures() {
        return Err(DoctorChecksFailed.into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn build_doctor_request_targets_daemon_snapshot_with_args() {
        let args = DoctorArgs {
            path: Some(PathBuf::from("/w/project")),
            offline: true,
            dependencies_json: false,
        };
        let Request::GetDoctorSnapshot {
            project_root,
            no_sandbox,
            offline,
        } = build_doctor_request(&args, true)
        else {
            panic!("doctor default path must request GetDoctorSnapshot");
        };
        assert_eq!(project_root.as_deref(), Some("/w/project"));
        assert!(no_sandbox);
        assert!(offline);
    }

    #[test]
    fn build_doctor_request_omits_project_root_when_unset() {
        let args = DoctorArgs {
            path: None,
            offline: false,
            dependencies_json: false,
        };
        let Request::GetDoctorSnapshot {
            project_root,
            no_sandbox,
            offline,
        } = build_doctor_request(&args, false)
        else {
            panic!("doctor default path must request GetDoctorSnapshot");
        };
        assert!(project_root.is_none());
        assert!(!no_sandbox);
        assert!(!offline);
    }
}
