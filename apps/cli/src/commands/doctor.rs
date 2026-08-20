//! `cockpit doctor` diagnostics snapshot.
//!
//! The daemon owns the diagnostics snapshot (`GetDoctorSnapshot`), assembling
//! it against the store it owns so the CLI never opens SQLite. The
//! `--dependencies-json` view reports the host dependency projection, which is
//! a filesystem/binary probe (like `RefreshHostCapabilities`) that opens no
//! SQLite; it is computed locally because the snapshot RPC returns only the
//! rendered text plus the failure flag.

use std::time::Duration;

use anyhow::Result;

#[derive(Debug, thiserror::Error)]
#[error("doctor checks failed")]
pub struct DoctorChecksFailed;

#[derive(Debug, thiserror::Error)]
#[error("doctor itself could not run: {0:#}")]
pub struct DoctorCouldNotRun(#[source] pub anyhow::Error);

use crate::cli::DoctorArgs;
use crate::daemon::client::ensure_persistent_daemon;
use crate::daemon::proto::{Request, Response};

pub async fn run(args: DoctorArgs, no_sandbox: bool) -> Result<()> {
    if args.dependencies_json {
        return dependencies_json(&args, no_sandbox).await;
    }

    let daemon = ensure_persistent_daemon()
        .await
        .map_err(DoctorCouldNotRun)?;
    let response = daemon
        .client
        .request(build_doctor_request(&args, no_sandbox))
        .await
        .map_err(DoctorCouldNotRun)?
        .map_err(|error| {
            DoctorCouldNotRun(anyhow::anyhow!("daemon rejected doctor snapshot: {error}"))
        })?;
    let Response::DoctorSnapshot {
        rendered,
        has_failures,
    } = response
    else {
        return Err(DoctorCouldNotRun(anyhow::anyhow!(
            "daemon returned unexpected response to doctor snapshot"
        ))
        .into());
    };
    print!("{rendered}");
    if has_failures {
        return Err(DoctorChecksFailed.into());
    }
    Ok(())
}

/// Assemble the daemon request for the default doctor snapshot. Extracted so
/// the real request the command sends can be unit-tested without a live daemon.
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
        // Drives the real request-builder the command calls: the default path
        // assembles a `GetDoctorSnapshot` (daemon-owned, no in-process SQLite)
        // carrying the path/sandbox/offline flags the user passed.
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
