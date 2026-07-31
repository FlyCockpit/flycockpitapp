//! `cockpit doctor` diagnostics snapshot.

use anyhow::Result;

#[derive(Debug, thiserror::Error)]
#[error("doctor checks failed")]
pub struct DoctorChecksFailed;

#[derive(Debug, thiserror::Error)]
#[error("doctor itself could not run: {0:#}")]
pub struct DoctorCouldNotRun(#[source] pub anyhow::Error);

use crate::cli::DoctorArgs;

pub async fn run(args: DoctorArgs, no_sandbox: bool) -> Result<()> {
    let snapshot = crate::diagnostics::cli_snapshot(args.path.as_deref(), no_sandbox, args.offline)
        .await
        .map_err(DoctorCouldNotRun)?;
    print!("{}", crate::diagnostics::render(&snapshot));
    if snapshot.has_failures {
        return Err(DoctorChecksFailed.into());
    }
    Ok(())
}
