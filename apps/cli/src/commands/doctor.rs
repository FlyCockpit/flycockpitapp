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
    if args.dependencies_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&snapshot.dependencies)
                .map_err(|error| DoctorCouldNotRun(anyhow::Error::new(error)))?
        );
    } else {
        print!("{}", crate::diagnostics::render(&snapshot));
    }
    let failed = if args.dependencies_json {
        snapshot.dependencies.has_required_failures()
    } else {
        snapshot.has_failures
    };
    if failed {
        return Err(DoctorChecksFailed.into());
    }
    Ok(())
}
