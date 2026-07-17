//! `cockpit doctor` diagnostics snapshot.

use anyhow::Result;

use crate::cli::DoctorArgs;

pub async fn run(args: DoctorArgs, no_sandbox: bool) -> Result<()> {
    let snapshot =
        crate::diagnostics::cli_snapshot(args.path.as_deref(), no_sandbox, args.offline).await?;
    print!("{}", crate::diagnostics::render(&snapshot));
    if snapshot.has_failures {
        anyhow::bail!("doctor checks failed");
    }
    Ok(())
}
