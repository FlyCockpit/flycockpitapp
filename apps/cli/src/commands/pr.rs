use anyhow::Result;

use crate::cli::PrArgs;

pub async fn run(_args: PrArgs) -> Result<()> {
    // Wraps `gh pr checkout` and then launches the cockpit TUI in the
    // resulting worktree.
    anyhow::bail!(
        "cockpit pr is not implemented yet (planned: wrapper around `gh pr checkout` + TUI launch)"
    )
}
