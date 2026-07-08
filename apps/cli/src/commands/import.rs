use anyhow::Result;

use crate::cli::ImportArgs;

pub async fn run(_args: ImportArgs) -> Result<()> {
    // File path only — opencode also accepts share URLs, but cockpit doesn't
    // do hosted sharing (see the design notes non-goals).
    anyhow::bail!("cockpit import is not implemented yet (planned; JSON file only)")
}
