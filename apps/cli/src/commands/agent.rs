use anyhow::Result;

use crate::cli::AgentCommand;

pub async fn run(_cmd: AgentCommand) -> Result<()> {
    // `cockpit agent create` and `cockpit agent list`. List walks cockpit's
    // standard locations plus extended-config `agent_dirs`.
    anyhow::bail!("cockpit agent is not implemented yet")
}
