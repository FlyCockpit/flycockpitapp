use anyhow::Result;

use crate::cli::MetaArgs;

pub async fn run(_args: MetaArgs) -> Result<()> {
    // GOALS §6 (reconciled by implementation note): the
    // *external-harness invocation mechanism* now lives in-session as the
    // `harness_list` / `harness_invoke` tools (granted to the `Build` /
    // `Plan` primaries), backed by the `crate::harness` engine and the
    // cockpit-native `harnesses` config block. Any primary agent can
    // already delegate work to another harness from a normal `cockpit tui`
    // session — there is no separate orchestrator entry point to enter.
    //
    // The `cockpit meta` subcommand remains reserved for the broader
    // orchestrator surface still on the roadmap (ralph plan management,
    // recursive `cockpit` subagents); that piece is not built yet.
    anyhow::bail!(
        "external harnesses are invoked in-session via the `harness_list` / `harness_invoke` \
         tools (configure them in /settings → Harnesses); the standalone `cockpit meta` \
         orchestrator is still on the roadmap (see the design notes §6)"
    )
}
