use anyhow::Result;

use crate::cli::{ProviderAddArgs, ProvidersCommand, ProvidersUsageArgs};

pub async fn run(cmd: ProvidersCommand) -> Result<()> {
    match cmd {
        ProvidersCommand::List => {
            // No provider ships an interactive login flow today; all
            // providers are configured via /settings → Providers + `$VAR`
            // refs in header values.
            println!("API-key providers (configure via the TUI's /settings):");
            for t in crate::providers::TEMPLATES {
                if matches!(t.auth, crate::config::providers::AuthKind::ApiKey) {
                    println!("  {} — {}", t.id, t.display);
                }
            }
            Ok(())
        }
        ProvidersCommand::Add(args) => add(args).await,
        ProvidersCommand::Usage(args) => usage(args).await,
    }
}

async fn add(args: ProviderAddArgs) -> Result<()> {
    crate::commands::setup::run_provider_add(args.template).await
}

async fn usage(args: ProvidersUsageArgs) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let cfg = crate::secret_ref::load_effective(&cwd);
    let rows =
        crate::providers::usage::probes::fetch_all_provider_usage(&cfg, args.provider.as_deref())
            .await?;
    for (idx, row) in rows.iter().enumerate() {
        if idx > 0 {
            println!();
        }
        for line in crate::providers::usage::render_usage_lines(row) {
            println!("{line}");
        }
    }
    Ok(())
}
