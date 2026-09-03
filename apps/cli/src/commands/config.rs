use anyhow::{Context, Result};

#[cfg(feature = "extended")]
use crate::cli::ImageSpendArgs;
use crate::cli::{
    ConfigCommand, ConfigExportPolicyArgs, ConfigHistoryScopeArgs, ConfigImportPolicyArgs,
};
#[cfg(feature = "extended")]
use anyhow::bail;

pub async fn run(cmd: ConfigCommand) -> Result<()> {
    match cmd {
        #[cfg(feature = "extended")]
        ConfigCommand::ImageSpend(args) => image_spend(args).await,
        ConfigCommand::ExportPolicy(args) => export_policy(args).await,
        ConfigCommand::ImportPolicy(args) => import_policy(args).await,
        ConfigCommand::HistoryScope(args) => history_scope(args).await,
    }
}

async fn history_scope(args: ConfigHistoryScopeArgs) -> Result<()> {
    // The shared canonical key: the same `project_root` wire value that
    // `trust history-scope` sends for the same workspace (issue #299).
    let project_root = super::history_scope_project_root(args.path)?;
    let daemon = crate::daemon::client::ensure_persistent_daemon()
        .await
        .context("starting persistent daemon for history scope")?;
    let client = daemon.client;
    let current = client
        .request(crate::daemon::proto::Request::GetWorkspaceHistoryScope {
            project_root: project_root.clone(),
        })
        .await?
        .map_err(|error| anyhow::anyhow!("daemon rejected history scope read: {error}"))?;
    let crate::daemon::proto::Response::WorkspaceHistoryScope {
        mut outbound,
        mut inbound,
    } = current
    else {
        anyhow::bail!("daemon returned unexpected history scope response: {current:?}");
    };
    let changed = args.outbound.is_some() || args.inbound.is_some();
    if let Some(value) = args.outbound {
        outbound = value;
    }
    if let Some(value) = args.inbound {
        inbound = value;
    }
    if changed {
        let saved = client
            .request(crate::daemon::proto::Request::SetWorkspaceHistoryScope {
                project_root,
                outbound,
                inbound,
            })
            .await?
            .map_err(|error| anyhow::anyhow!("daemon rejected history scope save: {error}"))?;
        if !matches!(
            saved,
            crate::daemon::proto::Response::WorkspaceHistoryScope { .. }
        ) {
            anyhow::bail!("daemon returned unexpected history scope save response: {saved:?}");
        }
    }
    println!("outbound: {outbound}\ninbound: {inbound}");
    Ok(())
}

#[cfg(feature = "extended")]
async fn image_spend(args: ImageSpendArgs) -> Result<()> {
    let project_key = args
        .project_key
        .context("--project-key is required to read or save image spend policy")?;
    let daemon = crate::daemon::client::ensure_persistent_daemon()
        .await
        .context("starting persistent daemon for image spend policy")?;
    if let Some(file) = args.save {
        let raw = std::fs::read_to_string(&file)
            .with_context(|| format!("reading {}", file.display()))?;
        let settings: cockpit_config::config::image_spend::ImageSpendSettings =
            serde_json::from_str(&raw).with_context(|| format!("parsing {}", file.display()))?;
        let current = daemon
            .client
            .request(crate::daemon::proto::Request::GetImageSpendPolicy {
                project_key: project_key.clone(),
            })
            .await?
            .map_err(|error| anyhow::anyhow!("daemon rejected image spend read: {error}"))?;
        let expected_policy_version = match current {
            crate::daemon::proto::Response::ImageSpendPolicy { policy_version, .. } => {
                policy_version
            }
            other => bail!("daemon returned unexpected image spend response: {other:?}"),
        };
        let saved = daemon
            .client
            .request(crate::daemon::proto::Request::SaveImageSpendPolicy {
                client_operation_id: uuid::Uuid::now_v7().to_string(),
                project_key,
                settings_json: serde_json::to_string(&settings)?,
                expected_policy_version,
            })
            .await?
            .map_err(|error| anyhow::anyhow!("daemon rejected image spend save: {error}"))?;
        let crate::daemon::proto::Response::ImageSpendPolicySaved {
            result_policy_version: policy_version,
            ..
        } = saved
        else {
            bail!("daemon returned unexpected image spend save response: {saved:?}");
        };
        println!("saved image spend policy version {policy_version}");
        return Ok(());
    }
    let response = daemon
        .client
        .request(crate::daemon::proto::Request::GetImageSpendPolicy { project_key })
        .await?
        .map_err(|error| anyhow::anyhow!("daemon rejected image spend read: {error}"))?;
    let crate::daemon::proto::Response::ImageSpendPolicy { settings, .. } = response else {
        bail!("daemon returned unexpected image spend response: {response:?}");
    };
    let settings = settings.unwrap_or_default();
    println!("{}", serde_json::to_string_pretty(&settings)?);
    if let Err(reason) = settings.validate() {
        println!(
            "paid image dispatch blocked: {reason:?}; review and save request, session, project, and project-window settings"
        );
    }
    Ok(())
}

async fn export_policy(args: ConfigExportPolicyArgs) -> Result<()> {
    let cwd = std::env::current_dir().context("resolving current directory")?;
    let daemon = crate::daemon::client::ensure_persistent_daemon()
        .await
        .context("starting persistent daemon for policy export")?;
    let response = daemon
        .client
        .request(crate::daemon::proto::Request::ExportPolicy {
            project_root: cwd.display().to_string(),
        })
        .await?
        .map_err(|error| anyhow::anyhow!("daemon rejected policy export: {error}"))?;
    let crate::daemon::proto::Response::PolicyExported { bundle_json: json } = response else {
        anyhow::bail!("daemon returned unexpected policy export response: {response:?}");
    };
    match args.output {
        Some(path) => {
            if let Some(parent) = path.parent()
                && !parent.as_os_str().is_empty()
            {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("creating {}", parent.display()))?;
            }
            std::fs::write(&path, format!("{json}\n"))
                .with_context(|| format!("writing {}", path.display()))?;
            println!("Exported portable policy bundle to {}", path.display());
        }
        None => println!("{json}"),
    }
    Ok(())
}

async fn import_policy(args: ConfigImportPolicyArgs) -> Result<()> {
    // The bundle travels inline in one request frame, so bound the read at
    // the wire frame cap: an oversized or non-regular policy file fails here
    // instead of allocating or blocking the CLI before the frame cap runs.
    let raw_bytes = cockpit_host::bounded::read_at_most(
        &args.file,
        crate::daemon::proto::MAX_NDJSON_FRAME_BYTES as u64,
    )
    .with_context(|| format!("reading {}", args.file.display()))?;
    let raw =
        String::from_utf8(raw_bytes).with_context(|| format!("reading {}", args.file.display()))?;
    let cwd = std::env::current_dir().context("resolving current directory")?;
    let daemon = crate::daemon::client::ensure_persistent_daemon()
        .await
        .context("starting persistent daemon for policy import")?;
    let response = daemon
        .client
        .request(crate::daemon::proto::Request::ImportPolicy {
            project_root: cwd.display().to_string(),
            bundle_json: raw,
            replace: args.replace,
        })
        .await?
        .map_err(|error| anyhow::anyhow!("daemon rejected policy import: {error}"))?;
    let crate::daemon::proto::Response::PolicyImported {
        target,
        provider_count,
    } = response
    else {
        anyhow::bail!("daemon returned unexpected policy import response: {response:?}");
    };

    let mode = if args.replace { "replaced" } else { "merged" };
    println!(
        "Imported portable policy bundle into {} ({mode}; {} provider{}). Reconnect any credentials referenced by name on this machine.",
        target,
        provider_count,
        if provider_count == 1 { "" } else { "s" }
    );
    Ok(())
}
