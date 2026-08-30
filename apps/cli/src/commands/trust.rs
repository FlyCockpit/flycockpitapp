//! Workspace trust CLI commands.

use std::path::PathBuf;

use anyhow::{Context, Result};

use crate::cli::{HistoryScopeArgs, TrustCommand, TrustModeArg, TrustSetArgs, TrustStatusArgs};
use crate::config::trust::TrustRoot;
use crate::daemon::client::ensure_persistent_daemon;
use crate::daemon::proto::{Request, Response, WorkspaceTrustMode};

pub async fn run(command: TrustCommand) -> Result<()> {
    match command {
        TrustCommand::Status(args) => status(args).await,
        TrustCommand::Set(args) => set(args).await,
        TrustCommand::HistoryScope(args) => history_scope(args).await,
    }
}

async fn history_scope(args: HistoryScopeArgs) -> Result<()> {
    let path = path_or_current_dir(args.path)?;
    let trust_root = crate::config::trust::resolve_trust_root(&path)?;
    let daemon = ensure_persistent_daemon()
        .await
        .context("starting persistent daemon for workspace history scope")?;
    let response = daemon
        .client
        .request(Request::SetWorkspaceHistoryScope {
            project_root: trust_root.root.display().to_string(),
            outbound: args.outbound,
            inbound: args.inbound,
        })
        .await
        .context("requesting workspace history scope set from daemon")?
        .map_err(|error| {
            anyhow::anyhow!("daemon rejected workspace history scope request: {error}")
        })?;
    match response {
        Response::WorkspaceHistoryScope { outbound, inbound } => {
            print!(
                "trust root: {}\nhistory outbound: {outbound}\nhistory inbound: {inbound}\n",
                trust_root.root.display()
            );
            Ok(())
        }
        other => anyhow::bail!(
            "daemon returned unexpected response to workspace history scope: {other:?}"
        ),
    }
}

async fn status(args: TrustStatusArgs) -> Result<()> {
    let path = path_or_current_dir(args.path)?;
    let trust_root = crate::config::trust::resolve_trust_root(&path)?;
    let daemon = ensure_persistent_daemon()
        .await
        .context("starting persistent daemon for workspace trust status")?;
    let client = daemon.client.clone();
    let project_root = trust_root.root.display().to_string();
    let response = client
        .request(Request::GetWorkspaceTrust { project_root })
        .await
        .context("requesting workspace trust from daemon")?
        .map_err(|error| anyhow::anyhow!("daemon rejected workspace trust request: {error}"))?;
    let mode = match response {
        Response::WorkspaceTrust { mode, .. } => mode,
        other => anyhow::bail!("daemon returned unexpected response to workspace trust: {other:?}"),
    };
    print!("{}", render_status(&trust_root, mode.as_ref()));
    Ok(())
}

async fn set(args: TrustSetArgs) -> Result<()> {
    let path = path_or_current_dir(args.path)?;
    let trust_root = crate::config::trust::resolve_trust_root(&path)?;
    let mode: WorkspaceTrustMode = args.mode.into();
    let project_root = trust_root.root.display().to_string();
    let daemon = ensure_persistent_daemon()
        .await
        .context("starting persistent daemon for workspace trust set")?;
    let client = daemon.client.clone();
    // Fetch the current config generation from the daemon so the
    // SetWorkspaceTrust RPC can detect concurrent trust changes.
    let disclosures = client
        .request(Request::GetStartupDisclosures {
            project_root: project_root.clone(),
        })
        .await
        .context("requesting startup disclosures from daemon")?
        .map_err(|error| anyhow::anyhow!("daemon rejected startup disclosures: {error}"))?;
    let expected_config_generation = match disclosures {
        Response::StartupDisclosures {
            config_generation, ..
        } => config_generation,
        other => {
            anyhow::bail!("daemon returned unexpected response to startup disclosures: {other:?}")
        }
    };
    let response = client
        .request(Request::SetWorkspaceTrust {
            project_root: project_root.clone(),
            mode,
            expected_config_generation,
        })
        .await
        .context("requesting workspace trust set from daemon")?
        .map_err(|error| anyhow::anyhow!("daemon rejected workspace trust set: {error}"))?;
    match response {
        Response::WorkspaceTrustSet { .. } => {}
        other => {
            anyhow::bail!("daemon returned unexpected response to workspace trust set: {other:?}")
        }
    }
    // Fetch the updated decision through the daemon RPC for display — the
    // CLI never opens SQLite directly (daemon-frontend decision, AC6).
    let trust_response = client
        .request(Request::GetWorkspaceTrust {
            project_root: project_root.clone(),
        })
        .await
        .context("requesting updated workspace trust from daemon")?
        .map_err(|error| anyhow::anyhow!("daemon rejected workspace trust request: {error}"))?;
    let mode = match trust_response {
        Response::WorkspaceTrust { mode, .. } => mode,
        other => anyhow::bail!("daemon returned unexpected response to workspace trust: {other:?}"),
    };
    let mode = mode.ok_or_else(|| {
        anyhow::anyhow!(
            "workspace trust decision was not found after set for {}",
            trust_root.root.display()
        )
    })?;
    print!("{}", render_set(&trust_root, &mode));
    Ok(())
}

fn path_or_current_dir(path: Option<PathBuf>) -> Result<PathBuf> {
    match path {
        Some(path) => Ok(path),
        None => Ok(std::env::current_dir()?),
    }
}

pub(crate) fn render_status(trust_root: &TrustRoot, mode: Option<&WorkspaceTrustMode>) -> String {
    let mode_str = mode.map(trust_mode_str).unwrap_or("unknown");
    format!(
        "trust root: {}\nmode: {mode_str}\nroot type: {}\n",
        trust_root.root.display(),
        trust_root.kind.as_str()
    )
}

pub(crate) fn render_set(trust_root: &TrustRoot, mode: &WorkspaceTrustMode) -> String {
    format!(
        "trust root: {}\nmode: {}\nroot type: {}\n",
        trust_root.root.display(),
        trust_mode_str(mode),
        trust_root.kind.as_str()
    )
}

fn trust_mode_str(mode: &WorkspaceTrustMode) -> &'static str {
    match mode {
        WorkspaceTrustMode::Trust => "trust",
        WorkspaceTrustMode::IgnoreConfig => "ignore-config",
        WorkspaceTrustMode::Untrusted => "untrusted",
    }
}

impl From<TrustModeArg> for WorkspaceTrustMode {
    fn from(value: TrustModeArg) -> Self {
        match value {
            TrustModeArg::Trust => Self::Trust,
            TrustModeArg::IgnoreConfig => Self::IgnoreConfig,
            TrustModeArg::Untrusted => Self::Untrusted,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::trust::{TrustRootKind, resolve_trust_root};

    #[test]
    fn status_output_names_root_and_unknown_mode() {
        let tmp = tempfile::tempdir().unwrap();
        let root = resolve_trust_root(tmp.path()).unwrap();

        let output = render_status(&root, None);

        assert!(output.contains(&format!("trust root: {}", root.root.display())));
        assert!(output.contains("mode: unknown"));
        assert!(output.contains("root type: directory"));
    }

    #[test]
    fn set_output_names_root_and_mode() {
        let tmp = tempfile::tempdir().unwrap();
        let root = TrustRoot {
            opened_path: tmp.path().to_path_buf(),
            root: tmp.path().to_path_buf(),
            kind: TrustRootKind::Directory,
        };
        let mode = WorkspaceTrustMode::IgnoreConfig;

        let output = render_set(&root, &mode);

        assert!(output.contains(&format!("trust root: {}", root.root.display())));
        assert!(output.contains("mode: ignore-config"));
    }
}
