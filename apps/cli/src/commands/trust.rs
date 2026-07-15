//! Workspace trust CLI commands.

use std::path::PathBuf;

use anyhow::Result;

use crate::cli::{TrustCommand, TrustModeArg, TrustSetArgs, TrustStatusArgs};
use crate::config::trust::TrustRoot;
use crate::db::Db;
use crate::db::workspace_trust::{WorkspaceTrustDecision, WorkspaceTrustMode};

pub async fn run(command: TrustCommand) -> Result<()> {
    match command {
        TrustCommand::Status(args) => status(args).await,
        TrustCommand::Set(args) => set(args).await,
    }
}

async fn status(args: TrustStatusArgs) -> Result<()> {
    let path = path_or_current_dir(args.path)?;
    let trust_root = crate::config::trust::resolve_trust_root(&path)?;
    let db = Db::open_default()?;
    let decision = db.workspace_trust_by_root(&trust_root.root)?;
    print!("{}", render_status(&trust_root, decision.as_ref()));
    Ok(())
}

async fn set(args: TrustSetArgs) -> Result<()> {
    let path = path_or_current_dir(args.path)?;
    let trust_root = crate::config::trust::resolve_trust_root(&path)?;
    let db = Db::open_default()?;
    let decision = db.set_workspace_trust(&trust_root.root, args.mode.into())?;
    print!("{}", render_set(&trust_root, &decision));
    Ok(())
}

fn path_or_current_dir(path: Option<PathBuf>) -> Result<PathBuf> {
    match path {
        Some(path) => Ok(path),
        None => Ok(std::env::current_dir()?),
    }
}

pub(crate) fn render_status(
    trust_root: &TrustRoot,
    decision: Option<&WorkspaceTrustDecision>,
) -> String {
    let mode = decision
        .map(|decision| decision.mode.as_str())
        .unwrap_or("unknown");
    format!(
        "trust root: {}\nmode: {mode}\nroot type: {}\n",
        trust_root.root.display(),
        trust_root.kind.as_str()
    )
}

pub(crate) fn render_set(trust_root: &TrustRoot, decision: &WorkspaceTrustDecision) -> String {
    format!(
        "trust root: {}\nmode: {}\nroot type: {}\n",
        trust_root.root.display(),
        decision.mode,
        trust_root.kind.as_str()
    )
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
        let decision = WorkspaceTrustDecision {
            root_path: tmp.path().display().to_string(),
            mode: WorkspaceTrustMode::IgnoreConfig,
            created_at: 1,
            updated_at: 2,
        };

        let output = render_set(&root, &decision);

        assert!(output.contains(&format!("trust root: {}", root.root.display())));
        assert!(output.contains("mode: ignore-config"));
    }
}
