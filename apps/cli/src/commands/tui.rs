use std::io::{IsTerminal, Write, stdin, stdout};
use std::path::Path;

use anyhow::{Context, Result};
use uuid::Uuid;

use crate::db::workspace_trust::WorkspaceTrustMode;
use crate::tui::app::App;
use crate::welcome;

pub async fn run(project: Option<&Path>, no_sandbox: bool) -> Result<()> {
    if !stdin().is_terminal() || !stdout().is_terminal() {
        welcome::print(project);
        return Ok(());
    }

    let db = ensure_tui_workspace_trust(project)?;

    let mut app = App::new_with_db(project, no_sandbox, db);
    app.run().await
}

pub async fn run_with_session(
    project: Option<&Path>,
    no_sandbox: bool,
    session_id: Uuid,
) -> Result<()> {
    if !stdin().is_terminal() || !stdout().is_terminal() {
        println!("session {session_id}");
        return Ok(());
    }

    let db = ensure_tui_workspace_trust(project)?;

    let mut app = App::new_with_db_and_session(project, no_sandbox, db, session_id);
    app.run().await
}

fn ensure_tui_workspace_trust(project: Option<&Path>) -> Result<crate::db::Db> {
    let opened = match project {
        Some(path) => path.to_path_buf(),
        None => std::env::current_dir().context("resolving cwd")?,
    };
    let root = crate::config::trust::resolve_trust_root(&opened)?;
    let db = crate::db::Db::open_default().context("opening cockpit DB")?;
    if let Some(decision) = db.workspace_trust_by_root(&root.root)? {
        crate::config::trust::apply_trusted_workspace(root, decision.mode)?;
        return Ok(db);
    }

    let mode = prompt_workspace_trust_choice(&root.root)?;
    db.set_workspace_trust(&root.root, mode)?;
    crate::config::trust::apply_trusted_workspace(root, mode)?;
    Ok(db)
}

fn prompt_workspace_trust_choice(root: &Path) -> Result<WorkspaceTrustMode> {
    let mut out = stdout();
    writeln!(
        out,
        "Cockpit has not seen this workspace before:\n  {}\n\nChoose workspace trust:\n  1) trust - open and honor project .cockpit config\n  2) ignore-config - open but ignore project .cockpit config and approvals\n  3) untrusted - refuse to open\n\nSelection [1/2/3]: ",
        root.display()
    )?;
    out.flush()?;
    let mut line = String::new();
    stdin().read_line(&mut line)?;
    parse_trust_choice(&line).with_context(|| {
        format!(
            "run `cockpit trust set {} --mode trust|ignore-config|untrusted`",
            root.display()
        )
    })
}

fn parse_trust_choice(raw: &str) -> Result<WorkspaceTrustMode> {
    match raw.trim() {
        "1" | "trust" => Ok(WorkspaceTrustMode::Trust),
        "2" | "ignore-config" | "ignore" => Ok(WorkspaceTrustMode::IgnoreConfig),
        "3" | "untrusted" => Ok(WorkspaceTrustMode::Untrusted),
        other => anyhow::bail!("invalid workspace trust selection `{other}`"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trust_prompt_choices_map_to_modes() {
        assert_eq!(parse_trust_choice("1").unwrap(), WorkspaceTrustMode::Trust);
        assert_eq!(
            parse_trust_choice("ignore-config").unwrap(),
            WorkspaceTrustMode::IgnoreConfig
        );
        assert_eq!(
            parse_trust_choice("untrusted").unwrap(),
            WorkspaceTrustMode::Untrusted
        );
    }
}
