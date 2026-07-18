use std::io::{self, IsTerminal, Write};

use anyhow::{Context, Result, bail};

use crate::assistants::{create_assistant, default_home_dir, spec_from_wizard};
use crate::cli::{AssistantCommand, AssistantDeleteArgs, AssistantNewArgs};
use crate::commands::setup::{TerminalActionHandler, TerminalIo, run_terminal_wizard};
use crate::db::Db;
use crate::session::project_id_for;
use crate::wizard::WizardRun;

pub async fn run(cmd: AssistantCommand, no_sandbox: bool) -> Result<()> {
    match cmd {
        AssistantCommand::New(args) => new(args).await,
        AssistantCommand::List => list(),
        AssistantCommand::Show { name } => show(&name),
        AssistantCommand::Delete(args) => delete(args),
        AssistantCommand::Chat { name } => chat(&name, no_sandbox).await,
        AssistantCommand::Learn(args) => crate::commands::learn::run(args, no_sandbox).await,
    }
}

async fn new(args: AssistantNewArgs) -> Result<()> {
    crate::assistants::validate_assistant_name(&args.name)?;
    let db = Db::open_default().context("opening cockpit DB")?;
    let home_dir = default_home_dir(&args.name)?;
    let descriptor = crate::assistants::descriptor();
    let mut io = StdTerminalIo;
    let tty = io::stdin().is_terminal();
    let mut actions = AssistantNewAction {
        db,
        name: args.name.clone(),
        home_dir,
    };
    let run = run_terminal_wizard(descriptor, &mut io, &tty, &mut actions).await?;
    if !run.is_complete() {
        bail!("assistant creation did not complete");
    }
    Ok(())
}

fn list() -> Result<()> {
    let db = Db::open_default().context("opening cockpit DB")?;
    let rows = db.list_assistants().context("listing assistants")?;
    if rows.is_empty() {
        println!("no assistants");
        return Ok(());
    }
    for row in rows {
        match crate::assistants::load_from_row(&row) {
            Ok(def) => println!(
                "{}\t{}\t{}",
                def.name,
                def.description,
                def.home_dir.display()
            ),
            Err(error) => println!("{}\t<invalid: {}>\t{}", row.name, error, row.home_dir),
        }
    }
    Ok(())
}

fn show(name: &str) -> Result<()> {
    let db = Db::open_default().context("opening cockpit DB")?;
    let row = db
        .get_assistant(name)
        .with_context(|| format!("loading assistant `{name}`"))?
        .ok_or_else(|| anyhow::anyhow!("assistant `{name}` not found"))?;
    let def = crate::assistants::load_from_row(&row)?;
    println!("name: {}", def.name);
    println!("description: {}", def.description);
    println!("home_dir: {}", def.home_dir.display());
    println!("definition: {}", def.agent.source.display());
    println!("content_hash: {}", row.content_hash);
    println!("mode: {:?}", def.agent.mode);
    if let Some(model) = def.agent.model.as_deref() {
        println!("model: {model}");
    }
    if let Some(tools) = def.agent.tools.as_ref() {
        println!("tools: {}", tools.join(","));
    }
    Ok(())
}

fn delete(args: AssistantDeleteArgs) -> Result<()> {
    let db = Db::open_default().context("opening cockpit DB")?;
    let row = db
        .get_assistant(&args.name)
        .with_context(|| format!("loading assistant `{}`", args.name))?
        .ok_or_else(|| anyhow::anyhow!("assistant `{}` not found", args.name))?;
    if !args.yes {
        print!(
            "Delete assistant `{}` from the registry? Its home directory will remain at {} [y/N]: ",
            args.name, row.home_dir
        );
        io::stdout().flush()?;
        let mut line = String::new();
        io::stdin().read_line(&mut line)?;
        if !matches!(line.trim(), "y" | "Y" | "yes" | "YES") {
            println!("cancelled");
            return Ok(());
        }
    }
    db.delete_assistant(&args.name)?;
    println!(
        "deleted assistant `{}`; home directory left intact: {}",
        args.name, row.home_dir
    );
    Ok(())
}

async fn chat(name: &str, no_sandbox: bool) -> Result<()> {
    crate::assistants::validate_assistant_name(name)?;
    let project_root = std::env::current_dir().context("resolving cwd")?;
    let db = Db::open_default().context("opening cockpit DB")?;
    let row = db
        .get_assistant(name)
        .with_context(|| format!("loading assistant `{name}`"))?
        .ok_or_else(|| anyhow::anyhow!("assistant `{name}` not found"))?;
    crate::assistants::load_from_row(&row)
        .with_context(|| format!("validating assistant `{name}` before chat"))?;
    let session = match db.most_recent_session_for_assistant(name)? {
        Some(session) => session,
        None => {
            let project_id = project_id_for(&project_root);
            let project_root_str = project_root.to_string_lossy().into_owned();
            db.create_assistant_session(&project_id, &project_root_str, name, name)
                .context("creating assistant session")?
        }
    };
    crate::commands::tui::run_with_session(Some(&project_root), no_sandbox, session.session_id)
        .await
}

struct StdTerminalIo;

impl TerminalIo for StdTerminalIo {
    fn read_line(&mut self) -> io::Result<String> {
        let mut line = String::new();
        io::stdin().read_line(&mut line)?;
        Ok(line)
    }

    fn write(&mut self, text: &str) -> io::Result<()> {
        let mut out = io::stdout();
        out.write_all(text.as_bytes())?;
        out.flush()
    }
}

struct AssistantNewAction {
    db: Db,
    name: String,
    home_dir: std::path::PathBuf,
}

impl TerminalActionHandler for AssistantNewAction {
    fn run_action<'a>(
        &'a mut self,
        step_id: &'static str,
        run: &'a WizardRun,
        io: &'a mut dyn TerminalIo,
    ) -> crate::commands::setup::ActionFuture<'a> {
        Box::pin(async move {
            if step_id != "save" {
                return Ok(());
            }
            let spec = spec_from_wizard(&self.name, self.home_dir.clone(), run)?;
            let row = create_assistant(&self.db, spec)?;
            io.write_line(&format!(
                "Created assistant `{}` at {}",
                row.name, row.home_dir
            ))?;
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agents::AgentMode;
    use crate::wizard::WizardAnswer;

    #[test]
    fn assistant_crud_roundtrip() {
        let temp = tempfile::tempdir().unwrap();
        let db = Db::open_in_memory().unwrap();
        let home = temp.path().join("assistants").join("helper-bot");
        let row = create_assistant(
            &db,
            crate::assistants::CreateAssistantSpec {
                name: "helper-bot".to_string(),
                description: "Helps with tests".to_string(),
                mode: AgentMode::Primary,
                tools: Some(vec!["read".to_string()]),
                model: Some("openai/gpt-5.5".to_string()),
                prompt: "Stay focused.".to_string(),
                home_dir: home.clone(),
            },
        )
        .unwrap();

        assert_eq!(row.name, "helper-bot");
        assert!(home.join("assistant.md").is_file());
        assert_eq!(db.list_assistants().unwrap().len(), 1);

        let def = crate::assistants::load_from_row(&row).unwrap();
        assert_eq!(def.agent.model.as_deref(), Some("openai/gpt-5.5"));
        assert_eq!(def.agent.tools.as_deref(), Some(&["read".to_string()][..]));
    }

    #[test]
    fn delete_preserves_home_dir() {
        let temp = tempfile::tempdir().unwrap();
        let db = Db::open_in_memory().unwrap();
        let home = temp.path().join("assistants").join("helper-bot");
        create_assistant(
            &db,
            crate::assistants::CreateAssistantSpec {
                name: "helper-bot".to_string(),
                description: "Helps with tests".to_string(),
                mode: AgentMode::Primary,
                tools: Some(vec!["read".to_string()]),
                model: Some("openai/gpt-5.5".to_string()),
                prompt: "Stay focused.".to_string(),
                home_dir: home.clone(),
            },
        )
        .unwrap();

        assert!(db.delete_assistant("helper-bot").unwrap());
        assert!(db.get_assistant("helper-bot").unwrap().is_none());
        assert!(
            home.is_dir(),
            "delete must leave the assistant home directory intact"
        );
    }

    #[test]
    fn assistant_sessions_owned() {
        let temp = tempfile::tempdir().unwrap();
        let db = Db::open_in_memory().unwrap();
        let project_root = temp.path().to_path_buf();
        let project_id = project_id_for(&project_root);
        let project_root_str = project_root.to_string_lossy().into_owned();

        let session = db
            .create_assistant_session(&project_id, &project_root_str, "helper-bot", "helper-bot")
            .unwrap();
        db.create_session(&project_id, &project_root_str, "Build")
            .unwrap();

        let fetched = db.get_session(session.session_id).unwrap().unwrap();
        assert_eq!(fetched.assistant_name.as_deref(), Some("helper-bot"));

        let filtered = db
            .list_sessions_for_assistant("helper-bot", false, 100)
            .unwrap();
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].session_id, session.session_id);
    }

    #[test]
    fn assistant_spec_from_wizard_answers() {
        let mut run = WizardRun::new(crate::assistants::descriptor()).unwrap();
        run.submit(WizardAnswer::Text("Persistent helper".to_string()))
            .unwrap();
        run.submit(WizardAnswer::Select("all".to_string())).unwrap();
        run.submit(WizardAnswer::Text("openai/gpt-5.5".to_string()))
            .unwrap();
        run.submit(WizardAnswer::Text("read, write".to_string()))
            .unwrap();
        run.submit(WizardAnswer::Text("Help the user.".to_string()))
            .unwrap();
        let spec =
            spec_from_wizard("helper-bot", std::path::PathBuf::from("/tmp/helper"), &run).unwrap();
        assert_eq!(spec.mode, AgentMode::All);
        assert_eq!(spec.tools.unwrap(), vec!["read", "write"]);
    }
}
