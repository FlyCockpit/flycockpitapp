use std::io::{self, IsTerminal, Write};
use std::time::Instant;

use anyhow::{Context, Result, bail};
#[cfg(test)]
use uuid::Uuid;

#[cfg(test)]
use crate::agents::{AgentDef, GoalSettingsOverride};
#[cfg(test)]
use crate::assistants::{
    AssistantConfig, assistant_definition_path, identity, markdown_content_hash,
};
use crate::assistants::{CreateAssistantSpec, default_home_dir, spec_from_wizard};
use crate::cli::{
    AssistantCommand, AssistantDeleteArgs, AssistantMediaCommand, AssistantNewArgs,
    MediaAccountingCommand,
};
use crate::commands::setup::{TerminalActionHandler, TerminalIo, run_terminal_wizard};
use crate::daemon::client::ensure_persistent_daemon;
use crate::daemon::proto::{AssistantSessionResolutionMode, Request, Response};
#[cfg(test)]
use crate::session::project_id_for;
use crate::wizard::WizardRun;

pub async fn run(
    cmd: AssistantCommand,
    no_sandbox: bool,
    launch_start: Option<Instant>,
) -> Result<()> {
    match cmd {
        AssistantCommand::New(args) => new(args).await,
        AssistantCommand::List => list().await,
        AssistantCommand::Show { name } => show(&name).await,
        AssistantCommand::Delete(args) => delete(args).await,
        AssistantCommand::Chat { name } => chat(&name, no_sandbox, launch_start).await,
        AssistantCommand::Learn(args) => crate::commands::learn::run(args, no_sandbox).await,
        AssistantCommand::Media { command } => media(command).await,
    }
}

async fn media(command: AssistantMediaCommand) -> Result<()> {
    let daemon = ensure_persistent_daemon()
        .await
        .context("starting persistent daemon for media reservation accounting")?;
    match command {
        AssistantMediaCommand::Accounting {
            command: MediaAccountingCommand::Diagnose { scope, id, json: _ },
        } => {
            let response = daemon
                .client
                .request(media_diagnose_request(scope, id))
                .await
                .context("requesting media reservation diagnosis from daemon")?
                .map_err(|error| {
                    anyhow::anyhow!("daemon rejected media reservation diagnosis: {error}")
                })?;
            let Response::MediaReservationDiagnosis { diagnosis_json } = response else {
                bail!("daemon returned unexpected response to media diagnosis: {response:?}");
            };
            // The daemon already serialized the diagnosis (no secret bytes).
            println!("{diagnosis_json}");
        }
        AssistantMediaCommand::Accounting {
            command:
                MediaAccountingCommand::Repair {
                    scope,
                    id,
                    expected_block_generation,
                    repair_plan_digest,
                    idempotency_key,
                },
        } => {
            let response = daemon
                .client
                .request(media_repair_request(
                    scope,
                    id,
                    expected_block_generation,
                    repair_plan_digest,
                    idempotency_key,
                ))
                .await
                .context("requesting media reservation repair from daemon")?
                .map_err(|error| {
                    anyhow::anyhow!("daemon rejected media reservation repair: {error}")
                })?;
            let Response::MediaReservationRepaired { outcome } = response else {
                bail!("daemon returned unexpected response to media repair: {response:?}");
            };
            println!("{outcome}");
        }
    }
    Ok(())
}

/// Assemble the owner-remoted request for `assistant media accounting diagnose`.
/// Extracted so the real request the command sends is unit-testable without a
/// live daemon.
fn media_diagnose_request(scope: String, id: String) -> Request {
    Request::DiagnoseMediaReservation { scope, id }
}

/// Assemble the owner-remoted request for `assistant media accounting repair`.
fn media_repair_request(
    scope: String,
    id: String,
    expected_block_generation: u64,
    repair_plan_digest: String,
    idempotency_key: String,
) -> Request {
    Request::RepairMediaReservation {
        scope,
        id,
        expected_block_generation,
        repair_plan_digest,
        idempotency_key,
    }
}

async fn new(args: AssistantNewArgs) -> Result<()> {
    crate::assistants::validate_assistant_name(&args.name)?;
    let home_dir = default_home_dir(&args.name)?;
    let descriptor = crate::assistants::descriptor();
    let mut io = StdTerminalIo;
    let tty = io::stdin().is_terminal();
    let mut actions = AssistantNewAction {
        name: args.name.clone(),
        home_dir,
    };
    let run = run_terminal_wizard(descriptor, &mut io, &tty, &mut actions).await?;
    if !run.is_complete() {
        bail!("assistant creation did not complete");
    }
    Ok(())
}

/// Write the assistant's local home-directory artifacts (definition markdown +
/// identity files) from a preallocated installation identity and return the
/// `(config_json, content_hash)` the registry row needs. Mirrors the
/// file-writing half of `cockpit_core::assistants::create_assistant` (the DB
/// persist is remoted). Pure local IO — no daemon — so a parity test can
/// compare its output against the canonical `create_assistant` and fail if the
/// two ever drift.
///
/// Keeping identity allocation explicit here allows the caller to use the
/// exact same identity in the definition and persisted registry config.
#[cfg(test)]
fn write_assistant_home_with_installation_id(
    spec: &CreateAssistantSpec,
    installation_id: Uuid,
) -> Result<(String, String)> {
    crate::assistants::validate_assistant_name(&spec.name)?;
    if spec.description.trim().is_empty() {
        bail!("assistant description is required");
    }
    if spec.prompt.trim().is_empty() {
        bail!("assistant prompt is required");
    }
    std::fs::create_dir_all(&spec.home_dir)
        .with_context(|| format!("creating assistant home {}", spec.home_dir.display()))?;
    let path = assistant_definition_path(&spec.home_dir);
    let agent = AgentDef {
        name: spec.name.clone(),
        description: spec.description.clone(),
        mode: crate::agents::AgentMode::Primary,
        model: None,
        temperature: None,
        tools: None,
        tool_tiers: std::collections::BTreeMap::new(),
        tool_descriptions: std::collections::BTreeMap::new(),
        scan_tool_results: None,
        goal_supervision: GoalSettingsOverride::default(),
        permission: None,
        fork_eligible: false,
        vnext: Some(crate::assistants::vnext_for_private_assistant(
            installation_id,
        )),
        prompt: spec.prompt.clone(),
        prompt_variants: std::collections::HashMap::new(),
        source: path.clone(),
    };
    crate::agents::validate_invariants(&agent)?;
    let markdown = agent.to_markdown()?;
    std::fs::write(&path, &markdown)
        .with_context(|| format!("writing assistant definition {}", path.display()))?;
    identity::seed_identity_files(&spec.home_dir)?;
    let config = AssistantConfig {
        installation_id,
        agent_source: path.to_string_lossy().into_owned(),
        soul_hash: identity::hash_optional_file(&identity::soul_path(&spec.home_dir))?,
        user_hash: identity::hash_optional_file(&identity::user_path(&spec.home_dir))?,
        ..AssistantConfig::default()
    };
    let config_json = serde_json::to_string(&config).context("serializing assistant config")?;
    let content_hash = markdown_content_hash(&markdown);
    Ok((config_json, content_hash))
}

/// Write the assistant's local home-directory artifacts and persist the
/// registry row through the daemon-owned `UpsertAssistant` RPC. Only the DB
/// persist is remoted so the CLI never opens SQLite. Returns the persisted
/// (name, home_dir) for the wizard's confirmation line.
async fn persist_new_assistant(spec: CreateAssistantSpec) -> Result<(String, String)> {
    let daemon = ensure_persistent_daemon()
        .await
        .context("starting persistent daemon for assistant persist")?;
    let response = daemon
        .client
        .request(Request::UpsertAssistant {
            name: spec.name.clone(),
            description: spec.description,
            prompt: spec.prompt,
        })
        .await
        .context("requesting assistant persist from daemon")?
        .map_err(|error| anyhow::anyhow!("daemon rejected assistant persist: {error}"))?;
    let Response::AssistantUpserted { assistant } = response else {
        bail!("daemon returned unexpected response to assistant persist: {response:?}");
    };
    Ok((assistant.name, assistant.home_dir))
}

async fn list() -> Result<()> {
    let daemon = ensure_persistent_daemon()
        .await
        .context("starting persistent daemon for assistant list")?;
    let response = daemon
        .client
        .request(Request::ListAssistants)
        .await
        .context("requesting assistant list from daemon")?
        .map_err(|error| anyhow::anyhow!("daemon rejected assistant list: {error}"))?;
    let assistants = match response {
        Response::Assistants { assistants } => assistants,
        other => bail!("daemon returned unexpected response to assistant list: {other:?}"),
    };
    if assistants.is_empty() {
        println!("no assistants");
        return Ok(());
    }
    for assistant in assistants {
        let description = verified_assistant_definition(&assistant)
            .map(|def| def.description)
            .unwrap_or_else(|error| format!("<invalid: {error:#}>"));
        println!(
            "{}\t{}\t{}",
            assistant.name, description, assistant.home_dir
        );
    }
    Ok(())
}

async fn show(name: &str) -> Result<()> {
    let daemon = ensure_persistent_daemon()
        .await
        .context("starting persistent daemon for assistant show")?;
    let assistant = fetch_assistant(&daemon, name)
        .await?
        .ok_or_else(|| anyhow::anyhow!("assistant `{name}` not found"))?;
    let def = verified_assistant_definition(&assistant)?;
    println!("name: {}", def.name);
    println!("description: {}", def.description);
    println!("home_dir: {}", default_home_dir(&def.name)?.display());
    println!("definition: {}", def.source.display());
    if let Some(hash) = &assistant.definition_presentation_hash {
        println!("presentation_identity: {hash}");
    }
    println!(
        "agent_id: {}",
        def.vnext.as_ref().map_or("<legacy>", |v| &v.agent_id)
    );
    let execution_kind = match def.vnext.as_ref().map(|v| v.execution_kind) {
        Some(cockpit_core::agents::ExecutionKind::Assistant) => "assistant",
        Some(cockpit_core::agents::ExecutionKind::Coding) => "coding",
        Some(cockpit_core::agents::ExecutionKind::Computer) => "computer",
        None => "<legacy>",
    };
    println!("execution_kind: {execution_kind}");
    Ok(())
}

/// Consume only the daemon-coordinated registry/definition snapshot. The CLI
/// must never reopen the private assistant pathname after the daemon has
/// validated it: doing so would split authority and reintroduce a TOCTOU read.
fn verified_assistant_definition(
    assistant: &crate::daemon::proto::AssistantSummary,
) -> Result<cockpit_core::agents::AgentDef> {
    cockpit_proto::validate_assistant_summary(assistant)
        .map_err(|error| anyhow::anyhow!("assistant `{}`: {error}", assistant.name))?;
    let markdown = assistant.definition_markdown.as_deref().ok_or_else(|| {
        anyhow::anyhow!(
            "assistant `{}` definition is unavailable: {}",
            assistant.name,
            assistant
                .definition_diagnostic
                .as_deref()
                .unwrap_or("daemon returned an incoherent definition snapshot")
        )
    })?;
    if assistant.definition_diagnostic.is_some()
        || assistant
            .definition_revision
            .as_deref()
            .is_none_or(str::is_empty)
    {
        bail!(
            "assistant `{}` definition snapshot is incoherent",
            assistant.name
        );
    }
    cockpit_core::agents::parse_daemon_local_markdown(markdown, &assistant.name)
        .with_context(|| format!("parsing daemon snapshot for assistant `{}`", assistant.name))
}

async fn delete(args: AssistantDeleteArgs) -> Result<()> {
    let daemon = ensure_persistent_daemon()
        .await
        .context("starting persistent daemon for assistant delete")?;
    let (assistant, expected_config_generation) = fetch_assistant_inventory(&daemon, &args.name)
        .await?
        .ok_or_else(|| anyhow::anyhow!("assistant `{}` not found", args.name))?;
    if !args.yes {
        print!(
            "Delete assistant `{}` from the registry? Its home directory will remain at {} [y/N]: ",
            args.name, assistant.home_dir
        );
        io::stdout().flush()?;
        let mut line = String::new();
        io::stdin().read_line(&mut line)?;
        if !matches!(line.trim(), "y" | "Y" | "yes" | "YES") {
            println!("cancelled");
            return Ok(());
        }
    }
    let expected_revision = assistant.registration_revision.clone();
    if expected_revision.is_empty() {
        bail!("assistant registration has no deletion revision");
    }
    let project_root = std::env::current_dir()
        .context("resolving assistant deletion workspace")?
        .to_string_lossy()
        .into_owned();
    let client_operation_id = uuid::Uuid::new_v4().to_string();
    let response = daemon
        .client
        .request(delete_assistant_request(
            &client_operation_id,
            &project_root,
            &args.name,
            &expected_revision,
            expected_config_generation,
        ))
        .await
        .context("requesting assistant delete from daemon")?
        .map_err(|error| anyhow::anyhow!("daemon rejected assistant delete: {error}"))?;
    let Response::AssistantDeleted {
        client_operation_id: receipt_operation_id,
        mutation_intent_hash,
        requested_project_root,
        name,
        consumed_revision,
        ..
    } = response
    else {
        bail!("daemon returned unexpected response to assistant delete: {response:?}");
    };
    let expected_intent = cockpit_proto::assistant_mutation_intent_hash(
        &project_root,
        "delete",
        &args.name,
        &expected_revision,
        None,
    );
    if receipt_operation_id != client_operation_id
        || mutation_intent_hash != expected_intent
        || requested_project_root != project_root
        || name != args.name
        || consumed_revision != expected_revision
    {
        bail!("daemon returned an incoherent assistant deletion receipt");
    }
    println!(
        "deleted assistant `{}`; home directory left intact: {}",
        args.name, assistant.home_dir
    );
    Ok(())
}

/// Assemble the owner-remoted `GetAssistant` read (used by `show`/`delete`).
fn get_assistant_request(name: &str) -> Request {
    Request::GetAssistant {
        name: name.to_string(),
    }
}

/// Assemble the owner-remoted `DeleteAssistant` mutation.
fn delete_assistant_request(
    client_operation_id: &str,
    project_root: &str,
    name: &str,
    expected_revision: &str,
    expected_config_generation: u64,
) -> Request {
    Request::DeleteAssistant {
        client_operation_id: client_operation_id.to_string(),
        mutation_intent_hash: cockpit_proto::assistant_mutation_intent_hash(
            project_root,
            "delete",
            name,
            expected_revision,
            None,
        ),
        project_root: project_root.to_string(),
        name: name.to_string(),
        expected_revision: expected_revision.to_string(),
        expected_config_generation,
    }
}

async fn fetch_assistant_inventory(
    daemon: &crate::daemon::client::ConnectedDaemon,
    name: &str,
) -> Result<Option<(crate::daemon::proto::AssistantSummary, u64)>> {
    let response = daemon
        .client
        .request(Request::ListAssistants)
        .await
        .context("requesting assistant inventory from daemon")?
        .map_err(|error| anyhow::anyhow!("daemon rejected assistant inventory: {error}"))?;
    let Response::Assistants {
        assistants,
        config_generation,
    } = response
    else {
        bail!("daemon returned unexpected response to assistant inventory: {response:?}");
    };
    Ok(assistants
        .into_iter()
        .find(|assistant| assistant.name == name)
        .map(|assistant| (assistant, config_generation)))
}

/// Resolve a single assistant registry row through the daemon's owner-remoted
/// `GetAssistant` read. Returns `None` when the name is not registered.
async fn fetch_assistant(
    daemon: &crate::daemon::client::ConnectedDaemon,
    name: &str,
) -> Result<Option<crate::daemon::proto::AssistantSummary>> {
    let response = daemon
        .client
        .request(get_assistant_request(name))
        .await
        .context("requesting assistant from daemon")?
        .map_err(|error| anyhow::anyhow!("daemon rejected assistant query: {error}"))?;
    let Response::Assistant { assistant } = response else {
        bail!("daemon returned unexpected response to assistant query: {response:?}");
    };
    Ok(assistant)
}

async fn chat(name: &str, no_sandbox: bool, launch_start: Option<Instant>) -> Result<()> {
    crate::assistants::validate_assistant_name(name)?;
    let project_root = std::env::current_dir().context("resolving cwd")?;
    let project_root_str = project_root.to_string_lossy().into_owned();
    let daemon = ensure_persistent_daemon()
        .await
        .context("starting persistent daemon for assistant chat")?;
    let response = daemon
        .client
        .request(Request::ResolveAssistantSession {
            assistant_id: name.to_string(),
            project_root: project_root_str,
            mode: AssistantSessionResolutionMode::MostRecentOrCreate,
        })
        .await
        .context("requesting assistant session resolution from daemon")?
        .map_err(|error| {
            anyhow::anyhow!("daemon rejected assistant session resolution: {error}")
        })?;
    let session_id = match response {
        Response::AssistantSessionResolved { session, .. } => session.session_id,
        other => {
            bail!("daemon returned unexpected response to assistant session resolution: {other:?}")
        }
    };
    crate::commands::tui::run_with_session(
        Some(&project_root),
        no_sandbox,
        session_id,
        launch_start,
    )
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
            let (name, home_dir) = persist_new_assistant(spec).await?;
            io.write_line(&format!("Created assistant `{name}` at {home_dir}"))?;
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assistants::{create_assistant, create_assistant_with_installation_id};
    use crate::db::Db;
    use crate::wizard::WizardAnswer;

    fn sample_spec(home: std::path::PathBuf) -> crate::assistants::CreateAssistantSpec {
        crate::assistants::CreateAssistantSpec {
            name: "helper-bot".to_string(),
            description: "Helps with tests".to_string(),
            prompt: "Stay focused.".to_string(),
            home_dir: home,
        }
    }

    #[test]
    fn media_diagnose_and_repair_requests_are_owner_remoted() {
        // Drives the real request-builders the `media` command calls; asserts
        // the owner-remoted RPC tag and that the user's args map through.
        let Request::DiagnoseMediaReservation { scope, id } =
            media_diagnose_request("session".to_string(), "sess-1".to_string())
        else {
            panic!("diagnose must build DiagnoseMediaReservation");
        };
        assert_eq!(scope, "session");
        assert_eq!(id, "sess-1");

        let Request::RepairMediaReservation {
            scope,
            id,
            expected_block_generation,
            repair_plan_digest,
            idempotency_key,
        } = media_repair_request(
            "project".to_string(),
            "proj-9".to_string(),
            7,
            "digest-abc".to_string(),
            "idem-1".to_string(),
        )
        else {
            panic!("repair must build RepairMediaReservation");
        };
        assert_eq!(scope, "project");
        assert_eq!(id, "proj-9");
        assert_eq!(expected_block_generation, 7);
        assert_eq!(repair_plan_digest, "digest-abc");
        assert_eq!(idempotency_key, "idem-1");
    }

    #[test]
    fn get_and_delete_assistant_requests_carry_name() {
        let Request::GetAssistant { name } = get_assistant_request("helper-bot") else {
            panic!("show/delete must resolve through GetAssistant");
        };
        assert_eq!(name, "helper-bot");
        let Request::DeleteAssistant {
            client_operation_id,
            mutation_intent_hash,
            project_root,
            name,
            expected_revision,
            expected_config_generation,
        } = delete_assistant_request("op-1", "/project", "helper-bot", "rev-1", 7)
        else {
            panic!("delete must remove through DeleteAssistant");
        };
        assert_eq!(client_operation_id, "op-1");
        assert_eq!(project_root, "/project");
        assert_eq!(
            mutation_intent_hash,
            cockpit_proto::assistant_mutation_intent_hash(
                "/project",
                "delete",
                "helper-bot",
                "rev-1",
                None
            )
        );
        assert_eq!(name, "helper-bot");
        assert_eq!(expected_revision, "rev-1");
        assert_eq!(expected_config_generation, 7);
    }

    #[tokio::test]
    async fn cli_write_assistant_home_matches_core_create_assistant() {
        // Drift guard: `write_assistant_home` duplicates the file-writing half
        // of `cockpit_core::assistants::create_assistant` (cockpit-core is out
        // of scope to refactor). Build a home both ways from the same spec and
        // assert the on-disk definition BYTES are identical and the registry
        // identity is the vault-keyed identity of those bytes, so a future
        // core change cannot silently restore an offline-verifiable digest.
        let temp = tempfile::tempdir().unwrap();
        let _env = crate::test_env::TestEnvGuard::isolate_cockpit_home_at_async(temp.path()).await;
        let core_home = default_home_dir("helper-bot").unwrap();
        let cli_home = temp.path().join("cli").join("helper-bot");

        let db = Db::open_in_memory().unwrap();
        let installation_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
        let core_row = create_assistant_with_installation_id(
            &db,
            sample_spec(core_home.clone()),
            installation_id,
        )
        .await
        .unwrap();
        let (_config_json, _legacy_cli_hash) = write_assistant_home_with_installation_id(
            &sample_spec(cli_home.clone()),
            installation_id,
        )
        .unwrap();

        let core_md = std::fs::read(assistant_definition_path(&core_home)).unwrap();
        let cli_md = std::fs::read(assistant_definition_path(&cli_home)).unwrap();
        assert_eq!(
            core_md, cli_md,
            "assistant.md bytes must match cockpit-core's create_assistant"
        );
        let markdown = std::str::from_utf8(&cli_md).unwrap();
        assert_eq!(
            core_row.content_hash,
            cockpit_core::assistants::markdown_content_identity(&db, markdown).unwrap(),
            "persisted content identity must be vault-keyed over the exact assistant bytes"
        );
        assert_ne!(
            core_row.content_hash,
            markdown_content_hash(markdown),
            "persisted content identity must not be an offline-verifiable markdown digest"
        );
    }

    #[tokio::test]
    async fn assistant_crud_roundtrip() {
        let temp = tempfile::tempdir().unwrap();
        let _env = crate::test_env::TestEnvGuard::isolate_cockpit_home_at_async(temp.path()).await;
        let db = Db::open_in_memory().unwrap();
        let home = default_home_dir("helper-bot").unwrap();
        let row = create_assistant(
            &db,
            crate::assistants::CreateAssistantSpec {
                name: "helper-bot".to_string(),
                description: "Helps with tests".to_string(),
                prompt: "Stay focused.".to_string(),
                home_dir: home.clone(),
            },
        )
        .await
        .unwrap();

        assert_eq!(row.name, "helper-bot");
        assert!(home.join("assistant.md").is_file());
        assert_eq!(db.list_assistants().await.unwrap().len(), 1);

        // Assistant definitions carry the `local/` publisher, which only the
        // daemon-local trusted loader accepts.
        let def = cockpit_core::agents::load_daemon_local_named_from_file(
            &home.join("assistant.md"),
            &row.name,
        )
        .unwrap();
        assert_eq!(
            def.vnext.as_ref().map(|v| v.execution_kind),
            Some(cockpit_core::agents::ExecutionKind::Assistant)
        );
        assert!(def.model.is_none());
        assert!(def.tools.is_none());
    }

    #[tokio::test]
    async fn delete_preserves_home_dir() {
        let temp = tempfile::tempdir().unwrap();
        let _env = crate::test_env::TestEnvGuard::isolate_cockpit_home_at_async(temp.path()).await;
        let db = Db::open_in_memory().unwrap();
        let home = default_home_dir("helper-bot").unwrap();
        create_assistant(
            &db,
            crate::assistants::CreateAssistantSpec {
                name: "helper-bot".to_string(),
                description: "Helps with tests".to_string(),
                prompt: "Stay focused.".to_string(),
                home_dir: home.clone(),
            },
        )
        .await
        .unwrap();

        assert!(db.delete_assistant("helper-bot").await.unwrap());
        assert!(db.get_assistant("helper-bot").await.unwrap().is_none());
        assert!(
            home.is_dir(),
            "delete must leave the assistant home directory intact"
        );
    }

    #[tokio::test]
    async fn assistant_sessions_owned() {
        let temp = tempfile::tempdir().unwrap();
        let db = Db::open_in_memory().unwrap();
        let project_root = temp.path().to_path_buf();
        let project_id = project_id_for(&project_root);
        let project_root_str = project_root.to_string_lossy().into_owned();

        let session = db
            .create_assistant_session(&project_id, &project_root_str, "helper-bot", "helper-bot")
            .await
            .unwrap();
        db.create_session(&project_id, &project_root_str, "Build")
            .await
            .unwrap();

        let fetched = db.get_session(session.session_id).await.unwrap().unwrap();
        assert_eq!(fetched.assistant_name.as_deref(), Some("helper-bot"));

        let filtered = db
            .list_sessions_for_assistant("helper-bot", false, 100)
            .await
            .unwrap();
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].session_id, session.session_id);
    }

    #[test]
    fn assistant_spec_from_wizard_answers() {
        let mut run = WizardRun::new(crate::assistants::descriptor()).unwrap();
        run.submit(WizardAnswer::Text("Persistent helper".to_string()))
            .unwrap();
        run.submit(WizardAnswer::Text("Help the user.".to_string()))
            .unwrap();
        let spec =
            spec_from_wizard("helper-bot", std::path::PathBuf::from("/tmp/helper"), &run).unwrap();
        assert_eq!(spec.description, "Persistent helper");
        assert_eq!(spec.prompt, "Help the user.");
    }
}
