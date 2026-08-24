//! Assistant definitions and persistence helpers.
//!
//! An assistant is an entity wrapper around an agent-shaped markdown
//! definition stored at `<assistant-home>/assistant.md`. The markdown parser is
//! deliberately the same parser used for agents.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::agents::{
    AgentDef, AgentMode, ExecutionKind, ModelCapability, ModelLocality, ModelSlot, VnextAgentDef,
};
use crate::db::Db;
use crate::db::assistants::AssistantRow;
use crate::wizard::{
    StepDescriptor, StepKind, WizardAnswer, WizardDescriptor, WizardRun, WritePolicy,
};

pub const ASSISTANT_WIZARD_ID: &str = "assistant";
#[cfg(test)]
pub(crate) const VALID_ASSISTANT_CONTENT_HASH_FIXTURE: &str =
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

pub mod identity;
pub mod self_improvement;

#[derive(Debug, Clone)]
pub struct AssistantDef {
    pub name: String,
    pub description: String,
    pub home_dir: PathBuf,
    pub agent: AgentDef,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AssistantConfig {
    /// Daemon-owned installation identity.  This is deliberately distinct
    /// from the editable assistant display name and is the sole source of
    /// the `local/<UUID>` vNext publisher identity.
    #[serde(rename = "installationId")]
    pub installation_id: Uuid,
    #[serde(default)]
    pub agent_source: String,
    #[serde(default)]
    pub soul_edit_mode: identity::SoulEditMode,
    #[serde(default = "identity::default_identity_max_tokens")]
    pub identity_max_tokens: usize,
    #[serde(default)]
    pub soul_hash: Option<String>,
    #[serde(default)]
    pub user_hash: Option<String>,
    #[serde(default = "self_improvement::default_skill_review_interval")]
    pub skill_review_interval: u32,
}

impl Default for AssistantConfig {
    fn default() -> Self {
        Self {
            installation_id: Uuid::nil(),
            agent_source: String::new(),
            soul_edit_mode: identity::SoulEditMode::default(),
            identity_max_tokens: identity::default_identity_max_tokens(),
            soul_hash: None,
            user_hash: None,
            skill_review_interval: self_improvement::DEFAULT_SKILL_REVIEW_INTERVAL,
        }
    }
}

#[derive(Debug, Clone)]
pub struct CreateAssistantSpec {
    pub name: String,
    pub description: String,
    pub prompt: String,
    pub home_dir: PathBuf,
}

pub fn validate_assistant_name(name: &str) -> Result<()> {
    if name.is_empty() {
        bail!("assistant name is required");
    }
    let valid = name
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && name
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && name
            .bytes()
            .last()
            .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit());
    if !valid || name.contains("--") {
        bail!("assistant name `{name}` must be kebab-case");
    }
    Ok(())
}

pub fn default_home_dir(name: &str) -> Result<PathBuf> {
    Ok(crate::config::resolve::cockpit_data_dir()?
        .join("assistants")
        .join(name))
}

pub fn assistant_definition_path(home_dir: &Path) -> PathBuf {
    home_dir.join("assistant.md")
}

pub fn load_from_home(name: &str, home_dir: &Path) -> Result<AssistantDef> {
    validate_assistant_name(name)?;
    let path = assistant_definition_path(home_dir);
    let agent = crate::agents::load_daemon_local_named_from_file(&path, name)
        .with_context(|| format!("loading assistant definition {}", path.display()))?;
    Ok(AssistantDef {
        name: name.to_string(),
        description: agent.description.clone(),
        home_dir: home_dir.to_path_buf(),
        agent,
    })
}

pub fn load_from_row(row: &AssistantRow) -> Result<AssistantDef> {
    validate_row_home(row)?;
    let config: AssistantConfig = serde_json::from_str(&row.config_json)
        .with_context(|| format!("parsing assistant config for `{}`", row.name))?;
    if config.installation_id.is_nil() {
        bail!(
            "assistant `{}` has no daemon-owned installation ID",
            row.name
        );
    }
    let definition = load_from_home(&row.name, Path::new(&row.home_dir))?;
    let expected_agent_id = format!("local/{}", config.installation_id);
    if definition
        .agent
        .vnext
        .as_ref()
        .map(|vnext| vnext.agent_id.as_str())
        != Some(expected_agent_id.as_str())
    {
        bail!(
            "assistant `{}` definition identity does not match its daemon-owned installation ID",
            row.name
        );
    }
    Ok(definition)
}

/// Prove that a persisted assistant is bound to the only daemon-owned home
/// allowed for its name before any authority-bearing filesystem access.
pub fn validate_row_home(row: &AssistantRow) -> Result<PathBuf> {
    validate_assistant_name(&row.name)?;
    let expected = default_home_dir(&row.name)?;
    if Path::new(&row.home_dir) != expected {
        bail!(
            "assistant `{}` registry home is not its daemon-owned canonical home",
            row.name
        );
    }
    Ok(expected)
}

pub async fn create_assistant(db: &Db, spec: CreateAssistantSpec) -> Result<AssistantRow> {
    create_assistant_with_installation_id(db, spec, Uuid::new_v4()).await
}

/// Create an assistant using a caller-supplied installation identity.
///
/// The normal daemon-owned creation path uses [`create_assistant`], which
/// mints a fresh UUID. This explicit form is for flows that must write the
/// definition and registry configuration from one preallocated identity.
pub async fn create_assistant_with_installation_id(
    db: &Db,
    spec: CreateAssistantSpec,
    installation_id: Uuid,
) -> Result<AssistantRow> {
    let db = db.clone();
    tokio::task::spawn_blocking(move || {
        create_assistant_with_installation_id_sync(&db, spec, installation_id)
    })
    .await
    .context("assistant creation coordinator joined")?
}

fn create_assistant_with_installation_id_sync(
    db: &Db,
    spec: CreateAssistantSpec,
    installation_id: Uuid,
) -> Result<AssistantRow> {
    validate_assistant_name(&spec.name)?;
    if spec.description.trim().is_empty() {
        bail!("assistant description is required");
    }
    if spec.prompt.trim().is_empty() {
        bail!("assistant prompt is required");
    }
    let canonical_home = default_home_dir(&spec.name)?;
    if spec.home_dir != canonical_home {
        bail!("assistant creation requires the daemon-owned canonical home");
    }
    crate::private_fs::ensure_private_dir(&spec.home_dir)
        .with_context(|| format!("creating assistant home {}", spec.home_dir.display()))?;
    let path = assistant_definition_path(&spec.home_dir);
    let _guard = cockpit_config::config::hold_config_mutation_lock(&path)?;
    recover_creation_journal_locked(db, &spec.home_dir)?;
    if get_assistant_blocking(db, &spec.name)?.is_some() {
        bail!("assistant `{}` already exists", spec.name);
    }
    if cockpit_config::config::read_config_file_nofollow(&path)?.is_some() {
        bail!("assistant definition already exists without a registry row");
    }
    let agent = AgentDef {
        name: spec.name.clone(),
        description: spec.description,
        // These retained in-memory fields are ignored by schemaVersion 2.
        // They cannot be configured from the assistant specification.
        mode: AgentMode::Primary,
        model: None,
        temperature: None,
        tools: None,
        tool_tiers: std::collections::BTreeMap::new(),
        tool_descriptions: std::collections::BTreeMap::new(),
        scan_tool_results: None,
        goal_supervision: crate::agents::GoalSettingsOverride::default(),
        permission: None,
        fork_eligible: false,
        // Assistant homes are daemon-owned definition locations, so they are
        // the sole constructor allowed to use the local publisher. Tool/model
        // selections from the legacy wizard remain host-side setup inputs and
        // are intentionally absent from the serialized v2 definition.
        vnext: Some(vnext_for_private_assistant(installation_id)),
        prompt: spec.prompt,
        prompt_variants: std::collections::HashMap::new(),
        source: path.clone(),
    };
    crate::agents::validate_invariants(&agent)?;
    let markdown = agent.to_markdown()?;
    identity::seed_identity_files(&spec.home_dir)?;
    let config = AssistantConfig {
        installation_id,
        agent_source: path.to_string_lossy().into_owned(),
        soul_hash: identity::hash_optional_file(&identity::soul_path(&spec.home_dir))?,
        user_hash: identity::hash_optional_file(&identity::user_path(&spec.home_dir))?,
        ..AssistantConfig::default()
    };
    let config_json = serde_json::to_string(&config)?;
    let content_hash = sha256_hex(markdown.as_bytes());
    let journal = AssistantCreationJournal {
        operation_id: Uuid::new_v4().to_string(),
        name: spec.name.clone(),
        home_dir: spec.home_dir.to_string_lossy().into_owned(),
        config_json: config_json.clone(),
        content_hash: content_hash.clone(),
        markdown: markdown.clone(),
    };
    let journal_path = creation_journal_path(&spec.home_dir);
    cockpit_config::config::write_config_bytes_atomic(
        &journal_path,
        &serde_json::to_vec_pretty(&journal)?,
    )?;
    cockpit_config::config::write_config_bytes_atomic(&path, markdown.as_bytes())
        .with_context(|| format!("writing assistant definition {}", path.display()))?;
    let name = spec.name.clone();
    let home_dir = spec.home_dir.to_string_lossy().into_owned();
    let config_for_db = config_json.clone();
    let hash_for_db = content_hash.clone();
    let row = db.write_blocking(move |conn| {
        crate::db::Db::upsert_assistant_conn(conn, &name, &home_dir, &config_for_db, &hash_for_db)
    })?;
    cockpit_config::config::remove_config_file_atomic(&journal_path)?;
    Ok(row)
}

/// The sole daemon-owned v2 template for private assistants.  CLI-side
/// creation reuses it so both persistence paths produce the same provenance
/// and never serialize the retired tool/model/mode contract.
pub fn vnext_for_private_assistant(installation_id: Uuid) -> VnextAgentDef {
    VnextAgentDef {
        schema_version: crate::agents::SCHEMA_VERSION,
        agent_id: format!("local/{installation_id}"),
        execution_kind: ExecutionKind::Assistant,
        model_slots: std::collections::BTreeMap::from([(
            "primary".to_string(),
            ModelSlot {
                purpose: "Primary model for this private assistant.".to_string(),
                min_context_tokens: 1,
                required_capabilities: vec![ModelCapability::TextGeneration],
                locality: ModelLocality::Any,
                allow_default_fallback: true,
                suggested_models: Vec::new(),
            },
        )]),
        delegation: Default::default(),
        questions: None,
        verification: None,
    }
}

/// Snapshot every persisted private-assistant definition into the session's
/// daemon-owned UUID resolver.  Definitions are loaded once under the trusted
/// assistant-home boundary and then used directly for every child launch.
pub async fn local_installation_resolver(
    db: &Db,
) -> Result<crate::agents::LocalInstallationResolver> {
    let mut definitions = std::collections::BTreeMap::new();
    for row in db.list_assistants().await? {
        let config: AssistantConfig = serde_json::from_str(&row.config_json)
            .with_context(|| format!("parsing assistant config for `{}`", row.name))?;
        if config.installation_id.is_nil() {
            bail!(
                "assistant `{}` has no daemon-owned installation ID",
                row.name
            );
        }
        let definition = load_from_row(&row)?.agent;
        if definitions
            .insert(config.installation_id, definition)
            .is_some()
        {
            bail!(
                "multiple persisted assistants claim daemon-local installation ID `{}`",
                config.installation_id
            );
        }
    }
    crate::agents::LocalInstallationResolver::from_bound_definitions(definitions)
}

pub fn descriptor() -> WizardDescriptor {
    WizardDescriptor {
        id: ASSISTANT_WIZARD_ID,
        title: "Create assistant",
        description: "Create a persistent assistant identity backed by an agent definition.",
        write_policy: WritePolicy::CommitAtEnd,
        model_context: None,
        steps: vec![
            StepDescriptor {
                id: "description",
                prompt: "Assistant description",
                help: "Short human-readable purpose for lists and selection surfaces.",
                help_hook: None,
                kind: StepKind::Text,
                default_answer: None,
                prefill: None,
                validate: Some(non_empty_text),
                write: None,
                branch: None,
            },
            StepDescriptor {
                id: "prompt",
                prompt: "System prompt",
                help: "The assistant's agent prompt body.",
                help_hook: None,
                kind: StepKind::Text,
                default_answer: Some(WizardAnswer::Text(
                    "You are a persistent Cockpit assistant.".to_string(),
                )),
                prefill: None,
                validate: Some(non_empty_text),
                write: None,
                branch: None,
            },
            StepDescriptor {
                id: "save",
                prompt: "Save assistant",
                help: "Writes assistant.md and records the assistant row.",
                help_hook: None,
                kind: StepKind::Action {
                    progress: "Saving assistant...",
                },
                default_answer: None,
                prefill: None,
                validate: None,
                write: None,
                branch: None,
            },
        ],
    }
}

pub fn spec_from_wizard(
    name: &str,
    home_dir: PathBuf,
    run: &WizardRun,
) -> Result<CreateAssistantSpec> {
    validate_assistant_name(name)?;
    let description = text_answer(run, "description").context("assistant description missing")?;
    let prompt = text_answer(run, "prompt").context("assistant prompt missing")?;
    Ok(CreateAssistantSpec {
        name: name.to_string(),
        description,
        prompt,
        home_dir,
    })
}

fn non_empty_text(_: &WizardRun, answer: &WizardAnswer) -> std::result::Result<(), String> {
    match answer {
        WizardAnswer::Text(value) if !value.trim().is_empty() => Ok(()),
        _ => Err("value is required".to_string()),
    }
}

fn text_answer(run: &WizardRun, step: &str) -> Option<String> {
    match run.answer(step) {
        Some(WizardAnswer::Text(value)) => Some(value.clone()),
        _ => None,
    }
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    crate::intel::hex_lower(&Sha256::digest(bytes))
}

pub fn markdown_content_hash(markdown: &str) -> String {
    sha256_hex(markdown.as_bytes())
}

pub fn definition_revision(row: &AssistantRow, markdown: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(b"cockpit-assistant-definition-revision-v2\0");
    for value in [
        &row.name,
        &row.home_dir,
        &row.config_json,
        &row.content_hash,
    ] {
        digest.update((value.len() as u64).to_le_bytes());
        digest.update(value.as_bytes());
    }
    digest.update((markdown.len() as u64).to_le_bytes());
    digest.update(markdown.as_bytes());
    format!("{:x}", digest.finalize())
}

pub fn validate_definition_identity(row: &AssistantRow, definition: &AgentDef) -> Result<()> {
    let config: AssistantConfig = serde_json::from_str(&row.config_json)
        .with_context(|| format!("parsing assistant config for `{}`", row.name))?;
    if config.installation_id.is_nil() {
        bail!(
            "assistant `{}` has no daemon-owned installation ID",
            row.name
        );
    }
    let expected = format!("local/{}", config.installation_id);
    let actual = definition
        .vnext
        .as_ref()
        .map(|definition| definition.agent_id.as_str());
    if actual != Some(expected.as_str()) {
        bail!(
            "assistant `{}` definition identity does not match installation `{}`",
            row.name,
            config.installation_id
        );
    }
    Ok(())
}

#[derive(Serialize, Deserialize)]
struct DefinitionSaveJournal {
    name: String,
    home_dir: String,
    config_json: String,
    prior_hash: String,
    next_hash: String,
    prior_markdown: String,
    next_markdown: String,
}

#[derive(Serialize, Deserialize)]
struct AssistantCreationJournal {
    operation_id: String,
    name: String,
    home_dir: String,
    config_json: String,
    content_hash: String,
    markdown: String,
}

fn definition_journal_path(home: &Path) -> PathBuf {
    home.join(".assistant-definition-save.journal.json")
}

fn creation_journal_path(home: &Path) -> PathBuf {
    home.join(".assistant-creation.journal.json")
}

fn recover_creation_journal_locked(db: &Db, home: &Path) -> Result<()> {
    let journal_path = creation_journal_path(home);
    let Some(raw) = cockpit_config::config::read_config_file_nofollow(&journal_path)? else {
        return Ok(());
    };
    let journal: AssistantCreationJournal =
        serde_json::from_slice(&raw).context("parsing assistant creation journal")?;
    let operation_id = Uuid::parse_str(&journal.operation_id)
        .context("assistant creation journal operation ID is invalid")?;
    if operation_id.to_string() != journal.operation_id
        || default_home_dir(&journal.name)? != home
        || Path::new(&journal.home_dir) != home
    {
        bail!("assistant creation journal identity is invalid");
    }
    if markdown_content_hash(&journal.markdown) != journal.content_hash {
        bail!("assistant creation journal hash does not match exact markdown bytes");
    }
    let target = assistant_definition_path(home);
    let row_for_validation = AssistantRow {
        name: journal.name.clone(),
        created_at: 0,
        home_dir: journal.home_dir.clone(),
        config_json: journal.config_json.clone(),
        content_hash: journal.content_hash.clone(),
    };
    let parsed = crate::agents::parse_daemon_local_markdown(&journal.markdown, &journal.name)?;
    validate_definition_identity(&row_for_validation, &parsed)?;
    identity::seed_identity_files(home)?;
    if let Some(existing) = get_assistant_blocking(db, &journal.name)? {
        validate_row_home(&existing)?;
        if existing.home_dir != journal.home_dir
            || existing.config_json != journal.config_json
            || existing.content_hash != journal.content_hash
        {
            bail!("assistant creation journal conflicts with registry row");
        }
        match cockpit_config::config::read_config_file_nofollow(&target)? {
            Some(bytes) if sha256_hex(&bytes) == journal.content_hash => {}
            Some(_) => bail!("assistant creation target conflicts with journal bytes"),
            None => cockpit_config::config::write_config_bytes_atomic(
                &target,
                journal.markdown.as_bytes(),
            )?,
        }
    } else {
        cockpit_config::config::write_config_bytes_atomic(&target, journal.markdown.as_bytes())?;
        let name = journal.name.clone();
        let home_dir = journal.home_dir.clone();
        let config_json = journal.config_json.clone();
        let content_hash = journal.content_hash.clone();
        db.write_blocking(move |conn| {
            crate::db::Db::upsert_assistant_conn(
                conn,
                &name,
                &home_dir,
                &config_json,
                &content_hash,
            )
        })?;
    }
    let current = cockpit_config::config::read_config_file_nofollow(&target)?
        .context("assistant definition disappeared during creation recovery")?;
    if sha256_hex(&current) != journal.content_hash {
        bail!("assistant creation target conflicts with journal bytes");
    }
    cockpit_config::config::remove_config_file_atomic(&journal_path)?;
    Ok(())
}

fn recover_definition_journal_locked(db: &Db, row: &AssistantRow) -> Result<()> {
    let home = validate_row_home(row)?;
    let home = home.as_path();
    let journal_path = definition_journal_path(home);
    let Some(raw) = cockpit_config::config::read_config_file_nofollow(&journal_path)? else {
        return Ok(());
    };
    let journal: DefinitionSaveJournal =
        serde_json::from_slice(&raw).context("parsing assistant definition save journal")?;
    if journal.name != row.name
        || journal.home_dir != row.home_dir
        || journal.config_json != row.config_json
    {
        bail!("assistant definition journal identity no longer matches registry row");
    }
    if markdown_content_hash(&journal.prior_markdown) != journal.prior_hash
        || markdown_content_hash(&journal.next_markdown) != journal.next_hash
    {
        bail!("assistant definition journal hashes do not match exact stored bytes");
    }
    for markdown in [&journal.prior_markdown, &journal.next_markdown] {
        let parsed = crate::agents::parse_daemon_local_markdown(markdown, &row.name)
            .context("parsing assistant definition journal version")?;
        validate_definition_identity(row, &parsed)?;
    }
    let target = assistant_definition_path(home);
    let current = cockpit_config::config::read_config_file_nofollow(&target)?
        .context("assistant definition is missing during journal recovery")?;
    let current_hash = sha256_hex(&current);
    if current_hash != journal.prior_hash && current_hash != journal.next_hash {
        bail!("assistant definition bytes conflict with both journal versions");
    }
    if row.content_hash == journal.next_hash {
        cockpit_config::config::write_config_bytes_atomic(
            &target,
            journal.next_markdown.as_bytes(),
        )?;
    } else if row.content_hash == journal.prior_hash {
        cockpit_config::config::write_config_bytes_atomic(
            &target,
            journal.prior_markdown.as_bytes(),
        )?;
    } else {
        bail!("assistant definition journal conflicts with registry revision");
    }
    cockpit_config::config::remove_config_file_atomic(&journal_path)?;
    // Re-read through the writer queue before returning so recovery never
    // reports a row different from the one it reconciled.
    let _ = get_assistant_blocking(db, &row.name)?;
    Ok(())
}

async fn recover_definition_journal(db: &Db, row: &AssistantRow) -> Result<()> {
    let db = db.clone();
    let row = row.clone();
    tokio::task::spawn_blocking(move || {
        let home = validate_row_home(&row)?;
        let target = assistant_definition_path(&home);
        let _guard = cockpit_config::config::hold_config_mutation_lock(&target)?;
        recover_definition_journal_locked(&db, &row)
    })
    .await
    .context("assistant definition recovery coordinator joined")?
}

pub async fn recover_definition_journals(db: &Db) -> Result<()> {
    let assistants_root = crate::config::resolve::cockpit_data_dir()?.join("assistants");
    match std::fs::read_dir(&assistants_root) {
        Ok(entries) => {
            for entry in entries {
                let entry = entry?;
                if entry.file_type()?.is_symlink() || !entry.file_type()?.is_dir() {
                    continue;
                }
                let home = entry.path();
                let db = db.clone();
                tokio::task::spawn_blocking(move || {
                    let target = assistant_definition_path(&home);
                    let _guard = cockpit_config::config::hold_config_mutation_lock(&target)?;
                    recover_creation_journal_locked(&db, &home)
                })
                .await
                .context("assistant creation recovery coordinator joined")??;
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    for row in db.list_assistants().await? {
        recover_definition_journal(db, &row).await?;
    }
    Ok(())
}

pub async fn save_definition_cas(
    db: &Db,
    row: AssistantRow,
    markdown: String,
    expected_revision: &str,
) -> Result<AssistantRow> {
    let db = db.clone();
    let expected_revision = expected_revision.to_string();
    tokio::task::spawn_blocking(move || {
        save_definition_cas_sync(&db, row, markdown, &expected_revision)
    })
    .await
    .context("assistant definition save coordinator joined")?
}

fn save_definition_cas_sync(
    db: &Db,
    row: AssistantRow,
    markdown: String,
    expected_revision: &str,
) -> Result<AssistantRow> {
    let home = validate_row_home(&row)?;
    let target = assistant_definition_path(&home);
    let _guard = cockpit_config::config::hold_config_mutation_lock(&target)?;
    recover_definition_journal_locked(db, &row)?;
    let current = cockpit_config::config::read_config_file_nofollow(&target)?
        .context("assistant definition is missing")?;
    let current = String::from_utf8(current).context("assistant definition is not valid UTF-8")?;
    if definition_revision(&row, &current) != expected_revision
        || row.content_hash != markdown_content_hash(&current)
    {
        bail!("assistant definition or registry changed; reload before saving");
    }
    let parsed = crate::agents::parse_daemon_local_markdown(&markdown, &row.name)?;
    validate_definition_identity(&row, &parsed)?;
    if current == markdown {
        return Ok(row);
    }
    let next_hash = markdown_content_hash(&markdown);
    let journal = DefinitionSaveJournal {
        name: row.name.clone(),
        home_dir: row.home_dir.clone(),
        config_json: row.config_json.clone(),
        prior_hash: row.content_hash.clone(),
        next_hash: next_hash.clone(),
        prior_markdown: current,
        next_markdown: markdown.clone(),
    };
    let encoded = serde_json::to_vec_pretty(&journal)?;
    let journal_path = definition_journal_path(&home);
    cockpit_config::config::write_config_bytes_atomic(&journal_path, &encoded)?;
    cockpit_config::config::write_config_bytes_atomic(&target, markdown.as_bytes())?;
    let expected = row.clone();
    let next_hash_for_db = next_hash.clone();
    let updated = match db.write_blocking(move |conn| {
        let changed = conn.execute(
            "UPDATE assistants SET content_hash=?5 WHERE name=?1 AND home_dir=?2 AND config_json=?3 AND content_hash=?4",
            rusqlite::params![expected.name, expected.home_dir, expected.config_json, expected.content_hash, next_hash_for_db],
        )?;
        if changed != 1 {
            bail!("assistant registry changed before definition commit");
        }
        crate::db::Db::get_assistant_conn(conn, &expected.name)?
            .context("assistant disappeared after definition update")
    }) {
        Ok(updated) => updated,
        Err(error) => {
            cockpit_config::config::write_config_bytes_atomic(
                &target,
                journal.prior_markdown.as_bytes(),
            )?;
            cockpit_config::config::remove_config_file_atomic(&journal_path)?;
            return Err(error);
        }
    };
    cockpit_config::config::remove_config_file_atomic(&journal_path)?;
    Ok(updated)
}

/// Remove only the registry binding while retaining the user's assistant home.
/// The same definition lock and journal recovery used by saves ensures delete
/// cannot race an in-flight file/row commit.
pub async fn delete_registration(db: &Db, name: &str, expected_revision: &str) -> Result<bool> {
    let db = db.clone();
    let name = name.to_string();
    let expected_revision = expected_revision.to_string();
    tokio::task::spawn_blocking(move || delete_registration_sync(&db, &name, &expected_revision))
        .await
        .context("assistant deletion coordinator joined")?
}

fn delete_registration_sync(db: &Db, name: &str, expected_revision: &str) -> Result<bool> {
    validate_assistant_name(name)?;
    let Some(row) = get_assistant_blocking(db, name)? else {
        return Ok(false);
    };
    let home = validate_row_home(&row)?;
    let target = assistant_definition_path(&home);
    let _guard = cockpit_config::config::hold_config_mutation_lock(&target)?;
    recover_creation_journal_locked(db, &home)?;
    let row = get_assistant_blocking(db, name)?
        .context("assistant disappeared during delete recovery")?;
    validate_row_home(&row)?;
    recover_definition_journal_locked(db, &row)?;
    let markdown = cockpit_config::config::read_config_file_nofollow(&target)?
        .context("assistant definition is missing during delete")?;
    let markdown = String::from_utf8(markdown).context("assistant definition is not UTF-8")?;
    if definition_revision(&row, &markdown) != expected_revision
        || markdown_content_hash(&markdown) != row.content_hash
    {
        bail!("assistant changed since delete confirmation");
    }
    db.write_blocking(move |conn| {
        let changed = conn.execute(
            "DELETE FROM assistants WHERE name=?1 AND created_at=?2 AND home_dir=?3 AND config_json=?4 AND content_hash=?5",
            rusqlite::params![row.name, row.created_at, row.home_dir, row.config_json, row.content_hash],
        )?;
        Ok(changed == 1)
    })
}

fn get_assistant_blocking(db: &Db, name: &str) -> Result<Option<AssistantRow>> {
    let name = name.to_string();
    db.write_blocking(move |conn| crate::db::Db::get_assistant_conn(conn, &name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assistant_def_parses_via_agent_parser() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("my-helper");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::write(
            assistant_definition_path(&home),
            "---\nagentId: local/00000000-0000-0000-0000-000000000001\ndescription: Helps with tests\nexecutionKind: assistant\nmodelSlots:\n  primary:\n    allowDefaultFallback: true\n    locality: any\n    minContextTokens: 1\n    purpose: Primary model\n    requiredCapabilities: [text_generation]\nschemaVersion: 2\n---\n\nStay focused.\n",
        )
        .unwrap();

        let def = load_from_home("my-helper", &home).unwrap();

        assert_eq!(def.name, "my-helper");
        assert_eq!(def.description, "Helps with tests");
        assert_eq!(def.agent.name, "my-helper");
        assert_eq!(def.agent.prompt, "Stay focused.");
        assert_eq!(
            def.agent.vnext.as_ref().map(|v| v.execution_kind),
            Some(ExecutionKind::Assistant)
        );
        assert!(def.agent.tools.is_none());
    }
}
