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
/// Daemon-owned identity backing the built-in `Assistant` primary.
///
/// The lower-case name is an internal persistence key; the user-facing root
/// agent remains the built-in `Assistant` definition.
pub const PRIMARY_ASSISTANT_IDENTITY_NAME: &str = "assistant";
const PRIMARY_ASSISTANT_INSTALLATION_ID: Uuid =
    Uuid::from_u128(0xa551_57a0_0000_4000_8000_0000_0000_0181);
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

/// A daemon-coordinated registry/definition snapshot.  A row-local damaged
/// definition is represented diagnostically so one bad assistant does not
/// hide the rest of the inventory. A non-canonical name/home remains a hard
/// containment error. Malformed config, definition identity conflicts, and
/// damaged recovery journals are registration-local diagnostics: normal loads
/// still fail closed, while the owner can unregister by registry CAS.
#[derive(Debug, Clone)]
pub struct AssistantSnapshot {
    pub row: AssistantRow,
    pub definition_markdown: Option<String>,
    pub definition_revision: Option<String>,
    pub definition_diagnostic: Option<String>,
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

/// Validate a user-managed named assistant. The daemon-owned identity for the
/// built-in primary is deliberately excluded from every ordinary CRUD/chat
/// entry point.
pub fn validate_named_assistant_name(name: &str) -> Result<()> {
    validate_assistant_name(name)?;
    if name == PRIMARY_ASSISTANT_IDENTITY_NAME {
        bail!("assistant name `{name}` is reserved for Cockpit's built-in Assistant primary");
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

/// Load an authority-bearing assistant definition through the one daemon
/// coordinator.  Callers must never combine a registry row obtained at one
/// instant with an uncoordinated pathname read at another.
pub async fn load_verified(db: &Db, name: &str) -> Result<Option<AssistantDef>> {
    let Some(snapshot) = snapshot(db, name).await? else {
        return Ok(None);
    };
    let markdown = snapshot.definition_markdown.with_context(|| {
        format!(
            "assistant `{name}` definition is unavailable: {}",
            snapshot
                .definition_diagnostic
                .as_deref()
                .unwrap_or("definition snapshot is incoherent")
        )
    })?;
    if snapshot
        .definition_revision
        .as_deref()
        .is_none_or(str::is_empty)
        || snapshot.definition_diagnostic.is_some()
    {
        bail!("assistant `{name}` definition snapshot is incoherent");
    }
    let agent = crate::agents::parse_daemon_local_markdown(&markdown, name)?;
    validate_definition_identity(&snapshot.row, &agent)?;
    Ok(Some(AssistantDef {
        name: name.to_string(),
        description: agent.description.clone(),
        home_dir: validate_row_home(&snapshot.row)?,
        agent,
    }))
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
    validate_named_assistant_name(&spec.name)?;
    create_assistant_with_installation_id_and_soul_edit_mode(
        db,
        spec,
        installation_id,
        identity::SoulEditMode::default(),
    )
    .await
}

async fn create_assistant_with_installation_id_and_soul_edit_mode(
    db: &Db,
    spec: CreateAssistantSpec,
    installation_id: Uuid,
    soul_edit_mode: identity::SoulEditMode,
) -> Result<AssistantRow> {
    let db = db.clone();
    tokio::task::spawn_blocking(move || {
        create_assistant_with_installation_id_sync(&db, spec, installation_id, soul_edit_mode)
    })
    .await
    .context("assistant creation coordinator joined")?
}

fn create_assistant_with_installation_id_sync(
    db: &Db,
    spec: CreateAssistantSpec,
    installation_id: Uuid,
    soul_edit_mode: identity::SoulEditMode,
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
    cockpit_host::private_fs::ensure_private_dir(&spec.home_dir)
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
        capabilities: None,
        tool_steering: None,
        context_policy: None,
        // Assistant homes are daemon-owned definition locations, so they are
        // the sole constructor allowed to use the local publisher. Tool/model
        // selections from the legacy wizard remain host-side setup inputs and
        // are intentionally absent from the serialized v2 definition.
        vnext: Some(vnext_for_private_assistant(installation_id)),
        prompt: spec.prompt,
        prompt_overrides: std::collections::BTreeMap::new(),
        package_files: None,
        mcp_bindings: Vec::new(),
        private_subagents: std::collections::BTreeMap::new(),
        source: path.clone(),
    };
    crate::agents::validate_invariants(&agent)?;
    let markdown = agent.to_markdown()?;
    identity::seed_identity_files(&spec.home_dir)?;
    cockpit_host::private_fs::ensure_private_dir(&spec.home_dir.join("knowledge")).with_context(
        || {
            format!(
                "creating assistant knowledge base {}",
                spec.home_dir.join("knowledge").display()
            )
        },
    )?;
    let config = AssistantConfig {
        installation_id,
        agent_source: path.to_string_lossy().into_owned(),
        soul_edit_mode,
        soul_hash: identity::hash_optional_file(&identity::soul_path(&spec.home_dir))?,
        user_hash: identity::hash_optional_file(&identity::user_path(&spec.home_dir))?,
        ..AssistantConfig::default()
    };
    let config_json = serde_json::to_string(&config)?;
    let content_hash = markdown_content_identity(db, &markdown)?;
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
    let row = db.blocking_write_for_sync_event(move |conn| {
        crate::db::Db::upsert_assistant_conn(conn, &name, &home_dir, &config_for_db, &hash_for_db)
    })?;
    cockpit_config::config::remove_config_file_atomic(&journal_path)?;
    Ok(row)
}

/// Provision the identity and normal assistant-owned knowledge base used by
/// the built-in `Assistant` primary. The assistant session keeps its built-in
/// root definition; this durable identity supplies only SOUL/USER state and
/// the standard assistant knowledge attachment.
pub async fn ensure_primary_assistant(db: &Db) -> Result<AssistantRow> {
    if let Some(row) = db.get_assistant(PRIMARY_ASSISTANT_IDENTITY_NAME).await? {
        return validate_primary_assistant(db, row).await;
    }

    let home_dir = default_home_dir(PRIMARY_ASSISTANT_IDENTITY_NAME)?;
    let spec = CreateAssistantSpec {
        name: PRIMARY_ASSISTANT_IDENTITY_NAME.to_string(),
        description: "Identity and knowledge base for Cockpit's built-in Assistant primary."
            .to_string(),
        prompt: "This daemon-owned assistant identity supplies personal context to Cockpit's built-in Assistant primary."
            .to_string(),
        home_dir,
    };
    match create_assistant_with_installation_id_and_soul_edit_mode(
        db,
        spec,
        PRIMARY_ASSISTANT_INSTALLATION_ID,
        identity::SoulEditMode::Autonomous,
    )
    .await
    {
        Ok(row) => Ok(row),
        Err(create_error) => match db.get_assistant(PRIMARY_ASSISTANT_IDENTITY_NAME).await? {
            // Another daemon/bootstrap race provisioned the same durable
            // identity. Use the stored row; no error-string matching or
            // duplicate home initialization is needed.
            Some(row) => validate_primary_assistant(db, row).await,
            None => Err(create_error).context("provisioning built-in Assistant identity"),
        },
    }
}

/// Change the daemon-owned Assistant primary's SOUL.md edit policy without
/// exposing its reserved persistence identity to ordinary assistant CRUD.
///
/// The primary starts autonomous, but the human may select `human_only` (or
/// the existing proposal-approval middle mode) at any time.  This owns the
/// configuration mutation under the same definition lock used by identity
/// recovery, so an in-flight identity publisher cannot overwrite the policy.
pub async fn set_primary_assistant_soul_edit_mode(
    db: &Db,
    soul_edit_mode: identity::SoulEditMode,
) -> Result<AssistantRow> {
    let db = db.clone();
    tokio::task::spawn_blocking(move || {
        set_primary_assistant_soul_edit_mode_sync(&db, soul_edit_mode)
    })
    .await
    .context("built-in Assistant soul-edit setting coordinator joined")?
}

fn set_primary_assistant_soul_edit_mode_sync(
    db: &Db,
    soul_edit_mode: identity::SoulEditMode,
) -> Result<AssistantRow> {
    let row = get_assistant_blocking(db, PRIMARY_ASSISTANT_IDENTITY_NAME)?
        .context("built-in Assistant identity is not provisioned")?;
    let home = validate_row_home(&row)?;
    validate_primary_assistant_config(&row, &home)?;
    let definition = assistant_definition_path(&home);
    let _guard = cockpit_config::config::hold_config_mutation_lock(&definition)?;
    recover_creation_journal_locked(db, &home)?;
    let row = get_assistant_blocking(db, PRIMARY_ASSISTANT_IDENTITY_NAME)?
        .context("built-in Assistant identity disappeared while updating SOUL edit mode")?;
    let home = validate_row_home(&row)?;
    validate_primary_assistant_config(&row, &home)?;
    recover_definition_journal_locked(db, &row)?;
    let row = get_assistant_blocking(db, PRIMARY_ASSISTANT_IDENTITY_NAME)?
        .context("built-in Assistant identity disappeared during definition recovery")?;
    let home = validate_row_home(&row)?;
    let mut config = validate_primary_assistant_config(&row, &home)?;
    config.soul_edit_mode = soul_edit_mode;
    let config_json = serde_json::to_string(&config)?;
    db.blocking_write_for_sync_event(move |conn| {
        crate::db::Db::update_assistant_identity_hashes_cas_conn(conn, row, &config_json)
    })
}

async fn validate_primary_assistant(db: &Db, row: AssistantRow) -> Result<AssistantRow> {
    let home = validate_row_home(&row)?;
    validate_primary_assistant_config(&row, &home)?;
    let definition = load_verified(db, PRIMARY_ASSISTANT_IDENTITY_NAME)
        .await?
        .context("built-in Assistant identity definition is missing")?;
    let vnext = definition
        .agent
        .vnext
        .context("built-in Assistant identity definition has no vNext provenance")?;
    anyhow::ensure!(
        vnext.agent_id == format!("local/{PRIMARY_ASSISTANT_INSTALLATION_ID}")
            && vnext.execution_kind == ExecutionKind::Assistant,
        "built-in Assistant identity definition provenance does not match its daemon installation"
    );
    Ok(row)
}

fn validate_primary_assistant_config(row: &AssistantRow, home: &Path) -> Result<AssistantConfig> {
    anyhow::ensure!(
        row.name == PRIMARY_ASSISTANT_IDENTITY_NAME,
        "built-in Assistant identity has an invalid registry name"
    );
    anyhow::ensure!(
        home == default_home_dir(PRIMARY_ASSISTANT_IDENTITY_NAME)?.as_path(),
        "built-in Assistant identity has an invalid daemon-owned home"
    );
    let config: AssistantConfig = serde_json::from_str(&row.config_json)
        .context("parsing built-in Assistant identity configuration")?;
    anyhow::ensure!(
        config.installation_id == PRIMARY_ASSISTANT_INSTALLATION_ID,
        "reserved assistant identity is not the daemon-owned built-in Assistant installation"
    );
    anyhow::ensure!(
        config.agent_source == assistant_definition_path(&home).to_string_lossy(),
        "built-in Assistant identity has invalid definition provenance"
    );
    Ok(config)
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
                models: Vec::new(),
            },
        )]),
        delegation: Default::default(),
        questions: None,
        verification: None,
        allowed_knowledge_bases: None,
    }
}

/// Snapshot every persisted private-assistant definition into the session's
/// daemon-owned UUID resolver.  Definitions are loaded once under the trusted
/// assistant-home boundary and then used directly for every child launch.
pub async fn local_installation_resolver(
    db: &Db,
) -> Result<crate::agents::LocalInstallationResolver> {
    let mut definitions = std::collections::BTreeMap::new();
    for snapshot in snapshots(db).await? {
        let row = snapshot.row;
        let config: AssistantConfig = serde_json::from_str(&row.config_json)
            .with_context(|| format!("parsing assistant config for `{}`", row.name))?;
        if config.installation_id.is_nil() {
            bail!(
                "assistant `{}` has no daemon-owned installation ID",
                row.name
            );
        }
        let markdown = snapshot.definition_markdown.with_context(|| {
            format!(
                "assistant `{}` definition is unavailable: {}",
                row.name,
                snapshot
                    .definition_diagnostic
                    .as_deref()
                    .unwrap_or("unknown error")
            )
        })?;
        if snapshot
            .definition_revision
            .as_deref()
            .is_none_or(str::is_empty)
            || snapshot.definition_diagnostic.is_some()
        {
            bail!("assistant `{}` definition snapshot is incoherent", row.name);
        }
        let definition = crate::agents::parse_daemon_local_markdown(&markdown, &row.name)?;
        validate_definition_identity(&row, &definition)?;
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
    validate_named_assistant_name(name)?;
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

/// Stable installation/vault-keyed identity for assistant definition bytes.
/// Unlike a plain digest this persisted registry token cannot be used as an
/// offline oracle for guessed prompts.
pub fn markdown_content_identity(db: &Db, markdown: &str) -> Result<String> {
    assistant_content_identity(db, markdown.as_bytes())
}

fn assistant_content_identity(db: &Db, bytes: &[u8]) -> Result<String> {
    let vault = crate::secure_key::open_for_db(db)
        .context("opening the assistant content-identity vault")?;
    Ok(crate::intel::hex_lower(&vault.keyed_request_identity(
        b"flycockpit.assistant.registry-content.v1",
        bytes,
    )))
}

pub fn definition_revision(row: &AssistantRow, markdown: &str) -> String {
    crate::daemon::authority_token::mint(
        b"assistant-definition-revision/v1",
        &[
            row.name.as_bytes(),
            row.home_dir.as_bytes(),
            row.config_json.as_bytes(),
            row.content_hash.as_bytes(),
            markdown.as_bytes(),
        ],
    )
}

pub fn registration_revision(row: &AssistantRow) -> String {
    crate::daemon::authority_token::mint(
        b"assistant-registration-revision/v1",
        &[
            &row.created_at_unix_ms.to_le_bytes(),
            row.name.as_bytes(),
            row.home_dir.as_bytes(),
            row.config_json.as_bytes(),
            row.content_hash.as_bytes(),
        ],
    )
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
    if markdown_content_identity(db, &journal.markdown)? != journal.content_hash {
        bail!("assistant creation journal hash does not match exact markdown bytes");
    }
    let target = assistant_definition_path(home);
    let row_for_validation = AssistantRow {
        name: journal.name.clone(),
        created_at_unix_ms: 0,
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
            Some(bytes) if assistant_content_identity(db, &bytes)? == journal.content_hash => {}
            Some(_) => bail!("assistant creation target conflicts with journal bytes"),
            None => cockpit_config::config::write_config_bytes_atomic(
                &target,
                journal.markdown.as_bytes(),
            )?,
        }
    } else {
        match cockpit_config::config::read_config_file_nofollow(&target)? {
            Some(bytes) if bytes == journal.markdown.as_bytes() => {}
            Some(_) => bail!(
                "assistant creation target exists without a registry row and conflicts with journal bytes"
            ),
            None => cockpit_config::config::write_config_bytes_atomic(
                &target,
                journal.markdown.as_bytes(),
            )?,
        }
        let name = journal.name.clone();
        let home_dir = journal.home_dir.clone();
        let config_json = journal.config_json.clone();
        let content_hash = journal.content_hash.clone();
        db.blocking_write_for_sync_event(move |conn| {
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
    if assistant_content_identity(db, &current)? != journal.content_hash {
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
    if markdown_content_identity(db, &journal.prior_markdown)? != journal.prior_hash
        || markdown_content_identity(db, &journal.next_markdown)? != journal.next_hash
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
    let current_hash = assistant_content_identity(db, &current)?;
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
    recover_unregister_journals(db).await?;
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

/// Read all assistant definitions through the same lock and recovery path as
/// save/delete/identity operations.
pub async fn snapshots(db: &Db) -> Result<Vec<AssistantSnapshot>> {
    let db = db.clone();
    tokio::task::spawn_blocking(move || {
        recover_unregister_journals_sync(&db)?;
        let rows = db.blocking_write_for_sync_event(crate::db::Db::list_assistants_conn)?;
        if rows.len() > cockpit_proto::MAX_ASSISTANT_SUMMARIES {
            bail!(
                "assistant inventory exceeds the {}-entry local response limit",
                cockpit_proto::MAX_ASSISTANT_SUMMARIES
            );
        }
        let mut names = std::collections::HashSet::new();
        let mut snapshots = Vec::with_capacity(rows.len());
        for row in rows {
            if !names.insert(row.name.clone()) {
                bail!("duplicate assistant registry name `{}`", row.name);
            }
            snapshots.push(snapshot_from_row_sync(&db, row)?);
        }
        Ok(snapshots)
    })
    .await
    .context("assistant snapshot coordinator joined")?
}

/// Read one assistant through the same lock and recovery path as mutations.
pub async fn snapshot(db: &Db, name: &str) -> Result<Option<AssistantSnapshot>> {
    validate_assistant_name(name)?;
    let db = db.clone();
    let name = name.to_string();
    tokio::task::spawn_blocking(move || {
        recover_unregister_journals_sync(&db)?;
        let Some(row) = get_assistant_blocking(&db, &name)? else {
            return Ok(None);
        };
        snapshot_from_row_sync(&db, row).map(Some)
    })
    .await
    .context("assistant snapshot coordinator joined")?
}

fn snapshot_from_row_sync(db: &Db, row: AssistantRow) -> Result<AssistantSnapshot> {
    let home = validate_row_home(&row)?;
    let target = assistant_definition_path(&home);
    let _guard = cockpit_config::config::hold_config_mutation_lock(&target)?;
    let unavailable = |row: AssistantRow, diagnostic: String| AssistantSnapshot {
        row,
        definition_markdown: None,
        definition_revision: None,
        definition_diagnostic: Some(diagnostic),
    };
    if let Err(error) = recover_creation_journal_locked(db, &home) {
        return Ok(unavailable(
            row,
            format!("assistant creation recovery is unavailable: {error:#}"),
        ));
    }
    let row = get_assistant_blocking(db, &row.name)?
        .context("assistant disappeared while acquiring its snapshot")?;
    validate_row_home(&row)?;
    if let Err(error) = recover_definition_journal_locked(db, &row) {
        return Ok(unavailable(
            row,
            format!("assistant definition recovery is unavailable: {error:#}"),
        ));
    }
    let row = get_assistant_blocking(db, &row.name)?
        .context("assistant disappeared during definition recovery")?;
    validate_row_home(&row)?;

    let Some(bytes) = cockpit_config::config::read_config_file_nofollow(&target)? else {
        return Ok(unavailable(row, "assistant definition is missing".into()));
    };
    if bytes.len() > cockpit_proto::MAX_AGENT_MARKDOWN_BYTES {
        return Ok(unavailable(
            row,
            format!(
                "assistant definition exceeds the {}-byte local response limit",
                cockpit_proto::MAX_AGENT_MARKDOWN_BYTES
            ),
        ));
    }
    if assistant_content_identity(db, &bytes)? != row.content_hash {
        return Ok(unavailable(
            row,
            "assistant definition does not match the registry content identity".into(),
        ));
    }
    let markdown = match String::from_utf8(bytes) {
        Ok(markdown) => markdown,
        Err(_) => {
            return Ok(unavailable(
                row,
                "assistant definition is not valid UTF-8".into(),
            ));
        }
    };
    let definition = match crate::agents::parse_daemon_local_markdown(&markdown, &row.name) {
        Ok(definition) => definition,
        Err(error) => {
            return Ok(unavailable(
                row,
                format!("assistant definition is invalid: {error:#}"),
            ));
        }
    };
    // A valid document claiming a different installation identity is an
    // authority violation, not ordinary row-local corruption.
    if let Err(error) = validate_definition_identity(&row, &definition) {
        return Ok(unavailable(
            row,
            format!("assistant definition identity/config is invalid: {error:#}"),
        ));
    }
    let revision = definition_revision(&row, &markdown);
    Ok(AssistantSnapshot {
        row,
        definition_markdown: Some(markdown),
        definition_revision: Some(revision),
        definition_diagnostic: None,
    })
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
    recover_creation_journal_locked(db, &home)?;
    let row = get_assistant_blocking(db, &row.name)?
        .context("assistant disappeared during creation recovery")?;
    validate_row_home(&row)?;
    recover_definition_journal_locked(db, &row)?;
    let row = get_assistant_blocking(db, &row.name)?
        .context("assistant disappeared during definition recovery")?;
    validate_row_home(&row)?;
    let current = cockpit_config::config::read_config_file_nofollow(&target)?
        .context("assistant definition is missing")?;
    let current = String::from_utf8(current).context("assistant definition is not valid UTF-8")?;
    if definition_revision(&row, &current) != expected_revision
        || row.content_hash != markdown_content_identity(db, &current)?
    {
        bail!("assistant definition or registry changed; reload before saving");
    }
    let parsed = crate::agents::parse_daemon_local_markdown(&markdown, &row.name)?;
    validate_definition_identity(&row, &parsed)?;
    if current == markdown {
        return Ok(row);
    }
    let next_hash = markdown_content_identity(db, &markdown)?;
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
    let updated = match db.blocking_write_for_sync_event(move |conn| {
        crate::db::Db::update_assistant_content_hash_cas_conn(
            conn,
            &expected.name,
            &expected.home_dir,
            &expected.config_json,
            &expected.content_hash,
            &next_hash_for_db,
        )
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
    recover_unregister_journals_sync(db)?;
    validate_named_assistant_name(name)?;
    let Some(row) = get_assistant_blocking(db, name)? else {
        return Ok(false);
    };
    let home = validate_row_home(&row)?;
    let target = assistant_definition_path(&home);
    let guard = cockpit_config::config::hold_config_mutation_lock(&target)?;
    let row = get_assistant_blocking(db, name)?
        .context("assistant disappeared while acquiring delete authority")?;
    validate_row_home(&row)?;
    if registration_revision(&row) != expected_revision {
        bail!("assistant registration changed since delete confirmation");
    }
    // Unregister is intentionally independent of definition parsing. Corrupt
    // or conflicting recovery inputs are moved out of the active namespace
    // under the same lock, retained for forensics, and restored if the row CAS
    // fails. They are never interpreted merely to authorize deletion.
    let operation_id = Uuid::new_v4().to_string();
    let mut journal = build_unregister_journal(&row, &home, operation_id)?;
    persist_unregister_journal(&journal)?;
    quarantine_unregister_journals(&guard, &home, &journal)?;
    journal.phase = UnregisterPhase::Quarantined;
    persist_unregister_journal(&journal)?;
    let deleted = delete_registered_row_cas(db, &journal)?;
    if !deleted {
        restore_unregister_journals(&guard, &home, &journal)?;
        remove_unregister_journal(&journal)?;
        return Ok(false);
    }
    journal.phase = UnregisterPhase::RegistryDeleted;
    persist_unregister_journal(&journal)?;
    remove_unregister_journal(&journal)?;
    Ok(true)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum UnregisterPhase {
    Prepared,
    Quarantined,
    RegistryDeleted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct UnregisterArtifact {
    active_name: String,
    retained_name: String,
    sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct UnregisterJournal {
    operation_id: String,
    phase: UnregisterPhase,
    name: String,
    created_at_unix_ms: i64,
    home_dir: String,
    config_json: String,
    content_hash: String,
    artifacts: Vec<UnregisterArtifact>,
}

fn row_matches_unregister_journal(row: &AssistantRow, journal: &UnregisterJournal) -> bool {
    row.name == journal.name
        && row.created_at_unix_ms == journal.created_at_unix_ms
        && row.home_dir == journal.home_dir
        && row.config_json == journal.config_json
        && row.content_hash == journal.content_hash
}

const UNREGISTER_ARTIFACT_NAMES: [(&str, &str); 2] = [
    (".assistant-creation.journal.json", "creation.journal.json"),
    (
        ".assistant-definition-save.journal.json",
        "definition-save.journal.json",
    ),
];

fn valid_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_unregister_artifacts(artifacts: &[UnregisterArtifact]) -> Result<()> {
    let mut previous_index = None;
    for artifact in artifacts {
        let index = UNREGISTER_ARTIFACT_NAMES
            .iter()
            .position(|names| artifact.active_name == names.0 && artifact.retained_name == names.1)
            .context("assistant unregister journal contains an unknown artifact identity")?;
        if previous_index.is_some_and(|previous| index <= previous) {
            bail!("assistant unregister journal artifact identities are duplicated or unordered");
        }
        if !valid_sha256_hex(&artifact.sha256) {
            bail!("assistant unregister journal artifact digest is invalid");
        }
        previous_index = Some(index);
    }
    Ok(())
}

fn validate_unregister_artifact_set(home: &Path, journal: &UnregisterJournal) -> Result<()> {
    let operation = quarantine_operation_dir(home, journal);
    for (active_name, retained_name) in UNREGISTER_ARTIFACT_NAMES {
        let declared = journal.artifacts.iter().find(|artifact| {
            artifact.active_name == active_name && artifact.retained_name == retained_name
        });
        let active = cockpit_config::config::read_config_file_nofollow(&home.join(active_name))?;
        let retained =
            cockpit_config::config::read_config_file_nofollow(&operation.join(retained_name))?;
        match (declared, active, retained) {
            (None, None, None) => {}
            (Some(artifact), Some(bytes), None) | (Some(artifact), None, Some(bytes))
                if sha256_hex(&bytes) == artifact.sha256 => {}
            _ => bail!("assistant unregister journal artifact set is not exact"),
        }
    }
    Ok(())
}

fn unregister_journal_root() -> Result<PathBuf> {
    Ok(crate::config::resolve::cockpit_data_dir()?
        .join("assistants")
        .join(".unregister-journals"))
}

fn unregister_journal_path(journal: &UnregisterJournal) -> Result<PathBuf> {
    Ok(unregister_journal_root()?.join(format!("{}.json", journal.operation_id)))
}

fn build_unregister_journal(
    row: &AssistantRow,
    home: &Path,
    operation_id: String,
) -> Result<UnregisterJournal> {
    let mut artifacts = Vec::new();
    for (active_name, retained_name) in UNREGISTER_ARTIFACT_NAMES {
        if let Some(bytes) =
            cockpit_config::config::read_config_file_nofollow(&home.join(active_name))?
        {
            artifacts.push(UnregisterArtifact {
                active_name: active_name.into(),
                retained_name: retained_name.into(),
                sha256: sha256_hex(&bytes),
            });
        }
    }
    Ok(UnregisterJournal {
        operation_id,
        phase: UnregisterPhase::Prepared,
        name: row.name.clone(),
        created_at_unix_ms: row.created_at_unix_ms,
        home_dir: row.home_dir.clone(),
        config_json: row.config_json.clone(),
        content_hash: row.content_hash.clone(),
        artifacts,
    })
}

fn persist_unregister_journal(journal: &UnregisterJournal) -> Result<()> {
    let root = unregister_journal_root()?;
    cockpit_host::private_fs::ensure_private_dir(&root)?;
    let bytes = serde_json::to_vec_pretty(journal)?;
    cockpit_config::config::write_config_bytes_atomic(&unregister_journal_path(journal)?, &bytes)?;
    cockpit_config::config::sync_directory_nofollow(&root)
}

fn remove_unregister_journal(journal: &UnregisterJournal) -> Result<()> {
    cockpit_config::config::remove_config_file_atomic(&unregister_journal_path(journal)?)?;
    cockpit_config::config::sync_directory_nofollow(&unregister_journal_root()?)
}

fn quarantine_operation_dir(home: &Path, journal: &UnregisterJournal) -> PathBuf {
    home.join(".assistant-unregister-quarantine")
        .join(&journal.operation_id)
}

fn quarantine_unregister_journals(
    guard: &cockpit_config::config::HeldConfigMutationLock,
    home: &Path,
    journal: &UnregisterJournal,
) -> Result<()> {
    let root = home.join(".assistant-unregister-quarantine");
    cockpit_host::private_fs::ensure_private_dir(&root)?;
    let operation = quarantine_operation_dir(home, journal);
    cockpit_host::private_fs::ensure_private_dir(&operation)?;
    cockpit_config::config::sync_directory_nofollow(&root)?;
    cockpit_config::config::sync_directory_nofollow(&operation)?;
    for artifact in &journal.artifacts {
        let active = home.join(&artifact.active_name);
        let retained = operation.join(&artifact.retained_name);
        match (
            cockpit_config::config::read_config_file_nofollow(&active)?,
            cockpit_config::config::read_config_file_nofollow(&retained)?,
        ) {
            (Some(bytes), None) if sha256_hex(&bytes) == artifact.sha256 => {
                cockpit_config::config::rename_config_file_nofollow(guard, &active, &retained)?;
            }
            (None, Some(bytes)) if sha256_hex(&bytes) == artifact.sha256 => {}
            _ => bail!("assistant unregister quarantine artifact identity is ambiguous"),
        }
    }
    cockpit_config::config::sync_directory_nofollow(&operation)?;
    cockpit_config::config::sync_directory_nofollow(home)?;
    Ok(())
}

fn restore_unregister_journals(
    guard: &cockpit_config::config::HeldConfigMutationLock,
    home: &Path,
    journal: &UnregisterJournal,
) -> Result<()> {
    let operation = quarantine_operation_dir(home, journal);
    for artifact in journal.artifacts.iter().rev() {
        let active = home.join(&artifact.active_name);
        let retained = operation.join(&artifact.retained_name);
        match (
            cockpit_config::config::read_config_file_nofollow(&active)?,
            cockpit_config::config::read_config_file_nofollow(&retained)?,
        ) {
            (None, Some(bytes)) if sha256_hex(&bytes) == artifact.sha256 => {
                cockpit_config::config::rename_config_file_nofollow(guard, &retained, &active)?;
            }
            (Some(bytes), None) if sha256_hex(&bytes) == artifact.sha256 => {}
            _ => bail!("assistant unregister rollback artifact identity is ambiguous"),
        }
    }
    cockpit_config::config::sync_directory_nofollow(home)?;
    Ok(())
}

fn delete_registered_row_cas(db: &Db, journal: &UnregisterJournal) -> Result<bool> {
    let journal = journal.clone();
    db.blocking_write_for_sync_event(move |conn| {
        let changed = conn.execute(
            "DELETE FROM assistants WHERE name=?1 AND created_at_unix_ms=?2 AND home_dir=?3 AND config_json=?4 AND content_hash=?5",
            rusqlite::params![journal.name, journal.created_at_unix_ms, journal.home_dir, journal.config_json, journal.content_hash],
        )?;
        Ok(changed == 1)
    })
}

pub async fn recover_unregister_journals(db: &Db) -> Result<()> {
    let db = db.clone();
    tokio::task::spawn_blocking(move || recover_unregister_journals_sync(&db))
        .await
        .context("assistant unregister recovery coordinator joined")?
}

fn recover_unregister_journals_sync(db: &Db) -> Result<()> {
    let root = unregister_journal_root()?;
    let entries = match std::fs::read_dir(&root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    for entry in entries {
        let entry = entry?;
        if entry.file_type()?.is_symlink() || !entry.file_type()?.is_file() {
            bail!("assistant unregister journal namespace contains a non-file entry");
        }
        let raw = cockpit_config::config::read_config_file_nofollow(&entry.path())?
            .context("assistant unregister journal disappeared")?;
        let mut journal: UnregisterJournal =
            serde_json::from_slice(&raw).context("parsing assistant unregister journal")?;
        let operation_id = Uuid::parse_str(&journal.operation_id)
            .context("assistant unregister journal operation ID is invalid")?;
        if operation_id.to_string() != journal.operation_id
            || entry.file_name() != format!("{}.json", journal.operation_id).as_str()
        {
            bail!("assistant unregister journal filename does not match its identity");
        }
        validate_assistant_name(&journal.name)?;
        let expected_home = default_home_dir(&journal.name)?;
        if Path::new(&journal.home_dir) != expected_home {
            bail!("assistant unregister journal identity is invalid");
        }
        validate_unregister_artifacts(&journal.artifacts)?;
        let target = assistant_definition_path(&expected_home);
        let guard = cockpit_config::config::hold_config_mutation_lock(&target)?;
        validate_unregister_artifact_set(&expected_home, &journal)?;
        let current = get_assistant_blocking(db, &journal.name)?;
        match (&journal.phase, current) {
            (UnregisterPhase::Prepared, Some(row))
                if row_matches_unregister_journal(&row, &journal) =>
            {
                quarantine_unregister_journals(&guard, &expected_home, &journal)?;
                journal.phase = UnregisterPhase::Quarantined;
                persist_unregister_journal(&journal)?;
                if !delete_registered_row_cas(db, &journal)? {
                    bail!("assistant unregister registry CAS failed during recovery");
                }
                journal.phase = UnregisterPhase::RegistryDeleted;
                persist_unregister_journal(&journal)?;
                remove_unregister_journal(&journal)?;
            }
            (UnregisterPhase::Prepared, None)
            | (UnregisterPhase::Quarantined, None)
            | (UnregisterPhase::RegistryDeleted, None) => {
                journal.phase = UnregisterPhase::RegistryDeleted;
                persist_unregister_journal(&journal)?;
                remove_unregister_journal(&journal)?;
            }
            (UnregisterPhase::Quarantined, Some(row))
                if row_matches_unregister_journal(&row, &journal) =>
            {
                quarantine_unregister_journals(&guard, &expected_home, &journal)?;
                if !delete_registered_row_cas(db, &journal)? {
                    bail!("assistant unregister registry CAS failed during recovery");
                }
                journal.phase = UnregisterPhase::RegistryDeleted;
                persist_unregister_journal(&journal)?;
                remove_unregister_journal(&journal)?;
            }
            (UnregisterPhase::Prepared | UnregisterPhase::Quarantined, Some(_)) => {
                restore_unregister_journals(&guard, &expected_home, &journal)?;
                remove_unregister_journal(&journal)?;
            }
            (UnregisterPhase::RegistryDeleted, Some(_)) => {
                bail!("assistant unregister journal conflicts with a recreated registration")
            }
        }
    }
    Ok(())
}

fn get_assistant_blocking(db: &Db, name: &str) -> Result<Option<AssistantRow>> {
    let name = name.to_string();
    db.blocking_write_for_sync_event(move |conn| crate::db::Db::get_assistant_conn(conn, &name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn assistant_definition_is_returned_by_daemon_coordinator_snapshot() {
        let env = crate::test_env::lock_async().await;
        let temp = tempfile::tempdir().unwrap();
        env.set_var("XDG_DATA_HOME", temp.path());
        let db = Db::open_in_memory().unwrap();
        let home = default_home_dir("my-helper").unwrap();
        create_assistant_with_installation_id(
            &db,
            CreateAssistantSpec {
                name: "my-helper".into(),
                description: "Helps with tests".into(),
                prompt: "Stay focused.".into(),
                home_dir: home.clone(),
            },
            Uuid::from_u128(1),
        )
        .await
        .unwrap();

        let snapshot = snapshot(&db, "my-helper").await.unwrap().unwrap();
        let def = crate::agents::parse_daemon_local_markdown(
            snapshot.definition_markdown.as_deref().unwrap(),
            "my-helper",
        )
        .unwrap();

        assert_eq!(def.name, "my-helper");
        assert_eq!(def.description, "Helps with tests");
        assert_eq!(def.prompt, "Stay focused.");
        assert_eq!(
            def.vnext.as_ref().map(|v| v.execution_kind),
            Some(ExecutionKind::Assistant)
        );
        assert!(def.tools.is_none());
        assert!(snapshot.definition_revision.is_some());
        assert!(snapshot.definition_diagnostic.is_none());
    }

    #[tokio::test]
    async fn primary_assistant_identity_is_provisioned_with_autonomous_soul_edits() {
        let env = crate::test_env::lock_async().await;
        let temp = tempfile::tempdir().unwrap();
        env.set_var("XDG_DATA_HOME", temp.path());
        let db = Db::open_in_memory().unwrap();

        let first = ensure_primary_assistant(&db).await.unwrap();
        let second = ensure_primary_assistant(&db).await.unwrap();
        let config: AssistantConfig = serde_json::from_str(&first.config_json).unwrap();

        assert_eq!(first.name, PRIMARY_ASSISTANT_IDENTITY_NAME);
        assert_eq!(second.name, PRIMARY_ASSISTANT_IDENTITY_NAME);
        assert_eq!(config.installation_id, PRIMARY_ASSISTANT_INSTALLATION_ID);
        assert_eq!(config.soul_edit_mode, identity::SoulEditMode::Autonomous);
        assert!(
            default_home_dir(PRIMARY_ASSISTANT_IDENTITY_NAME)
                .unwrap()
                .join("knowledge")
                .is_dir()
        );
    }

    #[tokio::test]
    async fn primary_assistant_soul_edit_mode_can_be_changed_to_human_only() {
        let env = crate::test_env::lock_async().await;
        let temp = tempfile::tempdir().unwrap();
        env.set_var("XDG_DATA_HOME", temp.path());
        let db = Db::open_in_memory().unwrap();

        ensure_primary_assistant(&db).await.unwrap();
        let updated = set_primary_assistant_soul_edit_mode(&db, identity::SoulEditMode::HumanOnly)
            .await
            .unwrap();
        let config: AssistantConfig = serde_json::from_str(&updated.config_json).unwrap();

        assert_eq!(config.soul_edit_mode, identity::SoulEditMode::HumanOnly);
        let reloaded = ensure_primary_assistant(&db).await.unwrap();
        assert_eq!(
            serde_json::from_str::<AssistantConfig>(&reloaded.config_json)
                .unwrap()
                .soul_edit_mode,
            identity::SoulEditMode::HumanOnly
        );
    }

    #[tokio::test]
    async fn ordinary_creation_cannot_claim_reserved_primary_identity() {
        let env = crate::test_env::lock_async().await;
        let temp = tempfile::tempdir().unwrap();
        env.set_var("XDG_DATA_HOME", temp.path());
        let db = Db::open_in_memory().unwrap();
        let error = create_assistant(
            &db,
            CreateAssistantSpec {
                name: PRIMARY_ASSISTANT_IDENTITY_NAME.into(),
                description: "ordinary assistant".into(),
                prompt: "ordinary prompt".into(),
                home_dir: default_home_dir(PRIMARY_ASSISTANT_IDENTITY_NAME).unwrap(),
            },
        )
        .await
        .unwrap_err();

        assert!(error.to_string().contains("reserved"), "{error:#}");
        assert!(
            db.get_assistant(PRIMARY_ASSISTANT_IDENTITY_NAME)
                .await
                .unwrap()
                .is_none()
        );
    }
}
