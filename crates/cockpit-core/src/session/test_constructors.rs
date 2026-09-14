//! Test/test-support session constructors. They open a vault for the given
//! `Db` so existing fixtures keep a four-argument `Session::create` shape.

use std::path::{Path, PathBuf};

use anyhow::Result;
use uuid::Uuid;

use super::Session;
use super::lifecycle::RedactionKeyResolverArc;
use crate::db::Db;

#[derive(Debug, Default)]
pub(crate) struct TestSessionRowOptions {
    model_selection: TestModelSelectionFields,
    session_entry_mode: Option<crate::daemon::proto::SessionEntryMode>,
    assistant: Option<TestAssistantFields>,
}

#[derive(Debug, Default)]
enum TestModelSelectionFields {
    #[default]
    None,
    Active(crate::config::providers::ActiveModelRef),
    Raw {
        provider: Option<String>,
        model: Option<String>,
        model_selection_json: Option<String>,
    },
}

#[derive(Debug)]
struct TestAssistantFields {
    name: String,
}

impl TestSessionRowOptions {
    pub(crate) fn with_model_selection(
        mut self,
        selection: crate::config::providers::ActiveModelRef,
    ) -> Self {
        self.model_selection = TestModelSelectionFields::Active(selection);
        self
    }

    pub(crate) fn with_raw_model_selection_fields(
        mut self,
        provider: Option<String>,
        model: Option<String>,
        model_selection_json: Option<String>,
    ) -> Self {
        self.model_selection = TestModelSelectionFields::Raw {
            provider,
            model,
            model_selection_json,
        };
        self
    }

    pub(crate) fn with_entry_mode(
        mut self,
        entry_mode: crate::daemon::proto::SessionEntryMode,
    ) -> Self {
        self.session_entry_mode = Some(entry_mode);
        self
    }

    pub(crate) fn with_assistant(mut self, assistant_name: impl Into<String>) -> Self {
        self.assistant = Some(TestAssistantFields {
            name: assistant_name.into(),
        });
        self
    }
}

impl Session {
    fn with_test_redaction_coverage(self) -> Result<Self> {
        let command_cache = crate::secret_command::CommandSecretCache::with_subprocess_executor();
        self.set_command_secret_cache(Some(command_cache.clone()));
        let config = crate::config::extended::RedactConfig::default();
        let policy_digest = crate::redact::coverage_bindings::redact_config_digest(&config);
        let environment = crate::env_snapshot::EnvSnapshot::new(
            cockpit_proto::EnvSnapshotSource::SessionWorker,
            Default::default(),
        );
        let vault_revision = self
            .secret_vault()
            .current_inventory_generation()
            .map_err(|error| anyhow::anyhow!("reading test redaction vault revision: {error}"))?;
        let principal = crate::daemon::principal::ClientPrincipal::owner();
        let inputs = crate::redact::coverage_bindings::SessionCoverageInputs {
            principal: &principal,
            owner_authorization_revision: 0,
            session_id: self.id,
            workspace_root: &self.project_root,
            environment: &environment,
            vault_revision,
            command_cache: &command_cache,
            policy_digest: &policy_digest,
            sealed: crate::redact::coverage_bindings::sealed_records_binding(&[]),
            override_revision: 0,
            redact_config: &config,
        };
        self.set_redaction_coverage(
            crate::redact::coverage_authority::RedactionCoverageAuthority::default(),
            inputs.coverage_key(),
            policy_digest,
        );
        Ok(self)
    }

    pub(crate) fn clear_redaction_coverage_for_test(&self) {
        *self.redaction_coverage.lock().unwrap() = None;
    }

    /// Build and insert a durable row that can be consumed by
    /// [`Session::resume_for_test`]. Raw-row fixtures use this boundary so the
    /// writer and resume validation share one synthetic project identity.
    pub(crate) async fn insert_row_for_test(
        db: &Db,
        project_root: &Path,
        active_agent: &str,
        options: TestSessionRowOptions,
    ) -> Result<cockpit_db::db::sessions::SessionRow> {
        let (project_root, project_id) = Self::test_session_identity(project_root);
        let project_root = project_root.to_string_lossy().into_owned();
        let active_agent = active_agent.to_string();
        let vault = crate::secure_key::vault_for_db(db)
            .map_err(|error| anyhow::anyhow!("opening vault for test session row: {error}"))?;
        db.transaction(move |conn| {
            let mut row = match options.assistant {
                Some(assistant) => {
                    if let Some(entry_mode) = options.session_entry_mode {
                        anyhow::ensure!(
                            entry_mode == crate::daemon::proto::SessionEntryMode::Assistant,
                            "assistant test row requires assistant entry mode"
                        );
                    }
                    crate::db::Db::build_new_assistant_session_row_conn(
                        conn,
                        &project_id,
                        &project_root,
                        &active_agent,
                        &assistant.name,
                    )?
                }
                None => crate::db::Db::build_new_session_row_conn(
                    conn,
                    &project_id,
                    &project_root,
                    &active_agent,
                )?,
            };
            match options.model_selection {
                TestModelSelectionFields::None => {}
                TestModelSelectionFields::Active(selection) => {
                    row.provider = Some(selection.provider.clone());
                    row.model = Some(selection.model.clone());
                    row.model_selection_json = Some(serde_json::to_string(&selection)?);
                }
                TestModelSelectionFields::Raw {
                    provider,
                    model,
                    model_selection_json,
                } => {
                    row.provider = provider;
                    row.model = model;
                    row.model_selection_json = model_selection_json;
                }
            }
            if let Some(entry_mode) = options.session_entry_mode {
                row.session_entry_mode = entry_mode.as_str().to_string();
            }
            super::lifecycle::persist_session_row_with_redaction_custody_on_conn(conn, &vault, &row)
        })
        .await
    }

    pub fn create_for_test(
        db: Db,
        project_root: PathBuf,
        active_agent: &str,
        resolver: RedactionKeyResolverArc,
    ) -> Result<Self> {
        let vault = crate::secure_key::vault_for_db(&db)
            .map_err(|e| anyhow::anyhow!("opening test session vault: {e}"))?;
        Self::create_with_test_workspace_root(db, project_root, active_agent, resolver, vault)?
            .with_test_redaction_coverage()
    }

    pub fn create_deferred_for_test(
        db: Db,
        project_root: PathBuf,
        active_agent: &str,
        resolver: RedactionKeyResolverArc,
    ) -> Result<Self> {
        let vault = crate::secure_key::vault_for_db(&db)
            .map_err(|e| anyhow::anyhow!("opening test session vault: {e}"))?;
        Self::create_deferred_with_test_workspace_root(
            db,
            project_root,
            active_agent,
            resolver,
            vault,
        )?
        .with_test_redaction_coverage()
    }

    pub fn create_assistant_deferred_for_test(
        db: Db,
        project_root: PathBuf,
        active_agent: &str,
        assistant_name: &str,
        resolver: RedactionKeyResolverArc,
    ) -> Result<Self> {
        let vault = crate::secure_key::vault_for_db(&db)
            .map_err(|e| anyhow::anyhow!("opening test session vault: {e}"))?;
        Self::create_assistant_deferred_with_test_workspace_root(
            db,
            project_root,
            active_agent,
            assistant_name,
            resolver,
            vault,
        )?
        .with_test_redaction_coverage()
    }

    pub fn create_fork_for_test(
        db: Db,
        parent_session_id: Uuid,
        fork_point_turn_id: Option<String>,
        resolver: RedactionKeyResolverArc,
    ) -> Result<Self> {
        let vault = crate::secure_key::vault_for_db(&db)
            .map_err(|e| anyhow::anyhow!("opening test session vault: {e}"))?;
        Self::create_fork_with_test_workspace_root(
            db,
            parent_session_id,
            fork_point_turn_id,
            resolver,
            vault,
        )?
        .with_test_redaction_coverage()
    }

    pub fn resume_for_test(
        db: Db,
        session_id: Uuid,
        resolver: RedactionKeyResolverArc,
    ) -> Result<Option<Self>> {
        let vault = crate::secure_key::vault_for_db(&db)
            .map_err(|e| anyhow::anyhow!("opening test session vault: {e}"))?;
        Self::resume_with_test_workspace_root(db, session_id, resolver, vault)?
            .map(Self::with_test_redaction_coverage)
            .transpose()
    }

    pub fn resume_strict_for_test(
        db: Db,
        session_id: Uuid,
        resolver: RedactionKeyResolverArc,
    ) -> Result<Option<Self>> {
        let vault = crate::secure_key::vault_for_db(&db)
            .map_err(|e| anyhow::anyhow!("opening test session vault: {e}"))?;
        Self::resume_with_strict_test_workspace_root(db, session_id, resolver, vault)?
            .map(Self::with_test_redaction_coverage)
            .transpose()
    }
}
