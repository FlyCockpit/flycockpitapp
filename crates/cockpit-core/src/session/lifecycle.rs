#![allow(deprecated)]

use std::path::Path;

use rusqlite::OptionalExtension;

use super::*;

/// Required protected redaction-history key resolver threaded into every
/// `Session` constructor (decision 16). Production installs the daemon's
/// `SecureKeyResolver`; tests pass [`super::test_redaction_key_resolver`].
pub(crate) type RedactionKeyResolverArc =
    Arc<dyn crate::redact::protected_redaction_history::RedactionKeyResolver>;

fn copy_vault_session_secrets(
    db: &crate::db::Db,
    vault: &crate::secure_key::SecretVault,
    parent: uuid::Uuid,
    child: uuid::Uuid,
) -> Result<()> {
    let parent_key = parent.to_string();
    let child_key = child.to_string();
    if let Ok(secret) = vault.get_item(
        cockpit_db::secret_vault::SecretVaultKind::RedactionTable,
        &crate::secure_key::redaction_table_item_id(&parent_key),
    ) {
        vault
            .put_item(
                cockpit_db::secret_vault::SecretVaultKind::RedactionTable,
                &crate::secure_key::redaction_table_item_id(&child_key),
                secret.as_slice(),
            )
            .map_err(|e| anyhow::anyhow!("copying redaction table vault item: {e}"))?;
    }
    let sealed_ids: Vec<(String, i64)> = db
        .blocking_write_for_sync_maintenance({
            let parent_key = parent_key.clone();
            move |conn| {
                let mut stmt =
                    conn.prepare("SELECT value_id FROM sealed_values WHERE session_id = ?1")?;
                let ids = stmt
                    .query_map(rusqlite::params![parent_key], |row| row.get::<_, String>(0))?
                    .collect::<std::result::Result<Vec<_>, _>>()?;
                let mut out = Vec::new();
                for value_id in ids {
                    let version: i64 = conn
                        .query_row(
                            "SELECT COALESCE(active_version, 1) FROM sealed_value_records
                              WHERE scope = 'session' AND scope_key = ?1 AND name = ?2",
                            rusqlite::params![parent_key, value_id],
                            |row| row.get(0),
                        )
                        .optional()
                        .map_err(anyhow::Error::from)?
                        .unwrap_or(1);
                    out.push((value_id, version.max(1)));
                }
                Ok(out)
            }
        })
        .context("listing parent sealed values for fork copy")?;
    for (value_id, version) in sealed_ids {
        let from = crate::secure_key::session_sealed_item_id(&parent_key, &value_id, version);
        let to = crate::secure_key::session_sealed_item_id(&child_key, &value_id, version);
        if let Ok(secret) = vault.get_item(
            cockpit_db::secret_vault::SecretVaultKind::SessionSealedValue,
            &from,
        ) {
            vault
                .put_item(
                    cockpit_db::secret_vault::SecretVaultKind::SessionSealedValue,
                    &to,
                    secret.as_slice(),
                )
                .map_err(|e| anyhow::anyhow!("copying session sealed vault item: {e}"))?;
        }
    }
    db.blocking_write_for_sync_maintenance({
        let child_key = child_key.clone();
        move |conn| {
            conn.execute(
                "UPDATE sessions SET redaction_table_json = NULL WHERE session_id = ?1",
                rusqlite::params![child_key],
            )?;
            conn.execute(
                "UPDATE sealed_values SET value = NULL WHERE session_id = ?1",
                rusqlite::params![child_key],
            )?;
            Ok(())
        }
    })
    .context("clearing plaintext columns on forked session")?;
    Ok(())
}

fn persist_redaction_table_to_vault(
    db: &crate::db::Db,
    vault: &Arc<crate::secure_key::SecretVault>,
    session_id: uuid::Uuid,
    json: &[u8],
) -> Result<()> {
    let item_id = crate::secure_key::redaction_table_item_id(&session_id.to_string());
    let json = json.to_vec();
    let session_key = session_id.to_string();
    let vault = vault.clone();
    db.blocking_write_for_sync_maintenance(move |conn| {
        conn.execute(
            "UPDATE sessions SET redaction_table_json = NULL WHERE session_id = ?1",
            rusqlite::params![session_key],
        )
        .context("clearing plaintext session redaction column")?;
        vault
            .put_item_on_conn(
                conn,
                cockpit_db::secret_vault::SecretVaultKind::RedactionTable,
                &item_id,
                &json,
            )
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        Ok(())
    })
    .context("persisting session redaction table")
}

pub(crate) fn load_redaction_table_from_vault(
    vault: &crate::secure_key::SecretVault,
    session_id: uuid::Uuid,
) -> Result<Option<String>> {
    let item_id = crate::secure_key::redaction_table_item_id(&session_id.to_string());
    match vault.get_item(
        cockpit_db::secret_vault::SecretVaultKind::RedactionTable,
        &item_id,
    ) {
        Ok(secret) => Ok(Some(
            String::from_utf8(secret.as_slice().to_vec())
                .context("redaction table vault item is not UTF-8")?,
        )),
        Err(crate::secure_key::SecureKeyError::NotFound(_)) => Ok(None),
        Err(error) => Err(anyhow::anyhow!(
            "reading redaction table vault item: {error}"
        )),
    }
}

fn capture_model_system_prompt_snapshot_json(project_root: &std::path::Path) -> String {
    let (_, providers) = crate::auto_title::load_configs_for(project_root);
    ModelSystemPromptSnapshot::capture(&providers).to_json_string()
}

fn capture_knowledge_base_prompt_snapshot_json(
    db: &Db,
    config: &crate::config::extended::ExtendedConfig,
    project_root: &std::path::Path,
    assistant_name: Option<&str>,
    allowed_knowledge_bases: Option<&std::collections::BTreeSet<String>>,
    trust_mode: crate::db::workspace_trust::WorkspaceTrustMode,
) -> Result<String> {
    let config = config.clone();
    let project_root = project_root.to_string_lossy().into_owned();
    let assistant_name = assistant_name.map(str::to_owned);
    let allowed_knowledge_bases = allowed_knowledge_bases.cloned();
    db.blocking_write_for_sync_maintenance(move |conn| {
        crate::knowledge::KnowledgeBasePromptSnapshot::capture(
            &config,
            conn,
            &project_root,
            assistant_name.as_deref(),
            allowed_knowledge_bases.as_ref(),
            trust_mode,
        )
        .map(|snapshot| snapshot.to_json_string())
    })
    .context("capturing knowledge-base prompt snapshot")
}

/// An uncommitted KB prompt snapshot captured for one exact root definition.
/// Construct the root with [`Self::system_prefix`] before committing it, so a
/// failed root rebuild can never replace the running agent's cached prefix.
pub(crate) struct CapturedKnowledgeBasePromptSnapshot {
    raw: String,
    snapshot: Arc<crate::knowledge::KnowledgeBasePromptSnapshot>,
}

impl CapturedKnowledgeBasePromptSnapshot {
    pub(crate) fn system_prefix(&self) -> String {
        self.snapshot.render_system_block()
    }
}

impl Session {
    /// Derive a session project id. Production sessions always prove the
    /// workspace directory identity; synthetic test roots retain a separate,
    /// deterministic test-only namespace and never publish workspace state.
    fn project_id_for_session_root(
        project_root: &Path,
        initialize_workspace_scratch: bool,
    ) -> Result<String> {
        if initialize_workspace_scratch {
            return project_id_for(project_root);
        }
        Ok(super::project_id_from_workspace_object(&format!(
            "cockpit-synthetic-test-workspace-root-v1\\0{}",
            project_root.display()
        )))
    }

    #[cfg(any(test, feature = "test-support"))]
    fn test_workspace_root(project_root: PathBuf) -> (PathBuf, bool) {
        // Test fixtures commonly use stable synthetic paths (for example
        // `/proj`) to exercise path policy without creating host files.
        // Prefer production identity when the fixture root exists.
        match std::fs::canonicalize(&project_root) {
            Ok(canonical_root) => (canonical_root, true),
            Err(_) => (project_root, false),
        }
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn create_with_test_workspace_root(
        db: Db,
        project_root: PathBuf,
        active_agent: &str,
        resolver: RedactionKeyResolverArc,
        vault: Arc<crate::secure_key::SecretVault>,
    ) -> Result<Self> {
        let (project_root, initialize_workspace_scratch) = Self::test_workspace_root(project_root);
        let project_id =
            Self::project_id_for_session_root(&project_root, initialize_workspace_scratch)?;
        let project_root_str = project_root.to_string_lossy().into_owned();
        let project_id_for_db = project_id.clone();
        let project_root_for_db = project_root_str.clone();
        let active_agent_for_db = active_agent.to_string();
        let mut row = db.blocking_write_for_sync_maintenance(move |conn| {
            crate::db::Db::build_new_session_row_conn(
                conn,
                &project_id_for_db,
                &project_root_for_db,
                &active_agent_for_db,
            )
        })?;
        row.model_system_prompt_snapshot_json =
            capture_model_system_prompt_snapshot_json(&project_root);
        let row_for_db = row.clone();
        let row = db
            .blocking_write_for_sync_maintenance(move |conn| {
                crate::db::Db::insert_session_row_conn(conn, &row_for_db)
            })
            .context("creating test session row")?;
        Self::from_row(
            db,
            project_root,
            row,
            resolver,
            vault,
            true,
            initialize_workspace_scratch,
        )
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn create_deferred_with_test_workspace_root(
        db: Db,
        project_root: PathBuf,
        active_agent: &str,
        resolver: RedactionKeyResolverArc,
        vault: Arc<crate::secure_key::SecretVault>,
    ) -> Result<Self> {
        let (project_root, initialize_workspace_scratch) = Self::test_workspace_root(project_root);
        let project_id =
            Self::project_id_for_session_root(&project_root, initialize_workspace_scratch)?;
        let project_root_str = project_root.to_string_lossy().into_owned();
        let project_id_for_db = project_id.clone();
        let project_root_for_db = project_root_str.clone();
        let active_agent_for_db = active_agent.to_string();
        let mut row = db
            .blocking_write_for_sync_maintenance(move |conn| {
                crate::db::Db::build_new_session_row_conn(
                    conn,
                    &project_id_for_db,
                    &project_root_for_db,
                    &active_agent_for_db,
                )
            })
            .context("building deferred test session row")?;
        row.model_system_prompt_snapshot_json =
            capture_model_system_prompt_snapshot_json(&project_root);
        let session = Self::from_row(
            db,
            project_root,
            row.clone(),
            resolver,
            vault,
            true,
            initialize_workspace_scratch,
        )?;
        *session.pending_row.lock().unwrap() = Some(row);
        Ok(session)
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn create_assistant_deferred_with_test_workspace_root(
        db: Db,
        project_root: PathBuf,
        active_agent: &str,
        assistant_name: &str,
        resolver: RedactionKeyResolverArc,
        vault: Arc<crate::secure_key::SecretVault>,
    ) -> Result<Self> {
        let (project_root, initialize_workspace_scratch) = Self::test_workspace_root(project_root);
        let project_id =
            Self::project_id_for_session_root(&project_root, initialize_workspace_scratch)?;
        let project_root_str = project_root.to_string_lossy().into_owned();
        let project_id_for_db = project_id.clone();
        let project_root_for_db = project_root_str.clone();
        let active_agent_for_db = active_agent.to_string();
        let assistant_name_for_db = assistant_name.to_string();
        let mut row = db
            .blocking_write_for_sync_maintenance(move |conn| {
                crate::db::Db::build_new_assistant_session_row_conn(
                    conn,
                    &project_id_for_db,
                    &project_root_for_db,
                    &active_agent_for_db,
                    &assistant_name_for_db,
                )
            })
            .context("building deferred assistant test session row")?;
        row.model_system_prompt_snapshot_json =
            capture_model_system_prompt_snapshot_json(&project_root);
        let session = Self::from_row(
            db,
            project_root,
            row.clone(),
            resolver,
            vault,
            true,
            initialize_workspace_scratch,
        )?;
        *session.pending_row.lock().unwrap() = Some(row);
        Ok(session)
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn create_fork_with_test_workspace_root(
        db: Db,
        parent_session_id: Uuid,
        fork_point_turn_id: Option<String>,
        resolver: RedactionKeyResolverArc,
        vault: Arc<crate::secure_key::SecretVault>,
    ) -> Result<Self> {
        let row = db
            .blocking_write_for_sync_maintenance(move |conn| {
                crate::db::Db::create_fork_conn(
                    conn,
                    parent_session_id,
                    fork_point_turn_id,
                    false,
                    false,
                    Uuid::new_v4(),
                    Utc::now().timestamp_millis(),
                )
            })
            .context("creating test fork session row")?;
        copy_vault_session_secrets(&db, &vault, parent_session_id, row.session_id)
            .context("copying vault sealed values and redaction table into test fork")?;
        let (project_root, initialize_workspace_scratch) =
            Self::test_workspace_root(PathBuf::from(&row.project_root));
        Self::from_row(
            db,
            project_root,
            row,
            resolver,
            vault,
            false,
            initialize_workspace_scratch,
        )
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn resume_with_test_workspace_root(
        db: Db,
        session_id: Uuid,
        resolver: RedactionKeyResolverArc,
        vault: Arc<crate::secure_key::SecretVault>,
    ) -> Result<Option<Self>> {
        let Some(row) = db
            .blocking_write_for_sync_maintenance(move |conn| {
                crate::db::Db::get_session_conn(conn, session_id)
            })
            .context("fetching test session")?
        else {
            return Ok(None);
        };
        let (project_root, initialize_workspace_scratch) =
            Self::test_workspace_root(PathBuf::from(&row.project_root));
        Ok(Some(Self::from_row(
            db,
            project_root,
            row,
            resolver,
            vault,
            false,
            initialize_workspace_scratch,
        )?))
    }

    /// Create a brand-new session, inserting its row in the DB.
    #[allow(dead_code)]
    pub fn create(
        db: Db,
        project_root: PathBuf,
        active_agent: &str,
        _config: &crate::config::extended::ExtendedConfig,
        resolver: RedactionKeyResolverArc,
        vault: Arc<crate::secure_key::SecretVault>,
    ) -> Result<Self> {
        let project_root = canonical_workspace_root(&project_root)?;
        let project_id = project_id_for(&project_root)?;
        let project_root_str = project_root.to_string_lossy().into_owned();
        let project_id_for_db = project_id.clone();
        let project_root_for_db = project_root_str.clone();
        let active_agent_for_db = active_agent.to_string();
        let mut row = db.blocking_write_for_sync_maintenance(move |conn| {
            crate::db::Db::build_new_session_row_conn(
                conn,
                &project_id_for_db,
                &project_root_for_db,
                &active_agent_for_db,
            )
        })?;
        row.model_system_prompt_snapshot_json =
            capture_model_system_prompt_snapshot_json(&project_root);
        // The worker freezes this only after the actual root has been loaded.
        // Capturing it here from a separately resolved name would let a
        // filesystem-backed definition change before the root is constructed.
        let row_for_db = row.clone();
        let row = db
            .blocking_write_for_sync_maintenance(move |conn| {
                crate::db::Db::insert_session_row_conn(conn, &row_for_db)
            })
            .context("creating session row")?;
        Self::from_row(db, project_root, row, resolver, vault, true, true)
    }

    /// Create a brand-new session held **in memory only** — its `sessions`
    /// row is not written yet (session-id-display-and-lazy-persist). The id
    /// and short_id exist immediately (so the TUI can show the id at
    /// startup), but the row lands in the DB only on the first user message
    /// via [`Self::persist_if_needed`]. A session created this way and never
    /// persisted leaves no DB trace and never appears in `session list`.
    pub fn create_deferred(
        db: Db,
        project_root: PathBuf,
        active_agent: &str,
        resolver: RedactionKeyResolverArc,
        vault: Arc<crate::secure_key::SecretVault>,
    ) -> Result<Self> {
        let project_root = canonical_workspace_root(&project_root)?;
        let project_id = project_id_for(&project_root)?;
        let project_root_str = project_root.to_string_lossy().into_owned();
        let project_id_for_db = project_id.clone();
        let project_root_for_db = project_root_str.clone();
        let active_agent_for_db = active_agent.to_string();
        let mut row = db
            .blocking_write_for_sync_maintenance(move |conn| {
                crate::db::Db::build_new_session_row_conn(
                    conn,
                    &project_id_for_db,
                    &project_root_for_db,
                    &active_agent_for_db,
                )
            })
            .context("building deferred session row")?;
        row.model_system_prompt_snapshot_json =
            capture_model_system_prompt_snapshot_json(&project_root);
        let session = Self::from_row(db, project_root, row.clone(), resolver, vault, true, true)?;
        *session.pending_row.lock().unwrap() = Some(row);
        Ok(session)
    }

    /// Set immutable entry setup while the new row is still deferred.  Once a
    /// session is durable this metadata must be matched, never rewritten, by
    /// subsequent Attach requests.
    pub(crate) fn set_deferred_entry_mode(
        &mut self,
        mode: crate::daemon::proto::SessionEntryMode,
    ) -> Result<()> {
        anyhow::ensure!(
            self.pending_row.lock().unwrap().is_some(),
            "entry mode may only be set before a new session is persisted"
        );
        self.session_entry_mode = mode;
        let staged =
            self.stage_pending_row(|row| row.session_entry_mode = mode.as_str().to_string());
        anyhow::ensure!(
            staged,
            "deferred session row disappeared while setting entry mode"
        );
        Ok(())
    }

    /// Mark a newly-created daemon session as a knowledge-dream transcript
    /// before its deferred row can be persisted. The flag is intentionally
    /// creation-only: a normal user transcript must never be retroactively
    /// hidden from default recall.
    pub(crate) fn set_deferred_dream_session(&self) -> Result<()> {
        anyhow::ensure!(
            self.pending_row.lock().unwrap().is_some(),
            "dream-session flag may only be set before a new session is persisted"
        );
        anyhow::ensure!(
            self.stage_pending_row(|row| row.is_dream_session = true),
            "deferred session row disappeared while marking dream transcript"
        );
        Ok(())
    }

    /// Capture the stable KB facts for the exact definition that is about to
    /// become the root.  The definition is supplied by the successful root
    /// loader, rather than re-resolved by name, so workspace edits cannot
    /// split the prompt allowlist from the live tool/retrieval allowlist.
    pub(crate) fn capture_knowledge_base_prompt_snapshot_for_agent(
        &self,
        config: &crate::config::extended::ExtendedConfig,
        definition: &crate::agents::AgentDef,
        trust_mode: crate::db::workspace_trust::WorkspaceTrustMode,
    ) -> Result<CapturedKnowledgeBasePromptSnapshot> {
        let raw = capture_knowledge_base_prompt_snapshot_json(
            &self.db,
            config,
            &self.project_root,
            self.assistant_name.as_deref(),
            definition.allowed_knowledge_bases(),
            trust_mode,
        )?;
        Ok(CapturedKnowledgeBasePromptSnapshot {
            snapshot: Arc::new(crate::knowledge::KnowledgeBasePromptSnapshot::from_json_str(&raw)),
            raw,
        })
    }

    /// Publish a root-definition-bound KB snapshot together with the
    /// session's in-memory view.  Dream completion never calls this method;
    /// only root construction/replacement may change the cached prefix.
    pub(crate) fn commit_knowledge_base_prompt_snapshot(
        &self,
        captured: CapturedKnowledgeBasePromptSnapshot,
    ) -> Result<()> {
        if self.stage_pending_row(|row| {
            row.knowledge_base_prompt_snapshot_json = captured.raw.clone();
            row.knowledge_base_prompt_snapshot_captured = true;
        }) {
            *self
                .knowledge_base_prompt_snapshot
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = captured.snapshot;
            self.knowledge_base_prompt_snapshot_captured
                .store(true, std::sync::atomic::Ordering::Release);
            return Ok(());
        }
        let session_id = self.id;
        let raw = captured.raw.clone();
        self.db
            .blocking_write_for_sync_maintenance(move |conn| {
                let changed = conn
                    .execute(
                        "UPDATE sessions
                     SET knowledge_base_prompt_snapshot_json = ?1,
                         knowledge_base_prompt_snapshot_captured = 1
                     WHERE session_id = ?2",
                        rusqlite::params![raw, session_id.to_string()],
                    )
                    .context("updating session knowledge-base prompt snapshot")?;
                anyhow::ensure!(
                    changed == 1,
                    "session disappeared while updating its knowledge-base prompt snapshot"
                );
                Ok(())
            })
            .context("persisting session knowledge-base prompt snapshot")?;
        *self
            .knowledge_base_prompt_snapshot
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = captured.snapshot;
        self.knowledge_base_prompt_snapshot_captured
            .store(true, std::sync::atomic::Ordering::Release);
        Ok(())
    }

    pub fn session_entry_mode(&self) -> crate::daemon::proto::SessionEntryMode {
        self.session_entry_mode
    }

    /// Create a brand-new assistant session held in memory only. Mirrors
    /// [`Self::create_deferred`], but carries `assistant_name` in the pending
    /// row so the eventual first user message persists the assistant session
    /// atomically with the rest of the deferred session metadata.
    pub fn create_assistant_deferred(
        db: Db,
        project_root: PathBuf,
        active_agent: &str,
        assistant_name: &str,
        resolver: RedactionKeyResolverArc,
        vault: Arc<crate::secure_key::SecretVault>,
    ) -> Result<Self> {
        let project_root = canonical_workspace_root(&project_root)?;
        let project_id = project_id_for(&project_root)?;
        let project_root_str = project_root.to_string_lossy().into_owned();
        let project_id_for_db = project_id.clone();
        let project_root_for_db = project_root_str.clone();
        let active_agent_for_db = active_agent.to_string();
        let assistant_name_for_db = assistant_name.to_string();
        let mut row = db
            .blocking_write_for_sync_maintenance(move |conn| {
                crate::db::Db::build_new_assistant_session_row_conn(
                    conn,
                    &project_id_for_db,
                    &project_root_for_db,
                    &active_agent_for_db,
                    &assistant_name_for_db,
                )
            })
            .context("building deferred assistant session row")?;
        row.model_system_prompt_snapshot_json =
            capture_model_system_prompt_snapshot_json(&project_root);
        let session = Self::from_row(db, project_root, row.clone(), resolver, vault, true, true)?;
        *session.pending_row.lock().unwrap() = Some(row);
        Ok(session)
    }

    /// Write the deferred `sessions` row if it hasn't been written yet, and
    /// return `true` when this call performed the write
    /// (session-id-display-and-lazy-persist). Idempotent: a no-op (returns
    /// `false`) for an already-persisted session — including every session
    /// created via [`Self::create`] / [`Self::resume`] / [`Self::create_fork`],
    /// which are persisted from the start.
    ///
    /// This is the **only** flush point, and it MUST be called before any
    /// row that references the session (agent-tree, write-scope, tool_calls,
    /// inference_calls, locks, …) so the FK/ordering invariant holds. A
    /// deferred session stays in-memory until the first user message (or an
    /// ephemeral-daemon attach that must survive process exit). The stored
    /// row carries the latest provider/model so a model picked before the
    /// flush survives.
    pub fn persist_if_needed(&self) -> Result<bool> {
        // Model mutation and the deferred INSERT share this lock so a picker
        // update cannot be overwritten by an older selection snapshot.
        let selection = self.model_selection.lock().unwrap();
        let model_selection_json = selection
            .as_ref()
            .map(|active| serde_json::to_string(&active))
            .transpose()
            .context("encoding deferred session model selection")?;
        let row = {
            let mut slot = self.pending_row.lock().unwrap();
            match slot.take() {
                Some(mut row) => {
                    row.provider = selection.as_ref().map(|active| active.provider.clone());
                    row.model = selection.as_ref().map(|active| active.model.clone());
                    row.model_selection_json = model_selection_json;
                    row.tool_surface_override_json = self.tool_surface_override_json();
                    row.goal_settings_override_json = self.goal_settings_override_json();
                    row.redaction_table_json = self.redaction_table_json.lock().unwrap().clone();
                    row
                }
                None => return Ok(false),
            }
        };
        let row_for_db = row.clone();
        match self.db.blocking_write_for_sync_maintenance(move |conn| {
            crate::db::Db::insert_session_row_conn(conn, &row_for_db)
        }) {
            Ok(persisted) => {
                if let Some(short_id) = persisted.short_id {
                    *self
                        .short_id
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner()) = short_id;
                }
            }
            Err(e) => {
                // Restore the pending row so a transient failure can retry on
                // the next user message rather than silently losing the session.
                *self.pending_row.lock().unwrap() = Some(row);
                return Err(e).context("persisting deferred session row");
            }
        }
        let session_id = self.id;
        if row.last_viewed_at_unix_ms.is_some()
            && let Err(e) = self.db.blocking_write_for_sync_maintenance(move |conn| {
                conn.execute(
                    "UPDATE sessions SET last_viewed_at_unix_ms = ?1 WHERE session_id = ?2",
                    params![Utc::now().timestamp_millis(), session_id.to_string()],
                )
                .context("marking session viewed")?;
                Ok(())
            })
        {
            tracing::warn!(error = %e, "persisting deferred session viewed marker failed");
        }
        Ok(true)
    }

    pub(super) fn stage_pending_row(&self, update: impl FnOnce(&mut SessionRow)) -> bool {
        let mut slot = self.pending_row.lock().unwrap();
        if let Some(row) = slot.as_mut() {
            update(row);
            true
        } else {
            false
        }
    }

    /// Whether this session's `sessions` row has been written
    /// (session-id-display-and-lazy-persist). `false` only for a deferred
    /// session that has not yet seen its first user message; `true`
    /// otherwise.
    pub fn is_persisted(&self) -> bool {
        self.pending_row.lock().unwrap().is_none()
    }

    /// Branch a fork from `parent` at `fork_point_turn_id` (None = tail).
    /// The new session inherits the parent's project, agent, provider,
    /// and model; its conversation history is reconstructed by the
    /// daemon from the parent's transcript up to the fork point.
    pub fn create_fork(
        db: Db,
        parent_session_id: Uuid,
        fork_point_turn_id: Option<String>,
        resolver: RedactionKeyResolverArc,
        vault: Arc<crate::secure_key::SecretVault>,
    ) -> Result<Self> {
        let row = db
            .blocking_write_for_sync_maintenance(move |conn| {
                crate::db::Db::create_fork_conn(
                    conn,
                    parent_session_id,
                    fork_point_turn_id,
                    false,
                    false,
                    Uuid::new_v4(),
                    Utc::now().timestamp_millis(),
                )
            })
            .context("creating fork session row")?;
        copy_vault_session_secrets(&db, &vault, parent_session_id, row.session_id)
            .context("copying vault sealed values and redaction table into fork")?;
        let project_root = PathBuf::from(&row.project_root);
        Self::from_row(db, project_root, row, resolver, vault, false, true)
    }

    /// Resume an existing session. Returns `None` if the id is unknown.
    /// Backfills `short_id` if missing (lazy migration from pre-§17 rows).
    pub fn resume(
        db: Db,
        session_id: Uuid,
        resolver: RedactionKeyResolverArc,
        vault: Arc<crate::secure_key::SecretVault>,
    ) -> Result<Option<Self>> {
        let Some(row) = db
            .blocking_write_for_sync_maintenance(move |conn| {
                crate::db::Db::get_session_conn(conn, session_id)
            })
            .context("fetching session")?
        else {
            return Ok(None);
        };
        let project_root = PathBuf::from(&row.project_root);
        Ok(Some(Self::from_row(
            db,
            project_root,
            row,
            resolver,
            vault,
            false,
            true,
        )?))
    }

    fn from_row(
        db: Db,
        project_root: PathBuf,
        row: SessionRow,
        resolver: RedactionKeyResolverArc,
        vault: Arc<crate::secure_key::SecretVault>,
        freshly_created: bool,
        initialize_workspace_scratch: bool,
    ) -> Result<Self> {
        let project_root = if initialize_workspace_scratch {
            canonical_workspace_root(&project_root)
                .context("canonicalizing persisted session workspace root")?
        } else {
            // Test-support constructors deliberately permit synthetic roots
            // such as `/proj`. Preserve canonicalization when possible so
            // fixtures using real roots keep production-equivalent identity.
            std::fs::canonicalize(&project_root).unwrap_or(project_root)
        };
        anyhow::ensure!(
            Self::project_id_for_session_root(&project_root, initialize_workspace_scratch)?
                == row.project_id,
            "persisted session project id does not match canonical workspace root"
        );
        let session_entry_mode = match row.session_entry_mode.as_str() {
            "code" => crate::daemon::proto::SessionEntryMode::Code,
            "assistant" => crate::daemon::proto::SessionEntryMode::Assistant,
            "computer" => crate::daemon::proto::SessionEntryMode::Computer,
            invalid => anyhow::bail!("invalid persisted session entry mode {invalid:?}"),
        };
        let started_at =
            DateTime::<Utc>::from_timestamp_millis(row.started_at_unix_ms).unwrap_or_else(Utc::now);
        let user_content_turns = count_user_turns_for_title(&db, row.session_id);
        let model_system_prompt_snapshot = Arc::new(ModelSystemPromptSnapshot::from_json_str(
            &row.model_system_prompt_snapshot_json,
        ));
        let knowledge_base_prompt_snapshot = RwLock::new(Arc::new(
            crate::knowledge::KnowledgeBasePromptSnapshot::from_json_str(
                &row.knowledge_base_prompt_snapshot_json,
            ),
        ));
        let short_id = match row.short_id.clone() {
            Some(s) => s,
            None => {
                let session_id = row.session_id;
                db.blocking_write_for_sync_maintenance(move |conn| {
                    crate::db::Db::ensure_short_id_conn(conn, session_id)
                })
                .context("backfilling short_id")?
            }
        };
        let model_selection = match row.model_selection_json.as_deref() {
            Some(raw) => {
                let selection =
                    serde_json::from_str::<crate::config::providers::ActiveModelRef>(raw)
                        .context("decoding persisted session model selection")?;
                if row.provider.as_deref() != Some(selection.provider.as_str())
                    || row.model.as_deref() != Some(selection.model.as_str())
                {
                    anyhow::bail!(
                        "persisted session model projections disagree with model_selection_json"
                    );
                }
                Some(selection)
            }
            None => {
                anyhow::ensure!(
                    row.provider.is_none() && row.model.is_none(),
                    "persisted session model projections require model_selection_json"
                );
                None
            }
        };
        let redaction_table_json = match row.redaction_table_json.filter(|s| !s.is_empty()) {
            Some(json) => Some(json),
            None => load_redaction_table_from_vault(&vault, row.session_id)
                .context("loading vault redaction table while resuming session")?,
        };
        // Durable workspace scratch is a required production session
        // capability. Test-support sessions with synthetic roots receive the
        // same per-session path but must not publish a reverse-map marker for
        // a root that cannot be canonicalized.
        let workspace_scratch_dir = if initialize_workspace_scratch {
            workspace_scratch_dir_for_session(&row.project_id, &project_root, row.session_id)
                .context("initializing required durable workspace scratch")?
        } else {
            let path = workspace_scratch_path_for_session(&row.project_id, row.session_id)?;
            std::fs::create_dir_all(&path)
                .with_context(|| format!("creating test workspace scratch `{}`", path.display()))?;
            path
        };
        Ok(Self {
            id: row.session_id,
            project_id: row.project_id,
            project_root,
            assistant_name: row.assistant_name,
            started_at,
            freshly_created,
            db,
            dream_read_scope: Arc::new(std::sync::RwLock::new(None)),
            dream_run_fence: Arc::new(Mutex::new(super::DreamRunFenceState::Vacant)),
            secret_vault: vault,
            external_journal: Mutex::new(None),
            forwarded_mcp_catalog: Arc::new(crate::mcp::forwarded::ForwardedCatalogSlot::default()),
            transcription_dispatch: Mutex::new(std::collections::HashMap::new()),
            message_media_authority: Mutex::new(None),
            #[cfg(test)]
            test_media_reservation_ledger: Mutex::new(None),
            tool_media_runtime: Mutex::new(None),
            tool_media_authority: Mutex::new(None),
            profile_utility_model_resolver: Mutex::new(None),
            command_secret_cache: Mutex::new(None),
            process_containment: Mutex::new(None),
            redaction_key_resolver: resolver,
            allow_unjournaled_inference: std::sync::atomic::AtomicBool::new(false),
            unjournaled_inference_reason: Mutex::new(None),
            short_id: Mutex::new(short_id),
            parent_session_id: row.parent_session_id,
            fork_point_turn_id: row.fork_point_turn_id,
            btw_parent_session_id: row.btw_parent_session_id,
            btw_tangent: row.btw_tangent,
            title: Mutex::new(row.title),
            description: Mutex::new(row.description),
            user_renamed: Mutex::new(row.user_renamed),
            active_agent: Mutex::new(row.active_agent),
            model_selection: Mutex::new(model_selection),
            session_entry_mode,
            tool_surface_override_json: Mutex::new(row.tool_surface_override_json),
            goal_settings_override_json: Mutex::new(row.goal_settings_override_json),
            redaction_table_json: Mutex::new(redaction_table_json),
            secret_path_matcher: std::sync::OnceLock::new(),
            model_system_prompt_snapshot,
            knowledge_base_prompt_snapshot,
            knowledge_base_prompt_snapshot_captured: AtomicBool::new(
                row.knowledge_base_prompt_snapshot_captured,
            ),
            last_time_prelude: Mutex::new(None),
            user_content_tokens: AtomicUsize::new(row.user_content_tokens.max(0) as usize),
            user_content_turns: AtomicUsize::new(user_content_turns),
            title_stage: AtomicU8::new(normalize_title_slot(row.title_stage)),
            title_nudge_slot_pending: AtomicU8::new(0),
            pending_metadata_fork: Mutex::new(None),
            compact_self_nudge_stage: AtomicU8::new(0),
            title_failure_noticed: std::sync::atomic::AtomicBool::new(false),
            redaction_placeholder_noticed: std::sync::atomic::AtomicBool::new(false),
            last_usage: Mutex::new(None),
            last_cache_hit_endpoint: Mutex::new(None),
            last_send_at: Mutex::new(None),
            pinned_messages: Mutex::new(Vec::new()),
            calibrator: Mutex::new(crate::tokens::Calibrator::new()),
            tmp_dir: Mutex::new(None),
            workspace_scratch_dir,
            host_shim_dir: Mutex::new(None),
            sandbox_mode: AtomicU8::new(sandbox_mode_to_u8(
                crate::tools::sandbox_mode::SandboxMode::Sandbox,
            )),
            container_network_enabled: AtomicBool::new(false),
            sandbox_escalation_enabled: AtomicBool::new(true),
            sandbox_escalation_notice_state: AtomicBool::new(true),
            safety_gate_degrade_notice_key: Mutex::new(None),
            mcp_reserved_cockpit_notice_sent: AtomicBool::new(false),
            agent_compact_requested: AtomicBool::new(false),
            // Default `manual` until the spawn path applies the config default.
            approval_mode: AtomicU8::new(approval_mode_to_u8(
                crate::config::extended::ApprovalMode::Manual,
            )),
            invocation_approval_override: AtomicU8::new(255),
            active_run_invocation_id: Mutex::new(None),
            // Default ON until the spawn path applies the config default.
            shell_compression_enabled: AtomicBool::new(true),
            active_tool_names: Mutex::new(std::collections::HashSet::new()),
            image_generation_dispatch: Mutex::new(None),
            active_sandbox_escalate_eligible: AtomicBool::new(false),
            last_tool_call: Mutex::new(None),
            last_recoverable_tool_call: Mutex::new(None),
            // Persisted by default; `create_deferred` overrides this with the
            // pending row right after construction.
            pending_row: Mutex::new(None),
            gitignore_session_allow: Mutex::new(Vec::new()),
            gitignore_session_reject: Mutex::new(std::collections::HashSet::new()),
            adopted_tip_tools: Mutex::new(std::collections::HashSet::new()),
            recent_bash: Mutex::new(std::collections::VecDeque::new()),
        })
    }

    /// The session's private tmp dir (sandboxing part 2), creating it on
    /// first access under `<system temp>/cockpit-session-<id>`. Sandboxed
    /// shells get read+write here, and native-tool path checks treat it
    /// as inside the boundary. Returns `None` only if the directory can't
    /// be created (a degraded but non-fatal state: native checks then
    /// fall back to cwd-only, and the shell sandbox simply omits the tmp
    /// allow entry).
    pub fn tmp_dir(&self) -> Option<PathBuf> {
        let mut slot = self.tmp_dir.lock().unwrap();
        if let Some(dir) = slot.as_ref() {
            return Some(dir.clone());
        }
        let dir = std::env::temp_dir().join(format!("cockpit-session-{}", self.id));
        match std::fs::create_dir_all(&dir) {
            Ok(()) => {
                *slot = Some(dir.clone());
                Some(dir)
            }
            Err(e) => {
                tracing::warn!(error = %e, dir = %dir.display(), "creating session tmp dir failed");
                None
            }
        }
    }

    /// Durable, private-to-this-session scratch below the workspace's Cockpit
    /// state directory. The containing workspace directory is keyed by the
    /// existing `project_id` and carries a marker that lets maintenance code
    /// recover the canonical project root without enumerating the filesystem.
    ///
    /// This is intentionally separate from [`Self::tmp_dir`]: ending or
    /// dropping a session removes only the ephemeral system-temp directory.
    pub fn workspace_scratch_dir(&self) -> PathBuf {
        self.workspace_scratch_dir.clone()
    }

    /// Per-session host shim directory under the Cockpit data dir. Used for
    /// small executable aliases that should be visible to host shells but
    /// removed when the session ends.
    pub fn host_shim_dir(&self) -> Option<PathBuf> {
        let mut slot = self.host_shim_dir.lock().unwrap();
        if let Some(dir) = slot.as_ref() {
            return Some(dir.clone());
        }
        let dir = match crate::config::resolve::cockpit_data_dir() {
            Ok(data_dir) => host_shim_bin_dir_for_data_dir(&data_dir, self.id),
            Err(e) => {
                tracing::warn!(error = %e, "resolving cockpit data dir for host shims failed");
                return None;
            }
        };
        match std::fs::create_dir_all(&dir) {
            Ok(()) => {
                *slot = Some(dir.clone());
                Some(dir)
            }
            Err(e) => {
                tracing::warn!(error = %e, dir = %dir.display(), "creating session host shim dir failed");
                None
            }
        }
    }

    /// Manually set the session's title. Locks out the auto-titling
    /// pass (GOALS §17d).
    // Manual-rename API (GOALS §17d); retained for the not-yet-wired
    // `/rename` affordance.
    #[allow(dead_code)]
    pub fn rename(&self, new_title: &str) -> Result<()> {
        let title = new_title.to_string();
        let session_id = self.id;
        // Route through the shared latch-clearing helper so a manual user rename
        // clears any pending title-recovery nudge (issue #23) — an already-named
        // session must never be nudged to name itself.
        self.db
            .blocking_write_for_sync_maintenance(move |conn| {
                crate::db::Db::rename_session_conn(conn, session_id, &title)
            })
            .context("renaming session")?;
        *self.title.lock().unwrap() = Some(new_title.to_string());
        *self.user_renamed.lock().unwrap() = true;
        Ok(())
    }

    /// Persist the accumulated egress redaction table with the session so raw
    /// history remains covered after resume even if env/dotenv sources change.
    pub fn persist_redaction_table(&self, table: &crate::redact::RedactionTable) -> Result<()> {
        let json = table.to_persisted_json()?;
        *self.redaction_table_json.lock().unwrap() = Some(json.clone());
        if self.stage_pending_row(|row| {
            row.redaction_table_json = None;
        }) {
            return persist_redaction_table_to_vault(
                &self.db,
                &self.secret_vault,
                self.id,
                json.as_bytes(),
            );
        }
        persist_redaction_table_to_vault(&self.db, &self.secret_vault, self.id, json.as_bytes())
    }

    pub fn persisted_redaction_table(&self) -> Result<Option<crate::redact::RedactionTable>> {
        if let Some(json) = self.redaction_table_json.lock().unwrap().clone() {
            return crate::redact::RedactionTable::from_persisted_json(&json)
                .map(Some)
                .context("loading persisted session redaction table");
        }
        match load_redaction_table_from_vault(&self.secret_vault, self.id)? {
            Some(json) => crate::redact::RedactionTable::from_persisted_json(&json)
                .map(Some)
                .context("loading vault session redaction table"),
            None => Ok(None),
        }
    }

    /// Load a session's durable redaction table through this daemon-owned
    /// session's vault handle. Cross-session readers must fold this table into
    /// their own redactor before returning any target-owned history.
    ///
    /// The database column remains a legacy import projection; production
    /// persistence keeps the table in the vault. A malformed persisted table
    /// is an error rather than a reason to return target content unredacted.
    pub(crate) async fn persisted_redaction_table_for_session(
        &self,
        reader_project: &str,
        session_id: uuid::Uuid,
    ) -> Result<Option<crate::redact::RedactionTable>> {
        if session_id == self.id {
            return self.persisted_redaction_table();
        }
        let Some(redaction_table_json) = self
            .db
            .session_redaction_table_json_for_reader_project(reader_project, session_id)
            .await?
        else {
            return Ok(None);
        };
        let json = match redaction_table_json.filter(|json| !json.is_empty()) {
            Some(json) => Some(json),
            None => load_redaction_table_from_vault(&self.secret_vault, session_id)?,
        };
        json.map(|json| {
            crate::redact::RedactionTable::from_persisted_json(&json)
                .context("loading persisted target-session redaction table")
        })
        .transpose()
    }

    /// Legacy file-origin markers are used only to warn when a resumed
    /// session cannot rebuild coverage. They never reveal a secret value.
    pub fn persisted_disk_redaction_origins(&self) -> Result<Vec<String>> {
        let json = match self.redaction_table_json.lock().unwrap().clone() {
            Some(json) => json,
            None => match load_redaction_table_from_vault(&self.secret_vault, self.id)? {
                Some(json) => json,
                None => return Ok(Vec::new()),
            },
        };
        crate::redact::RedactionTable::persisted_disk_derived_origins(&json)
            .context("loading persisted disk-derived redaction origins")
    }

    /// Touch `last_active_at_unix_ms`. Called by the daemon on every
    /// interaction so `cockpit -c` lands on the right session.
    pub fn touch(&self) -> Result<()> {
        if self.stage_pending_row(|row| {
            row.last_active_at_unix_ms = Utc::now().timestamp_millis();
        }) {
            return Ok(());
        }
        let session_id = self.id;
        self.db
            .blocking_write_for_sync_maintenance(move |conn| {
                conn.execute(
                    "UPDATE sessions SET last_active_at_unix_ms = ?1 WHERE session_id = ?2",
                    params![Utc::now().timestamp_millis(), session_id.to_string()],
                )
                .context("touching session")?;
                Ok(())
            })
            .context("touching session")
    }

    /// Mark this session viewed by a client. For an unpersisted deferred
    /// session, stage the marker so the first INSERT carries it; otherwise
    /// write through to the existing row.
    pub fn mark_viewed(&self) -> Result<()> {
        if self.stage_pending_row(|row| {
            row.last_viewed_at_unix_ms = Some(Utc::now().timestamp_millis());
        }) {
            return Ok(());
        }
        let session_id = self.id;
        self.db
            .blocking_write_for_sync_maintenance(move |conn| {
                conn.execute(
                    "UPDATE sessions SET last_viewed_at_unix_ms = ?1 WHERE session_id = ?2",
                    params![Utc::now().timestamp_millis(), session_id.to_string()],
                )
                .context("marking session viewed")?;
                Ok(())
            })
            .context("marking session viewed")
    }

    /// End the session — sets `ended_at_unix_ms` in the DB. Doesn't drop the
    /// row; history stays queryable via `cockpit session list`. Also
    /// removes the per-session tmp dir (sandboxing part 2): a session's
    /// scratch space doesn't outlive it.
    pub fn end(&self) -> Result<()> {
        self.remove_tmp_dir();
        let session_id = self.id;
        self.db
            .blocking_write_for_sync_maintenance(move |conn| {
                let now_ms = Utc::now().timestamp_millis();
                conn.execute(
                    "UPDATE sessions SET ended_at_unix_ms = ?1 WHERE session_id = ?2",
                    params![now_ms, session_id.to_string()],
                )
                .context("ending session")?;
                crate::db::tool_media_subject_bindings::invalidate_tool_media_authorization_epochs_for_session_conn(
                    conn,
                    session_id,
                    now_ms,
                )?;
                Ok(())
            })
            .context("ending session")
    }

    /// Remove the per-session tmp dir if one was created. Idempotent.
    /// Best-effort: a removal failure is logged, never propagated — it
    /// must not block session teardown.
    pub(super) fn remove_tmp_dir(&self) {
        if let Some(dir) = self.tmp_dir.lock().unwrap().take()
            && let Err(e) = std::fs::remove_dir_all(&dir)
            && e.kind() != std::io::ErrorKind::NotFound
        {
            tracing::warn!(error = %e, dir = %dir.display(), "removing session tmp dir failed");
        }
        if let Some(dir) = self.host_shim_dir.lock().unwrap().take() {
            let cleanup_dir = dir.parent().unwrap_or(&dir);
            if let Err(e) = std::fs::remove_dir_all(cleanup_dir)
                && e.kind() != std::io::ErrorKind::NotFound
            {
                tracing::warn!(error = %e, dir = %cleanup_dir.display(), "removing session host shim dir failed");
            }
        }
    }
}

pub(crate) fn host_shim_bin_dir_for_data_dir(data_dir: &Path, session_id: Uuid) -> PathBuf {
    data_dir
        .join("session-shims")
        .join(session_id.to_string())
        .join("bin")
}

#[cfg(test)]
mod vault_unification_tests {
    use super::*;

    #[test]
    fn redaction_table_not_plaintext_in_sessions_column() {
        let db = crate::db::Db::open_in_memory().unwrap();
        let session = Session::create_for_test(
            db.clone(),
            PathBuf::from("/repo"),
            "Build",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap();
        let mut table = crate::redact::RedactionTable::empty();
        table = table
            .with_forced_sealed_literal(
                "first-high-entropy-token".to_string(),
                crate::sealed::identity::SealedRedactionIdentity {
                    scope: crate::sealed::identity::SealedScopeKind::Session,
                    record_id: None,
                    name: crate::sealed::identity::SealedName::canonical("prod_token").unwrap(),
                    version: 0,
                },
            )
            .unwrap();
        session.persist_redaction_table(&table).unwrap();
        let column: Option<String> = db
            .blocking_write_for_sync_maintenance({
                let sid = session.id.to_string();
                move |conn| {
                    Ok(conn.query_row(
                        "SELECT redaction_table_json FROM sessions WHERE session_id = ?1",
                        rusqlite::params![sid],
                        |row| row.get(0),
                    )?)
                }
            })
            .unwrap();
        assert!(
            column
                .as_deref()
                .is_none_or(|json| !json.contains("first-high-entropy-token"))
        );
        let loaded = session.persisted_redaction_table().unwrap().unwrap();
        assert!(
            !loaded
                .scrub("first-high-entropy-token")
                .contains("first-high-entropy-token")
        );
    }
}
