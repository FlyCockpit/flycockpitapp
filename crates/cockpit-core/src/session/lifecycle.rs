#![allow(deprecated)]

use std::path::Path;

use rusqlite::OptionalExtension;

use super::*;

/// Required protected redaction-history key resolver threaded into every
/// `Session` constructor (decision 16). Production installs the daemon's
/// `SecureKeyResolver`; tests pass [`super::test_redaction_key_resolver`].
pub(crate) type RedactionKeyResolverArc =
    Arc<dyn crate::redact::protected_redaction_history::RedactionKeyResolver>;

/// Copy a parent sealed-value vault item when present.
///
/// `NotFound` is success only here: a parent sealed-values row may lack a
/// vault payload (`/btw` forks inherit transcript state without sealed-value
/// custody). Redaction-table copies must use
/// [`require_redaction_table_json_from_vault`] — missing table custody is
/// fail-closed, never an empty child table.
fn copy_optional_sealed_vault_item(
    vault: &crate::secure_key::SecretVault,
    from_id: &str,
    to_id: &str,
) -> Result<()> {
    match vault.get_item(
        cockpit_db::secret_vault::SecretVaultKind::SessionSealedValue,
        from_id,
    ) {
        Ok(secret) => vault
            .put_item(
                cockpit_db::secret_vault::SecretVaultKind::SessionSealedValue,
                to_id,
                secret.as_slice(),
            )
            .map_err(|error| anyhow::anyhow!("copying session sealed vault item: {error}")),
        Err(crate::secure_key::SecureKeyError::NotFound(_)) => Ok(()),
        Err(error) => Err(anyhow::anyhow!(
            "reading parent session sealed vault item for fork: {error}"
        )),
    }
}

fn copy_vault_redaction_table(
    vault: &crate::secure_key::SecretVault,
    parent: uuid::Uuid,
    child: uuid::Uuid,
    context: &'static str,
) -> Result<()> {
    let json = require_redaction_table_json_from_vault(vault, parent, context)?;
    persist_redaction_table_to_vault(vault, child, json.as_bytes())
}

fn copy_vault_redaction_table_on_conn(
    vault: &crate::secure_key::SecretVault,
    conn: &rusqlite::Connection,
    parent: uuid::Uuid,
    child: uuid::Uuid,
    context: &'static str,
) -> Result<()> {
    let json = require_redaction_table_json_from_vault_on_conn(vault, conn, parent, context)?;
    persist_redaction_table_to_vault_on_conn(vault, conn, child, json.as_bytes())
}

pub(crate) fn copy_vault_session_secrets(
    db: &crate::db::Db,
    vault: &crate::secure_key::SecretVault,
    parent: uuid::Uuid,
    child: uuid::Uuid,
) -> Result<()> {
    let parent_key = parent.to_string();
    let child_key = child.to_string();
    copy_vault_redaction_table(
        vault,
        parent,
        child,
        "copying parent redaction table for session fork",
    )?;
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
        copy_optional_sealed_vault_item(vault, &from, &to)?;
    }
    Ok(())
}

/// Copy vault redaction/sealed-secret custody, then persist the child.
///
/// The parent must already own a durable redaction table; missing custody is
/// fail-closed. The child session row is not created until the vault copy
/// succeeds, so a failed copy cannot leave a resumable fork without its
/// redaction boundary. `create_fork_row_conn` already inserts
/// `sealed_values.value` as NULL.
pub(crate) fn persist_fork_with_redaction_custody(
    db: &crate::db::Db,
    vault: &crate::secure_key::SecretVault,
    parent_session_id: uuid::Uuid,
    fork_point_turn_id: Option<String>,
    ephemeral: bool,
    fresh_thread: bool,
) -> Result<crate::db::sessions::SessionRow> {
    let session_id = uuid::Uuid::new_v4();
    let now_unix_ms = Utc::now().timestamp_millis();
    copy_vault_session_secrets(db, vault, parent_session_id, session_id)
        .context("copying vault sealed values and redaction table into fork")?;
    db.blocking_write_for_sync_maintenance(move |conn| {
        crate::db::Db::create_fork_conn(
            conn,
            parent_session_id,
            fork_point_turn_id,
            ephemeral,
            fresh_thread,
            session_id,
            now_unix_ms,
        )
    })
    .context("creating fork session row")
}

/// Copy parent redaction-table custody, then persist the `/btw` child.
///
/// `/btw` copies transcript state for a non-tangent fork and never copies
/// sealed values. Missing parent table custody is fail-closed. The child row
/// and its vault item commit in one transaction so a failed copy cannot leave
/// a resumable `/btw` session without its redaction boundary. Idempotent:
/// an existing live `/btw` fork is returned without a second copy.
pub(crate) async fn persist_btw_fork_with_redaction_custody(
    db: &crate::db::Db,
    vault: Arc<crate::secure_key::SecretVault>,
    parent_session_id: uuid::Uuid,
    tangent: bool,
) -> Result<crate::db::sessions::BtwForkCreateResult> {
    let session_id = uuid::Uuid::new_v4();
    let now_unix_ms = Utc::now().timestamp_millis();
    db.transaction(move |conn| {
        persist_btw_fork_with_redaction_custody_on_conn(
            conn,
            &vault,
            parent_session_id,
            tangent,
            session_id,
            now_unix_ms,
        )
    })
    .await
    .context("creating /btw fork with redaction custody")
}

/// Snapshot-consistent variant of [`persist_btw_fork_with_redaction_custody`].
pub(crate) fn persist_btw_fork_with_redaction_custody_on_conn(
    conn: &rusqlite::Connection,
    vault: &crate::secure_key::SecretVault,
    parent_session_id: uuid::Uuid,
    tangent: bool,
    session_id: uuid::Uuid,
    now_unix_ms: i64,
) -> Result<crate::db::sessions::BtwForkCreateResult> {
    let result = crate::db::Db::create_btw_fork_conn(
        conn,
        parent_session_id,
        tangent,
        session_id,
        now_unix_ms,
    )?;
    if result.created {
        copy_vault_redaction_table_on_conn(
            vault,
            conn,
            parent_session_id,
            result.info.session_id,
            "copying parent redaction table for /btw fork",
        )?;
    }
    Ok(result)
}

#[cfg(test)]
thread_local! {
    static FAIL_NEXT_REDACTION_VAULT_WRITE: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };
}

/// Arm the next session redaction vault write in this thread to fail before
/// committing, so tests can assert cache identity after a failed persist.
#[cfg(test)]
pub(crate) fn fail_next_redaction_vault_write_for_test() {
    FAIL_NEXT_REDACTION_VAULT_WRITE.with(|flag| flag.set(true));
}

fn persist_empty_redaction_table_on_conn(
    vault: &crate::secure_key::SecretVault,
    conn: &rusqlite::Connection,
    session_id: uuid::Uuid,
) -> Result<()> {
    let json = crate::redact::RedactionTable::empty().to_persisted_json()?;
    persist_redaction_table_to_vault_on_conn(vault, conn, session_id, json.as_bytes())
}

/// Create empty vault custody when a durable session is inserted without a
/// table yet. Existing items (spawn already persisted the live scan) are left
/// untouched so this cannot clobber accumulated secrets.
fn ensure_redaction_table_custody_on_conn(
    vault: &crate::secure_key::SecretVault,
    conn: &rusqlite::Connection,
    session_id: uuid::Uuid,
) -> Result<()> {
    let item_id = crate::secure_key::redaction_table_item_id(&session_id.to_string());
    match vault.get_item_on_conn(
        conn,
        cockpit_db::secret_vault::SecretVaultKind::RedactionTable,
        &item_id,
    ) {
        Ok(_) => Ok(()),
        Err(crate::secure_key::SecureKeyError::NotFound(_)) => {
            persist_empty_redaction_table_on_conn(vault, conn, session_id)
        }
        Err(error) => Err(crate::redact::RedactionTableUnavailable::new(
            "ensuring session redaction table custody",
            format!("session {session_id}: {error}"),
        )
        .into()),
    }
}

/// Insert a visible `sessions` row and establish redaction-table vault custody
/// on the same connection.
///
/// `conn` must already be inside a transaction so a failed vault write cannot
/// leave a resumable row. Existing vault items (a spawn-time live scan) are
/// left untouched. The insert is refused if custody is still missing after
/// `ensure`.
pub(crate) fn persist_session_row_with_redaction_custody_on_conn(
    conn: &rusqlite::Connection,
    vault: &crate::secure_key::SecretVault,
    row: &crate::db::sessions::SessionRow,
) -> Result<crate::db::sessions::SessionRow> {
    let inserted = crate::db::Db::insert_session_row_conn(conn, row)?;
    ensure_redaction_table_custody_on_conn(vault, conn, inserted.session_id)?;
    anyhow::ensure!(
        cockpit_db::secret_vault::session_redaction_table_vault_item_exists_conn(
            conn,
            &crate::secure_key::redaction_table_item_id(&inserted.session_id.to_string()),
        )?,
        "session insert did not establish redaction-table vault custody"
    );
    Ok(inserted)
}

fn persist_built_session_row_with_redaction_custody(
    db: &crate::db::Db,
    vault: Arc<crate::secure_key::SecretVault>,
    row: crate::db::sessions::SessionRow,
    context: &'static str,
) -> Result<crate::db::sessions::SessionRow> {
    db.blocking_write_for_sync_maintenance(move |conn| {
        let tx = conn
            .unchecked_transaction()
            .context("begin session insert with redaction custody tx")?;
        let persisted = persist_session_row_with_redaction_custody_on_conn(&tx, &vault, &row)?;
        tx.commit()
            .context("commit session insert with redaction custody tx")?;
        Ok(persisted)
    })
    .context(context)
}

/// Create a new root session row and empty redaction-table custody together.
pub(crate) async fn persist_session_with_redaction_custody(
    db: &crate::db::Db,
    vault: Arc<crate::secure_key::SecretVault>,
    project_id: &str,
    project_root: &str,
    active_agent: &str,
) -> Result<crate::db::sessions::SessionRow> {
    let project_id = project_id.to_string();
    let project_root = project_root.to_string();
    let active_agent = active_agent.to_string();
    db.transaction(move |conn| {
        let row = crate::db::Db::build_new_session_row_conn(
            conn,
            &project_id,
            &project_root,
            &active_agent,
        )?;
        persist_session_row_with_redaction_custody_on_conn(conn, &vault, &row)
    })
    .await
    .context("creating session with redaction custody")
}

/// Create a new assistant session row and empty redaction-table custody together.
pub(crate) async fn persist_assistant_session_with_redaction_custody(
    db: &crate::db::Db,
    vault: Arc<crate::secure_key::SecretVault>,
    project_id: &str,
    project_root: &str,
    active_agent: &str,
    assistant_name: &str,
) -> Result<crate::db::sessions::SessionRow> {
    let project_id = project_id.to_string();
    let project_root = project_root.to_string();
    let active_agent = active_agent.to_string();
    let assistant_name = assistant_name.to_string();
    db.transaction(move |conn| {
        let row = crate::db::Db::build_new_assistant_session_row_conn(
            conn,
            &project_id,
            &project_root,
            &active_agent,
            &assistant_name,
        )?;
        persist_session_row_with_redaction_custody_on_conn(conn, &vault, &row)
    })
    .await
    .context("creating assistant session with redaction custody")
}

fn persist_redaction_table_to_vault(
    vault: &crate::secure_key::SecretVault,
    session_id: uuid::Uuid,
    json: &[u8],
) -> Result<()> {
    #[cfg(test)]
    if FAIL_NEXT_REDACTION_VAULT_WRITE.with(|flag| flag.replace(false)) {
        return Err(anyhow::anyhow!("injected redaction vault write failure"));
    }
    let item_id = crate::secure_key::redaction_table_item_id(&session_id.to_string());
    vault
        .put_item(
            cockpit_db::secret_vault::SecretVaultKind::RedactionTable,
            &item_id,
            json,
        )
        .map_err(|error| anyhow::anyhow!("persisting session redaction table: {error}"))
}

fn persist_redaction_table_to_vault_on_conn(
    vault: &crate::secure_key::SecretVault,
    conn: &rusqlite::Connection,
    session_id: uuid::Uuid,
    json: &[u8],
) -> Result<()> {
    #[cfg(test)]
    if FAIL_NEXT_REDACTION_VAULT_WRITE.with(|flag| flag.replace(false)) {
        return Err(anyhow::anyhow!("injected redaction vault write failure"));
    }
    let item_id = crate::secure_key::redaction_table_item_id(&session_id.to_string());
    vault
        .put_item_on_conn(
            conn,
            cockpit_db::secret_vault::SecretVaultKind::RedactionTable,
            &item_id,
            json,
        )
        .map_err(|error| anyhow::anyhow!("persisting session redaction table: {error}"))
}

pub(crate) fn write_redaction_table_json_to_vault(
    db: &crate::db::Db,
    session_id: uuid::Uuid,
    json: &str,
) -> Result<()> {
    let vault = crate::secure_key::vault_for_db(db)
        .map_err(|error| anyhow::anyhow!("opening vault for redaction table: {error}"))?;
    persist_redaction_table_to_vault(&vault, session_id, json.as_bytes())
}

/// Establish empty vault custody for each newly inserted durable session in
/// the same SQLite transaction as the rows. Archives never carry secret
/// literals, so imported history is covered by an empty committed table
/// rather than a missing item that resume would treat as "no secrets."
pub(crate) fn persist_empty_redaction_tables_for_imported_sessions_on_conn(
    vault: &crate::secure_key::SecretVault,
    conn: &rusqlite::Connection,
    session_ids: &[uuid::Uuid],
) -> Result<()> {
    for session_id in session_ids {
        persist_empty_redaction_table_on_conn(vault, conn, *session_id)?;
    }
    Ok(())
}

fn redaction_table_json_from_required_vault_bytes(
    loaded: std::result::Result<Vec<u8>, crate::secure_key::SecureKeyError>,
    session_id: uuid::Uuid,
    context: &'static str,
) -> Result<String> {
    match loaded {
        Ok(bytes) => String::from_utf8(bytes).map_err(|error| {
            crate::redact::RedactionTableUnavailable::new(
                context,
                format!("session {session_id}: redaction table vault item is not UTF-8: {error}"),
            )
            .into()
        }),
        Err(error) => Err(crate::redact::RedactionTableUnavailable::new(
            context,
            format!("session {session_id}: {error}"),
        )
        .into()),
    }
}

/// Optional vault load used while a session may not yet have initial custody
/// (deferred construction, spawn adopt, own cache before the first persist).
///
/// Once a session is durable — its `sessions` row is visible to resume —
/// security-relevant loads must use [`require_redaction_table_json_from_vault`]:
/// `NotFound` is lost custody, never an empty table. Constructors that insert
/// that row (`persist_session_row_with_redaction_custody_on_conn`,
/// `persist_if_needed`, `/btw`, archive import, fork) establish custody in the
/// same operation.
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

/// Load the durable redaction table a session is expected to own.
///
/// Missing, unreadable, and non-UTF-8 vault items are typed fail-closed
/// errors — never `Ok` with an empty table.
pub(crate) fn require_redaction_table_json_from_vault(
    vault: &crate::secure_key::SecretVault,
    session_id: uuid::Uuid,
    context: &'static str,
) -> Result<String> {
    let item_id = crate::secure_key::redaction_table_item_id(&session_id.to_string());
    redaction_table_json_from_required_vault_bytes(
        vault
            .get_item(
                cockpit_db::secret_vault::SecretVaultKind::RedactionTable,
                &item_id,
            )
            .map(|secret| secret.as_slice().to_vec()),
        session_id,
        context,
    )
}

/// Snapshot-consistent variant of [`require_redaction_table_json_from_vault`].
pub(crate) fn require_redaction_table_json_from_vault_on_conn(
    vault: &crate::secure_key::SecretVault,
    conn: &rusqlite::Connection,
    session_id: uuid::Uuid,
    context: &'static str,
) -> Result<String> {
    let item_id = crate::secure_key::redaction_table_item_id(&session_id.to_string());
    redaction_table_json_from_required_vault_bytes(
        vault
            .get_item_on_conn(
                conn,
                cockpit_db::secret_vault::SecretVaultKind::RedactionTable,
                &item_id,
            )
            .map(|secret| secret.as_slice().to_vec()),
        session_id,
        context,
    )
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
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn test_session_identity(project_root: &Path) -> (PathBuf, String) {
        let project_root =
            std::fs::canonicalize(project_root).unwrap_or_else(|_| project_root.to_path_buf());
        let project_id = Self::project_id_for_canonical_test_session_root(&project_root);
        (project_root, project_id)
    }

    #[cfg(any(test, feature = "test-support"))]
    fn project_id_for_canonical_test_session_root(project_root: &Path) -> String {
        super::project_id_from_workspace_object(&format!(
            "cockpit-synthetic-test-workspace-root-v1\\0{}",
            project_root.display()
        ))
    }

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
        #[cfg(any(test, feature = "test-support"))]
        return Ok(Self::project_id_for_canonical_test_session_root(
            project_root,
        ));

        #[cfg(not(any(test, feature = "test-support")))]
        unreachable!("synthetic session roots are test-support only")
    }

    #[cfg(any(test, feature = "test-support"))]
    fn test_workspace_root(project_root: PathBuf) -> (PathBuf, bool) {
        // Test-support constructors must not publish production workspace
        // markers. Test runners create and remove temporary directories at a
        // high rate, so their filesystem identities can be reused while the
        // process-global durable state directory retains the old marker.
        // Production constructors remain the only path that proves an on-disk
        // workspace identity and initializes durable workspace scratch.
        (Self::test_session_identity(&project_root).0, false)
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
        let vault_for_insert = Arc::clone(&vault);
        let row = persist_built_session_row_with_redaction_custody(
            &db,
            vault_for_insert,
            row_for_db,
            "creating test session row",
        )?;
        Self::from_row(
            db,
            project_root,
            row,
            resolver,
            vault,
            true,
            initialize_workspace_scratch,
            false,
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
            false,
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
            false,
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
        let row = persist_fork_with_redaction_custody(
            &db,
            &vault,
            parent_session_id,
            fork_point_turn_id,
            false,
            false,
        )
        .context("creating test fork session row")?;
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
            false,
        )
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn resume_with_test_workspace_root(
        db: Db,
        session_id: Uuid,
        resolver: RedactionKeyResolverArc,
        vault: Arc<crate::secure_key::SecretVault>,
    ) -> Result<Option<Self>> {
        Self::resume_with_test_workspace_root_inner(db, session_id, resolver, vault, true)
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn resume_with_strict_test_workspace_root(
        db: Db,
        session_id: Uuid,
        resolver: RedactionKeyResolverArc,
        vault: Arc<crate::secure_key::SecretVault>,
    ) -> Result<Option<Self>> {
        Self::resume_with_test_workspace_root_inner(db, session_id, resolver, vault, false)
    }

    #[cfg(any(test, feature = "test-support"))]
    fn resume_with_test_workspace_root_inner(
        db: Db,
        session_id: Uuid,
        resolver: RedactionKeyResolverArc,
        vault: Arc<crate::secure_key::SecretVault>,
        allow_unbound_test_fixture_project_id: bool,
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
            allow_unbound_test_fixture_project_id,
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
        let vault_for_insert = Arc::clone(&vault);
        let row = persist_built_session_row_with_redaction_custody(
            &db,
            vault_for_insert,
            row_for_db,
            "creating session row",
        )?;
        Self::from_row(db, project_root, row, resolver, vault, true, true, false)
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
        let session = Self::from_row(
            db,
            project_root,
            row.clone(),
            resolver,
            vault,
            true,
            true,
            false,
        )?;
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
        let session = Self::from_row(
            db,
            project_root,
            row.clone(),
            resolver,
            vault,
            true,
            true,
            false,
        )?;
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
                    row
                }
                None => return Ok(false),
            }
        };
        let row_for_db = row.clone();
        let vault = Arc::clone(&self.secret_vault);
        let session_id_for_vault = row.session_id;
        match self.db.blocking_write_for_sync_maintenance(move |conn| {
            let tx = conn
                .unchecked_transaction()
                .context("begin persist_if_needed tx")?;
            let persisted =
                persist_session_row_with_redaction_custody_on_conn(&tx, &vault, &row_for_db)?;
            anyhow::ensure!(
                persisted.session_id == session_id_for_vault,
                "persist_if_needed must insert the deferred session id"
            );
            tx.commit().context("commit persist_if_needed tx")?;
            Ok(persisted)
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
        let row = persist_fork_with_redaction_custody(
            &db,
            &vault,
            parent_session_id,
            fork_point_turn_id,
            false,
            false,
        )?;
        let project_root = PathBuf::from(&row.project_root);
        Self::from_row(db, project_root, row, resolver, vault, false, true, false)
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
            false,
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
        allow_unbound_test_fixture_project_id: bool,
    ) -> Result<Self> {
        let project_root = if initialize_workspace_scratch {
            canonical_workspace_root(&project_root)
                .context("canonicalizing persisted session workspace root")?
        } else {
            // Test-support project ids are derived from a stable path spelling
            // rather than a host directory identity, and are never published
            // through a production workspace marker.
            std::fs::canonicalize(&project_root).unwrap_or(project_root)
        };
        #[cfg(any(test, feature = "test-support"))]
        let legacy_short_fixture_project_id = row.project_id.len() <= 24
            && row
                .project_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_');
        #[cfg(any(test, feature = "test-support"))]
        let initialize_workspace_scratch = {
            // Test-support rows intentionally use a separate project-id
            // namespace so they cannot publish a process-global workspace
            // marker. Those rows can still flow through the ordinary daemon
            // resume path, which otherwise has no caller-side indication that
            // the persisted row is synthetic. The durable project id is the
            // discriminator: never downgrade an unrecognised production row.
            let synthetic_id = Self::project_id_for_canonical_test_session_root(&project_root);
            if row.project_id == synthetic_id {
                false
            } else if project_id_for(&project_root).ok().as_deref() == Some(&row.project_id) {
                true
            } else if legacy_short_fixture_project_id {
                // The daemon integration tests still create a few low-level
                // fixture rows directly in the ledger.  Their short labels
                // are neither workspace-object identities nor safe durable
                // workspace directory components, so keep them on the
                // test-only scratch path below.
                false
            } else {
                initialize_workspace_scratch
            }
        };
        let project_id_matches =
            Self::project_id_for_session_root(&project_root, initialize_workspace_scratch)?
                == row.project_id;
        // Raw test fixtures predate workspace-object identities and enter
        // test-only code with short human labels. Production identities are
        // fixed-length workspace-object digests; deliberately malformed or
        // digest-shaped rows still take the strict identity path.
        anyhow::ensure!(
            project_id_matches || allow_unbound_test_fixture_project_id || {
                #[cfg(any(test, feature = "test-support"))]
                {
                    legacy_short_fixture_project_id
                }
                #[cfg(not(any(test, feature = "test-support")))]
                {
                    false
                }
            },
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
        let redaction_table_json = if freshly_created {
            // Deferred construction and the first persist of a brand-new row
            // may not yet own vault custody. Resume of an existing durable
            // session must not treat a missing item as "no historical secrets."
            load_redaction_table_from_vault(&vault, row.session_id)
                .context("loading vault redaction table while creating session")?
        } else {
            Some(require_redaction_table_json_from_vault(
                &vault,
                row.session_id,
                "loading vault redaction table while resuming session",
            )?)
        };
        // Durable workspace scratch is a required production session
        // capability. Test-support sessions with synthetic roots receive the
        // same per-session path but must not publish a reverse-map marker for
        // a root that cannot be canonicalized.
        let workspace_scratch_dir = if initialize_workspace_scratch {
            workspace_scratch_dir_for_session(&row.project_id, &project_root, row.session_id)
                .context("initializing required durable workspace scratch")?
        } else {
            let path = workspace_scratch_path_for_session(&row.project_id, row.session_id)
                .or_else(|error| {
                    #[cfg(any(test, feature = "test-support"))]
                    if legacy_short_fixture_project_id {
                        return super::test_fixture_workspace_scratch_path_for_session(
                            &row.project_id,
                            row.session_id,
                        );
                    }
                    Err(error)
                })?;
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
            seed_read_receipts: Mutex::new(std::collections::HashMap::new()),
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
            knowledge_read_snapshots: Mutex::new(super::KnowledgeReadSnapshotStore::default()),
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
            observed_cache_hit_endpoints: Mutex::new(BTreeSet::new()),
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
            monty_network_grants: Mutex::new(crate::mcp::network::SessionNetworkGrants::default()),
            monty_network_egress_gate: Arc::new(tokio::sync::RwLock::new(())),
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
            #[cfg(test)]
            booted_root_profile: Mutex::new(None),
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
    ///
    /// The in-memory cache advertised by [`Self::persisted_redaction_table`] is
    /// updated only after the vault write commits. A failed persist leaves both
    /// the durable vault and every cache advertised as persisted at the last
    /// committed table (persist-before-swap).
    pub fn persist_redaction_table(&self, table: &crate::redact::RedactionTable) -> Result<()> {
        let json = table.to_persisted_json()?;
        persist_redaction_table_to_vault(&self.secret_vault, self.id, json.as_bytes())?;
        *self.redaction_table_json.lock().unwrap() = Some(json);
        Ok(())
    }

    /// Load the last committed redaction table. The in-memory cache is a
    /// committed-table mirror, never a speculative write.
    ///
    /// `Ok(None)` is only for a not-yet-durable deferred session that has never
    /// written a vault item. A persisted session with a missing item is lost
    /// custody, never an empty table.
    pub fn persisted_redaction_table(&self) -> Result<Option<crate::redact::RedactionTable>> {
        if let Some(json) = self.redaction_table_json.lock().unwrap().clone() {
            return crate::redact::RedactionTable::from_persisted_json(&json)
                .map(Some)
                .context("loading persisted session redaction table");
        }
        if !self.is_persisted() {
            return match load_redaction_table_from_vault(&self.secret_vault, self.id)? {
                Some(json) => crate::redact::RedactionTable::from_persisted_json(&json)
                    .map(Some)
                    .context("loading vault session redaction table"),
                None => Ok(None),
            };
        }
        let json = require_redaction_table_json_from_vault(
            &self.secret_vault,
            self.id,
            "loading persisted session redaction table",
        )?;
        crate::redact::RedactionTable::from_persisted_json(&json)
            .map(Some)
            .context("loading vault session redaction table")
    }

    /// Drop the in-memory redaction cache so the next load hits the vault.
    /// Used to inject vault-read failures on security-relevant paths.
    #[cfg(test)]
    pub(crate) fn clear_cached_redaction_table_for_test(&self) {
        *self.redaction_table_json.lock().unwrap() = None;
    }

    /// Load a session's durable redaction table through this daemon-owned
    /// session's vault handle. Cross-session readers must fold this table into
    /// their own redactor before returning any target-owned history.
    ///
    /// A missing, malformed, or unloadable vault table is an error rather than
    /// a reason to return target content unredacted. `Ok(None)` means the
    /// target is not visible to `reader_project`, not that custody is absent.
    pub(crate) async fn persisted_redaction_table_for_session(
        &self,
        reader_project: &str,
        session_id: uuid::Uuid,
    ) -> Result<Option<crate::redact::RedactionTable>> {
        if session_id == self.id {
            return self.persisted_redaction_table();
        }
        if !self
            .db
            .session_visible_to_reader_project(reader_project, session_id)
            .await?
        {
            return Ok(None);
        }
        let json = require_redaction_table_json_from_vault(
            &self.secret_vault,
            session_id,
            "loading persisted target-session redaction table",
        )?;
        crate::redact::RedactionTable::from_persisted_json(&json)
            .map(Some)
            .context("loading persisted target-session redaction table")
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
                cockpit_db::db::sealed_scope::purge_session_sealed_values_conn(
                    conn,
                    &session_id.to_string(),
                    now_ms,
                )?;
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
        let column_names: Vec<String> = db
            .blocking_write_for_sync_maintenance(|conn| {
                let mut stmt = conn.prepare("PRAGMA table_info(sessions)")?;
                let names = stmt
                    .query_map([], |row| row.get::<_, String>(1))?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                Ok(names)
            })
            .unwrap();
        assert!(
            !column_names
                .iter()
                .any(|name| name == "redaction_table_json"),
            "sessions.redaction_table_json must not hold plaintext literals"
        );
        let loaded = session.persisted_redaction_table().unwrap().unwrap();
        assert!(
            !loaded
                .scrub("first-high-entropy-token")
                .contains("first-high-entropy-token")
        );
    }

    #[test]
    fn session_fork_fails_closed_when_redaction_vault_read_errors() {
        let db = crate::db::Db::open_in_memory().unwrap();
        let parent = Session::create_for_test(
            db.clone(),
            PathBuf::from("/repo"),
            "Build",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap();
        const SECRET: &str = "fork-vault-read-secret-abcdef123";
        let table = crate::redact::RedactionTable::empty()
            .with_forced_literal(SECRET.to_string(), "test".to_string())
            .unwrap();
        parent.persist_redaction_table(&table).unwrap();
        crate::secure_key::tamper_item_ciphertext(
            &db,
            cockpit_db::secret_vault::SecretVaultKind::RedactionTable,
            &crate::secure_key::redaction_table_item_id(&parent.id.to_string()),
            |ciphertext| ciphertext[0] ^= 0xff,
        )
        .unwrap();
        let err = Session::create_fork_for_test(
            db.clone(),
            parent.id,
            None,
            crate::session::test_redaction_key_resolver(),
        )
        .expect_err("fork must refuse to proceed without the parent redaction table");
        let message = format!("{err:#}");
        assert!(
            message.contains("refusing to proceed unredacted"),
            "visible fail-closed signal missing: {message}"
        );
        let child_ids: Vec<String> = db
            .blocking_write_for_sync_maintenance({
                let parent_id = parent.id.to_string();
                move |conn| {
                    let mut stmt = conn
                        .prepare("SELECT session_id FROM sessions WHERE parent_session_id = ?1")?;
                    let ids = stmt
                        .query_map(rusqlite::params![parent_id], |row| row.get::<_, String>(0))?
                        .collect::<rusqlite::Result<Vec<_>>>()?;
                    Ok(ids)
                }
            })
            .unwrap();
        assert!(
            child_ids.is_empty(),
            "failed fork must not leave a persisted child: {child_ids:?}"
        );
    }

    #[test]
    fn session_fork_fails_closed_when_parent_redaction_vault_item_is_missing() {
        let db = crate::db::Db::open_in_memory().unwrap();
        let parent = Session::create_for_test(
            db.clone(),
            PathBuf::from("/repo"),
            "Build",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap();
        crate::secure_key::vault_for_db(&db)
            .unwrap()
            .delete_item(
                cockpit_db::secret_vault::SecretVaultKind::RedactionTable,
                &crate::secure_key::redaction_table_item_id(&parent.id.to_string()),
            )
            .unwrap();
        let err = Session::create_fork_for_test(
            db.clone(),
            parent.id,
            None,
            crate::session::test_redaction_key_resolver(),
        )
        .expect_err("fork must refuse to proceed without the parent redaction table");
        let message = format!("{err:#}");
        assert!(
            crate::redact::RedactionTableUnavailable::in_chain(&err),
            "missing parent table must be a typed redaction failure: {message}"
        );
        assert!(
            message.contains("refusing to proceed unredacted"),
            "visible fail-closed signal missing: {message}"
        );
        let child_ids: Vec<String> = db
            .blocking_write_for_sync_maintenance({
                let parent_id = parent.id.to_string();
                move |conn| {
                    let mut stmt = conn
                        .prepare("SELECT session_id FROM sessions WHERE parent_session_id = ?1")?;
                    let ids = stmt
                        .query_map(rusqlite::params![parent_id], |row| row.get::<_, String>(0))?
                        .collect::<rusqlite::Result<Vec<_>>>()?;
                    Ok(ids)
                }
            })
            .unwrap();
        assert!(
            child_ids.is_empty(),
            "failed fork must not leave a persisted child: {child_ids:?}"
        );
    }

    #[test]
    fn resume_fails_closed_when_redaction_vault_item_is_missing() {
        let db = crate::db::Db::open_in_memory().unwrap();
        let session = Session::create_for_test(
            db.clone(),
            PathBuf::from("/repo"),
            "Build",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap();
        crate::secure_key::vault_for_db(&db)
            .unwrap()
            .delete_item(
                cockpit_db::secret_vault::SecretVaultKind::RedactionTable,
                &crate::secure_key::redaction_table_item_id(&session.id.to_string()),
            )
            .unwrap();
        let session_id = session.id;
        drop(session);
        let err = Session::resume_for_test(
            db,
            session_id,
            crate::session::test_redaction_key_resolver(),
        )
        .expect_err("resume must refuse a durable session without redaction custody");
        let message = format!("{err:#}");
        assert!(
            crate::redact::RedactionTableUnavailable::in_chain(&err),
            "missing table must be a typed redaction failure: {message}"
        );
        assert!(
            message.contains("refusing to proceed unredacted"),
            "visible fail-closed signal missing: {message}"
        );
    }

    #[tokio::test]
    async fn btw_fork_copies_parent_redaction_table() {
        let db = crate::db::Db::open_in_memory().unwrap();
        let parent = Session::create_for_test(
            db.clone(),
            PathBuf::from("/repo"),
            "Build",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap();
        const SECRET: &str = "btw-parent-redaction-secret-abcdef123";
        let table = crate::redact::RedactionTable::empty()
            .with_forced_literal(SECRET.to_string(), "test".to_string())
            .unwrap();
        parent.persist_redaction_table(&table).unwrap();
        let vault = crate::secure_key::vault_for_db(&db).unwrap();
        let seeded = persist_btw_fork_with_redaction_custody(&db, vault, parent.id, false)
            .await
            .expect("seeded /btw must copy parent redaction custody");
        assert!(seeded.created);
        let child = Session::resume_for_test(
            db,
            seeded.info.session_id,
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap()
        .expect("seeded /btw child");
        assert_ne!(
            child
                .persisted_redaction_table()
                .unwrap()
                .unwrap()
                .scrub(SECRET),
            SECRET,
            "non-tangent /btw must inherit parent redaction coverage"
        );
    }

    #[tokio::test]
    async fn btw_fork_fails_closed_when_parent_redaction_vault_item_is_missing() {
        let db = crate::db::Db::open_in_memory().unwrap();
        let parent = Session::create_for_test(
            db.clone(),
            PathBuf::from("/repo"),
            "Build",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap();
        crate::secure_key::vault_for_db(&db)
            .unwrap()
            .delete_item(
                cockpit_db::secret_vault::SecretVaultKind::RedactionTable,
                &crate::secure_key::redaction_table_item_id(&parent.id.to_string()),
            )
            .unwrap();
        let vault = crate::secure_key::vault_for_db(&db).unwrap();
        let err = persist_btw_fork_with_redaction_custody(&db, vault, parent.id, false)
            .await
            .expect_err("/btw must refuse to proceed without the parent redaction table");
        let message = format!("{err:#}");
        assert!(
            crate::redact::RedactionTableUnavailable::in_chain(&err),
            "missing parent table must be a typed redaction failure: {message}"
        );
        assert!(
            message.contains("refusing to proceed unredacted"),
            "visible fail-closed signal missing: {message}"
        );
        let child_ids: Vec<String> = db
            .blocking_write_for_sync_maintenance({
                let parent_id = parent.id.to_string();
                move |conn| {
                    let mut stmt = conn.prepare(
                        "SELECT session_id FROM sessions WHERE btw_parent_session_id = ?1",
                    )?;
                    let ids = stmt
                        .query_map(rusqlite::params![parent_id], |row| row.get::<_, String>(0))?
                        .collect::<rusqlite::Result<Vec<_>>>()?;
                    Ok(ids)
                }
            })
            .unwrap();
        assert!(
            child_ids.is_empty(),
            "failed /btw must not leave a persisted child: {child_ids:?}"
        );
    }

    #[test]
    fn persist_if_needed_establishes_redaction_custody() {
        let db = crate::db::Db::open_in_memory().unwrap();
        let session = Session::create_deferred_for_test(
            db.clone(),
            PathBuf::from("/repo"),
            "Build",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap();
        assert!(session.persist_if_needed().unwrap());
        session.clear_cached_redaction_table_for_test();
        assert!(
            session.persisted_redaction_table().unwrap().is_some(),
            "flushing a deferred session must establish vault custody"
        );
    }

    #[test]
    fn failed_vault_write_keeps_committed_persisted_cache_and_vault() {
        let db = crate::db::Db::open_in_memory().unwrap();
        let session = Session::create_for_test(
            db.clone(),
            PathBuf::from("/repo"),
            "Build",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap();
        const COMMITTED: &str = "committed-redaction-secret-abcdef123";
        const UNCOMMITTED: &str = "uncommitted-redaction-secret-xyz789";
        let committed = crate::redact::RedactionTable::empty()
            .with_forced_literal(COMMITTED.to_string(), "test".to_string())
            .unwrap();
        session.persist_redaction_table(&committed).unwrap();

        let newer = committed
            .with_forced_literal(UNCOMMITTED.to_string(), "test".to_string())
            .unwrap();
        fail_next_redaction_vault_write_for_test();
        session
            .persist_redaction_table(&newer)
            .expect_err("injected vault write failure must surface");

        let cached = session.persisted_redaction_table().unwrap().unwrap();
        assert_ne!(
            cached.scrub(COMMITTED),
            COMMITTED,
            "committed coverage must remain after a failed persist"
        );
        assert_eq!(
            cached.scrub(UNCOMMITTED),
            UNCOMMITTED,
            "uncommitted table must not be advertised as persisted"
        );

        session.clear_cached_redaction_table_for_test();
        let from_vault = session.persisted_redaction_table().unwrap().unwrap();
        assert_ne!(from_vault.scrub(COMMITTED), COMMITTED);
        assert_eq!(
            from_vault.scrub(UNCOMMITTED),
            UNCOMMITTED,
            "vault must remain at the last committed table after a failed persist"
        );
    }

    #[tokio::test]
    async fn persist_session_with_redaction_custody_is_resumable() {
        let db = crate::db::Db::open_in_memory().unwrap();
        let vault = crate::secure_key::vault_for_db(&db).unwrap();
        let row = persist_session_with_redaction_custody(&db, vault, "p", "/repo", "Build")
            .await
            .unwrap();
        Session::resume_for_test(
            db,
            row.session_id,
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap()
        .expect("new root session must resume with redaction custody");
    }

    #[tokio::test]
    async fn persist_assistant_session_with_redaction_custody_is_resumable() {
        let db = crate::db::Db::open_in_memory().unwrap();
        let vault = crate::secure_key::vault_for_db(&db).unwrap();
        let row = persist_assistant_session_with_redaction_custody(
            &db,
            vault,
            "p",
            "/repo",
            "helper-bot",
            "helper-bot",
        )
        .await
        .unwrap();
        assert_eq!(row.session_entry_mode, "assistant");
        let session = Session::resume_for_test(
            db,
            row.session_id,
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap()
        .expect("new assistant session must resume with redaction custody");
        assert_eq!(
            session.session_entry_mode(),
            crate::daemon::proto::SessionEntryMode::Assistant
        );
    }

    #[tokio::test]
    async fn failed_new_session_custody_write_leaves_no_visible_row() {
        let db = crate::db::Db::open_in_memory().unwrap();
        let vault = crate::secure_key::vault_for_db(&db).unwrap();
        fail_next_redaction_vault_write_for_test();
        persist_session_with_redaction_custody(&db, vault, "p", "/repo", "Build")
            .await
            .expect_err("injected vault write failure must surface");
        let rows = db.list_sessions(true, 10).await.unwrap();
        assert!(
            rows.is_empty(),
            "failed custody write must not leave a resumable session: {rows:?}"
        );
    }

    #[test]
    fn production_session_inserts_do_not_use_raw_db_constructors() {
        let src_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files = Vec::new();
        collect_rs_files(&src_dir, &mut files);
        let banned = [
            ".create_session(",
            "db.create_assistant_session(",
            "Db::create_assistant_session(",
        ];
        let offenders: Vec<String> = files
            .into_iter()
            .filter(|path| {
                !path.components().any(|c| {
                    let name = c.as_os_str();
                    name == "tests" || name == "tests.rs"
                })
            })
            .flat_map(|path| {
                let text = std::fs::read_to_string(&path).unwrap();
                let mut depth: i32 = 0;
                let mut cfg_test_pending = false;
                let mut cfg_test_depth: Option<i32> = None;
                let mut hits = Vec::new();
                for (idx, line) in text.lines().enumerate() {
                    let trimmed = line.trim_start();
                    let in_cfg_test = cfg_test_depth.is_some();
                    if !in_cfg_test
                        && !trimmed.starts_with("//")
                        && banned.iter().any(|needle| line.contains(needle))
                    {
                        hits.push(format!("{}:{}:{}", path.display(), idx + 1, line.trim()));
                    }
                    if trimmed.contains("#[cfg(test)]") {
                        cfg_test_pending = true;
                    }
                    let opens = line.matches('{').count() as i32;
                    let closes = line.matches('}').count() as i32;
                    if cfg_test_pending && opens > 0 {
                        cfg_test_depth = Some(depth);
                        cfg_test_pending = false;
                    }
                    depth += opens - closes;
                    if let Some(start) = cfg_test_depth
                        && depth <= start
                    {
                        cfg_test_depth = None;
                    }
                }
                hits
            })
            .collect();
        assert!(
            offenders.is_empty(),
            "production code must create durable sessions through custody-aware helpers, \
             not Db::create_session / Db::create_assistant_session:\n{offenders:#?}"
        );
    }

    fn collect_rs_files(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            if path.is_dir() {
                collect_rs_files(&path, out);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                out.push(path);
            }
        }
    }
}
