//! Daemon-owned agent discovery and mutation.

use std::path::{Path, PathBuf};
use std::time::Duration;

use uuid::Uuid;

use crate::daemon::proto::{
    AgentEditSnapshot, AgentEditTarget, AgentEditorCompletion, AgentEditorLease,
    AgentEditorSettlementStatus, AgentEntryKind, AgentInventoryEntry, AgentMutation,
    AgentMutationResult, AgentSourceLayer, ErrorCode, ErrorPayload, Response,
};
use crate::daemon::server::DaemonContext;

const EDITOR_LEASE_TTL: Duration = Duration::from_secs(8 * 60 * 60);

#[derive(serde::Serialize, serde::Deserialize)]
struct SealedEditorReplay {
    owner_digest: String,
    snapshot: AgentEditSnapshot,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct SealedEditorCompletion {
    owner_digest: String,
    client_operation_id: String,
    project_root: String,
    lease_id: String,
    markdown: Option<String>,
}

impl zeroize::Zeroize for SealedEditorCompletion {
    fn zeroize(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.owner_digest);
        zeroize::Zeroize::zeroize(&mut self.client_operation_id);
        zeroize::Zeroize::zeroize(&mut self.project_root);
        zeroize::Zeroize::zeroize(&mut self.lease_id);
        zeroize::Zeroize::zeroize(&mut self.markdown);
    }
}

fn editor_replay_handle(lease_id: &str) -> String {
    format!("agent-editor-lease:{lease_id}")
}

fn editor_completion_handle(completion_identity: [u8; 32]) -> String {
    format!(
        "agent-editor-completion:{}",
        hex::encode(completion_identity)
    )
}

fn load_editor_completion(
    ctx: &DaemonContext,
    row: &crate::db::agent_editor_leases::AgentEditorLeaseRow,
) -> Result<zeroize::Zeroizing<SealedEditorCompletion>, ErrorPayload> {
    let operation_id = row
        .completion_operation_id
        .as_deref()
        .ok_or_else(|| internal("completing editor lease omitted its operation id"))?;
    let expected_handle = editor_completion_handle(
        row.completion_identity
            .ok_or_else(|| internal("completing editor lease omitted its identity"))?,
    );
    let handle = row
        .completion_handle
        .as_deref()
        .ok_or_else(|| internal("completing editor lease omitted its sealed payload"))?;
    if handle != expected_handle {
        return Err(internal("editor completion payload handle is corrupt"));
    }
    let plaintext = ctx
        .secret_vault
        .get_item(
            cockpit_db::secret_vault::SecretVaultKind::SealedState,
            handle,
        )
        .map_err(internal)?;
    let payload: SealedEditorCompletion =
        serde_json::from_slice(plaintext.as_slice()).map_err(internal)?;
    if payload.owner_digest != row.owner_digest
        || payload.client_operation_id != operation_id
        || payload.project_root != row.project_root
        || payload.lease_id != row.lease_id
    {
        return Err(internal(
            "editor completion sealed payload binding mismatch",
        ));
    }
    let identity_plaintext = zeroize::Zeroizing::new(
        serde_json::to_vec(&(
            "complete_agent_editor_lease",
            &payload.client_operation_id,
            &payload.project_root,
            &payload.lease_id,
            payload.markdown.as_deref(),
        ))
        .map_err(internal)?,
    );
    let identity = ctx.secret_vault.keyed_identity(
        b"flycockpit.agent-editor.completion.v2",
        identity_plaintext.as_slice(),
    );
    if row.completion_identity != Some(identity) {
        return Err(internal(
            "editor completion sealed payload identity mismatch",
        ));
    }
    Ok(zeroize::Zeroizing::new(payload))
}

fn load_editor_replay(
    ctx: &DaemonContext,
    row: &crate::db::agent_editor_leases::AgentEditorLeaseRow,
) -> Result<AgentEditSnapshot, ErrorPayload> {
    let expected_handle = editor_replay_handle(&row.lease_id);
    let handle = row
        .snapshot_handle
        .as_deref()
        .ok_or_else(|| internal("active editor lease omitted its sealed replay handle"))?;
    if handle != expected_handle {
        return Err(internal("editor lease replay handle is corrupt"));
    }
    let plaintext = ctx
        .secret_vault
        .get_item(
            cockpit_db::secret_vault::SecretVaultKind::SealedState,
            handle,
        )
        .map_err(internal)?;
    let identity = ctx
        .secret_vault
        .keyed_identity(b"flycockpit.agent-editor.snapshot.v1", plaintext.as_slice());
    if identity != row.snapshot_identity {
        return Err(internal("editor lease sealed replay identity mismatch"));
    }
    let replay: SealedEditorReplay =
        serde_json::from_slice(plaintext.as_slice()).map_err(internal)?;
    if replay.owner_digest != row.owner_digest {
        return Err(internal("editor lease sealed replay owner mismatch"));
    }
    Ok(replay.snapshot)
}

async fn delete_editor_replay_and_row(
    ctx: &DaemonContext,
    row: crate::db::agent_editor_leases::AgentEditorLeaseRow,
) -> Result<(), ErrorPayload> {
    let vault = ctx.secret_vault.clone();
    let handle = row
        .snapshot_handle
        .unwrap_or_else(|| editor_replay_handle(&row.lease_id));
    let lease_id = row.lease_id;
    ctx.db
        .transaction(move |conn| {
            let deleted = conn.execute(
                "DELETE FROM agent_editor_leases WHERE lease_id=?1 AND state='open' AND expires_at_unix_ms < ?2",
                rusqlite::params![&lease_id, chrono::Utc::now().timestamp_millis()],
            )?;
            if deleted == 0 {
                return Ok(());
            }
            vault
                .mutate_item_on_conn(
                    conn,
                    cockpit_db::secret_vault::SecretVaultKind::SealedState,
                    &handle,
                    None,
                )
                .map_err(|error| anyhow::anyhow!(error))?;
            Ok(())
        })
        .await
        .map_err(internal)
}

async fn terminalize_editor_failure(
    ctx: &DaemonContext,
    row: &crate::db::agent_editor_leases::AgentEditorLeaseRow,
    project_root: &str,
    completion_identity: [u8; 32],
    error: &ErrorPayload,
) -> Result<AgentEditorCompletion, ErrorPayload> {
    let error = safe_editor_rejection(error);
    let receipt = editor_completion(
        row,
        row.completion_operation_id
            .as_deref()
            .ok_or_else(|| internal("editor failure omitted its client operation identity"))?,
        project_root,
        AgentEditorSettlementStatus::Rejected { error },
    );
    let terminal_error_json = serde_json::to_string(&receipt).map_err(internal)?;
    let completion_operation_id = receipt.client_operation_id.clone();
    let lease_id = row.lease_id.clone();
    let replay_handle = editor_replay_handle(&lease_id);
    let completion_handle = row.completion_handle.clone();
    let vault = ctx.secret_vault.clone();
    ctx.db
        .transaction(move |conn| {
            vault
                .mutate_item_on_conn(
                    conn,
                    cockpit_db::secret_vault::SecretVaultKind::SealedState,
                    &replay_handle,
                    None,
                )
                .map_err(|error| anyhow::anyhow!(error))?;
            if let Some(handle) = completion_handle.as_deref() {
                vault
                    .mutate_item_on_conn(
                        conn,
                        cockpit_db::secret_vault::SecretVaultKind::SealedState,
                        handle,
                        None,
                    )
                    .map_err(|error| anyhow::anyhow!(error))?;
            }
            crate::db::agent_editor_leases::fail_agent_editor_completion_conn(
                conn,
                &lease_id,
                completion_identity,
                &completion_operation_id,
                &terminal_error_json,
            )
        })
        .await
        .map_err(internal)?;
    Ok(receipt)
}

/// Boot/periodic maintenance for abandoned editor authority. Expired open
/// leases and their sealed payloads disappear atomically. Completing claims
/// remain durable across restart: after the bounded claim interval, the exact
/// operation may resubmit its original content and reconcile the filesystem.
pub(crate) async fn maintain_editor_leases(ctx: &DaemonContext) -> Result<(), ErrorPayload> {
    let expired = ctx
        .db
        .expired_open_agent_editor_leases(chrono::Utc::now().timestamp_millis())
        .await
        .map_err(internal)?;
    for row in expired {
        delete_editor_replay_and_row(ctx, row).await?;
    }
    let stale_before = chrono::Utc::now()
        .timestamp_millis()
        .saturating_sub(crate::db::agent_editor_leases::AGENT_EDITOR_COMPLETION_CLAIM_MS);
    let completing = ctx
        .db
        .recoverable_agent_editor_completions(stale_before)
        .await
        .map_err(internal)?;
    for row in completing {
        let payload = match load_editor_completion(ctx, &row) {
            Ok(payload) => payload,
            Err(error) => {
                let identity = row
                    .completion_identity
                    .ok_or_else(|| internal("completing editor lease omitted its identity"))?;
                terminalize_editor_failure(ctx, &row, &row.project_root, identity, &error).await?;
                continue;
            }
        };
        if let Err(error) = complete_editor_lease(
            ctx,
            payload.client_operation_id.clone(),
            payload.project_root.clone(),
            payload.lease_id.clone(),
            payload.markdown.clone(),
            payload.owner_digest.clone(),
        )
        .await
        {
            let identity = row
                .completion_identity
                .ok_or_else(|| internal("completing editor lease omitted its identity"))?;
            terminalize_editor_failure(ctx, &row, &row.project_root, identity, &error).await?;
        }
    }
    Ok(())
}

/// The singleton daemon may reclaim every incomplete editor completion during
/// pre-socket boot: no live predecessor can still own the in-memory claim.
pub(crate) async fn recover_editor_leases_before_publish(
    ctx: &DaemonContext,
) -> Result<(), ErrorPayload> {
    let completing = ctx
        .db
        .recoverable_agent_editor_completions(chrono::Utc::now().timestamp_millis())
        .await
        .map_err(internal)?;
    for row in completing {
        let payload = match load_editor_completion(ctx, &row) {
            Ok(payload) => payload,
            Err(error) => {
                let identity = row
                    .completion_identity
                    .ok_or_else(|| internal("completing editor lease omitted its identity"))?;
                terminalize_editor_failure(ctx, &row, &row.project_root, identity, &error).await?;
                continue;
            }
        };
        if let Err(error) = complete_editor_lease_inner(
            ctx,
            payload.client_operation_id.clone(),
            payload.project_root.clone(),
            payload.lease_id.clone(),
            payload.markdown.clone(),
            payload.owner_digest.clone(),
            true,
        )
        .await
        {
            let identity = row
                .completion_identity
                .ok_or_else(|| internal("completing editor lease omitted its identity"))?;
            terminalize_editor_failure(ctx, &row, &row.project_root, identity, &error).await?;
        }
    }
    Ok(())
}

pub async fn inventory(
    ctx: &DaemonContext,
    project_root: String,
) -> Result<Response, ErrorPayload> {
    let root = trusted_root(ctx, &project_root).await?;
    maintain_editor_leases(ctx).await?;
    tokio::task::spawn_blocking(move || {
        let guard =
            cockpit_config::config::hold_config_mutation_lock(&root.join(".cockpit/config.json"))
                .map_err(internal)?;
        inventory_sync(&root, &guard)
    })
    .await
    .map_err(join_error)?
}

pub async fn edit_snapshot(
    ctx: &DaemonContext,
    project_root: String,
    name: String,
) -> Result<Response, ErrorPayload> {
    let root = trusted_root(ctx, &project_root).await?;
    tokio::task::spawn_blocking(move || {
        let guard =
            cockpit_config::config::hold_config_mutation_lock(&root.join(".cockpit/config.json"))
                .map_err(internal)?;
        recover_reset_all_locked(&root, &guard)?;
        snapshot_sync(&root, &name).map(Response::AgentEditSnapshot)
    })
    .await
    .map_err(join_error)?
}

pub async fn mutate(
    ctx: &DaemonContext,
    project_root: String,
    mutation: AgentMutation,
    expected_revision: Option<String>,
) -> Result<Response, ErrorPayload> {
    let root = trusted_root(ctx, &project_root).await?;
    tokio::task::spawn_blocking(move || mutate_sync(&root, mutation, expected_revision))
        .await
        .map_err(join_error)?
}

pub async fn begin_editor_lease(
    ctx: &DaemonContext,
    client_operation_id: String,
    project_root: String,
    name: String,
    expected_revision: String,
    principal_digest: String,
) -> Result<Response, ErrorPayload> {
    if let Some(existing) = ctx
        .db
        .agent_editor_lease_by_operation(principal_digest.clone(), client_operation_id.clone())
        .await
        .map_err(internal)?
    {
        if existing.project_root != project_root
            || existing.agent_name != name
            || existing.consumed_revision != expected_revision
        {
            return Err(conflict(
                "agent editor client operation was reused for a different request",
            ));
        }
        if existing.expires_at_unix_ms < chrono::Utc::now().timestamp_millis()
            && existing.state != "terminal"
        {
            delete_editor_replay_and_row(ctx, existing).await?;
            return Err(conflict(
                "agent editor lease acquisition expired before it was acknowledged; start a new editor handoff",
            ));
        }
        if existing.state == "terminal" {
            return Err(conflict(
                "agent editor lease acquisition was already settled; start a new editor handoff",
            ));
        }
        let snapshot = load_editor_replay(ctx, &existing)?;
        return Ok(Response::AgentEditorLeaseBegun(AgentEditorLease {
            client_operation_id: existing.client_operation_id,
            lease_id: existing.lease_id,
            expires_at_unix_ms: existing.expires_at_unix_ms,
            snapshot,
        }));
    }
    // Exact durable replay is independent of the workspace's current trust
    // configuration. Only issuance of new filesystem authority is trust-gated.
    maintain_editor_leases(ctx).await?;
    let root = crate::daemon::fs_api::canonical_project_root(&project_root)?;
    let root_text = root.to_string_lossy().into_owned();
    let root = trusted_canonical_root(ctx, root).await?;
    let snapshot = tokio::task::spawn_blocking({
        let root = root.clone();
        let name = name.clone();
        move || {
            let guard = cockpit_config::config::hold_config_mutation_lock(
                &root.join(".cockpit/config.json"),
            )
            .map_err(internal)?;
            recover_reset_all_locked(&root, &guard)?;
            snapshot_sync(&root, &name)
        }
    })
    .await
    .map_err(join_error)??;
    ensure_revision(&snapshot.revision, Some(&expected_revision))?;
    let lease_id = Uuid::new_v4().to_string();
    let expires_at_unix_ms = chrono::Utc::now().timestamp_millis()
        + i64::try_from(EDITOR_LEASE_TTL.as_millis()).unwrap_or(i64::MAX);
    let replay_plaintext = zeroize::Zeroizing::new(
        serde_json::to_vec(&SealedEditorReplay {
            owner_digest: principal_digest.clone(),
            snapshot: snapshot.clone(),
        })
        .map_err(internal)?,
    );
    let snapshot_identity = ctx.secret_vault.keyed_identity(
        b"flycockpit.agent-editor.snapshot.v1",
        replay_plaintext.as_slice(),
    );
    let snapshot_handle = editor_replay_handle(&lease_id);
    let replay_owner = principal_digest.clone();
    let replay_operation = client_operation_id.clone();
    let response_operation = client_operation_id.clone();
    let replay_root = root_text.clone();
    let replay_name = name.clone();
    let replay_revision = expected_revision.clone();
    let row = crate::db::agent_editor_leases::AgentEditorLeaseRow {
        owner_digest: principal_digest,
        client_operation_id,
        lease_id: lease_id.clone(),
        project_root: root_text,
        agent_name: name,
        consumed_revision: expected_revision,
        snapshot_handle: Some(snapshot_handle.clone()),
        snapshot_identity,
        state: "open".into(),
        completion_identity: None,
        completion_handle: None,
        completion_operation_id: None,
        terminal_result_json: None,
        terminal_error_json: None,
        expires_at_unix_ms,
        updated_at_unix_ms: chrono::Utc::now().timestamp_millis(),
    };
    let vault = ctx.secret_vault.clone();
    let inserted = ctx
        .db
        .transaction(move |conn| {
            vault
                .mutate_item_on_conn(
                    conn,
                    cockpit_db::secret_vault::SecretVaultKind::SealedState,
                    &snapshot_handle,
                    Some(replay_plaintext.as_slice()),
                )
                .map_err(|error| anyhow::anyhow!(error))?;
            crate::db::agent_editor_leases::insert_agent_editor_lease_conn(conn, &row)?;
            Ok(())
        })
        .await;
    if let Err(insert_error) = inserted {
        // A concurrent duplicate Begin can win the owner/operation unique key
        // after our initial lookup. Replay only an exact binding; never turn a
        // key collision into a second lease.
        let existing = ctx
            .db
            .agent_editor_lease_by_operation(replay_owner, replay_operation)
            .await
            .map_err(internal)?;
        if let Some(existing) = existing
            && existing.project_root == replay_root
            && existing.agent_name == replay_name
            && existing.consumed_revision == replay_revision
        {
            if existing.expires_at_unix_ms < chrono::Utc::now().timestamp_millis()
                && existing.state != "terminal"
            {
                delete_editor_replay_and_row(ctx, existing).await?;
                return Err(conflict(
                    "agent editor lease acquisition expired before it was acknowledged; start a new editor handoff",
                ));
            }
            if existing.state == "terminal" {
                return Err(conflict(
                    "agent editor lease acquisition was already settled; start a new editor handoff",
                ));
            }
            let snapshot = load_editor_replay(ctx, &existing)?;
            return Ok(Response::AgentEditorLeaseBegun(AgentEditorLease {
                client_operation_id: existing.client_operation_id,
                lease_id: existing.lease_id,
                expires_at_unix_ms: existing.expires_at_unix_ms,
                snapshot,
            }));
        }
        return Err(internal(insert_error));
    }
    Ok(Response::AgentEditorLeaseBegun(AgentEditorLease {
        client_operation_id: response_operation,
        lease_id,
        expires_at_unix_ms,
        snapshot,
    }))
}

pub async fn complete_editor_lease(
    ctx: &DaemonContext,
    client_operation_id: String,
    project_root: String,
    lease_id: String,
    markdown: Option<String>,
    principal_digest: String,
) -> Result<Response, ErrorPayload> {
    complete_editor_lease_inner(
        ctx,
        client_operation_id,
        project_root,
        lease_id,
        markdown,
        principal_digest,
        false,
    )
    .await
}

async fn complete_editor_lease_inner(
    ctx: &DaemonContext,
    client_operation_id: String,
    project_root: String,
    lease_id: String,
    markdown: Option<String>,
    principal_digest: String,
    force_reclaim: bool,
) -> Result<Response, ErrorPayload> {
    Uuid::parse_str(&lease_id).map_err(|_| bad_request("invalid editor lease"))?;
    let known_lease = ctx
        .db
        .agent_editor_lease_by_id(lease_id.clone())
        .await
        .map_err(internal)?
        .ok_or_else(|| conflict("editor lease is absent or expired"))?;
    if known_lease.owner_digest != principal_digest {
        return Err(ErrorPayload {
            code: ErrorCode::Authorization,
            message: "agent editor lease belongs to another client principal".into(),
        });
    }
    // Validate every immutable capability target before changing the durable
    // lease state. A typo, stale workspace selection, or malformed persisted
    // snapshot must not poison an otherwise reusable lease by reserving its
    // one completion slot.
    if known_lease.project_root != project_root {
        return Err(bad_request("editor lease belongs to another workspace"));
    }
    let root_text = known_lease.project_root.clone();
    let completion_plaintext = zeroize::Zeroizing::new(
        serde_json::to_vec(&(
            "complete_agent_editor_lease",
            &client_operation_id,
            &root_text,
            &lease_id,
            markdown.as_deref(),
        ))
        .map_err(internal)?,
    );
    let completion_identity = ctx.secret_vault.keyed_identity(
        b"flycockpit.agent-editor.completion.v2",
        completion_plaintext.as_slice(),
    );
    if known_lease.state == "open" {
        load_editor_replay(ctx, &known_lease)?;
    }
    if known_lease.state == "terminal" {
        if known_lease.completion_identity != Some(completion_identity) {
            return Err(conflict(
                "agent editor lease was settled by a different completion request",
            ));
        }
        let json = known_lease
            .terminal_result_json
            .as_deref()
            .or(known_lease.terminal_error_json.as_deref())
            .ok_or_else(|| internal("terminal editor lease omitted its receipt"))?;
        let result: AgentEditorCompletion = serde_json::from_str(json).map_err(internal)?;
        if result.client_operation_id != client_operation_id {
            return Err(conflict(
                "agent editor lease was settled by a different client operation",
            ));
        }
        validate_editor_completion_receipt(&known_lease, &result)?;
        return Ok(Response::AgentEditorLeaseCompleted(result));
    }
    // Durable terminal replay and identity conflicts above do not depend on
    // mutable trust. A new or resumed filesystem mutation still does.
    let root = trusted_canonical_root(ctx, PathBuf::from(&root_text)).await?;
    // Expiry prevents an unacknowledged Begin from being replayed as apparent
    // success forever; it must not make an already-issued capability
    // impossible to settle. Completion remains exact-hash and owner bound, so
    // a client can reconcile a commit whose response was lost after the TTL.
    let completion_handle = editor_completion_handle(completion_identity);
    let sealed_completion = zeroize::Zeroizing::new(
        serde_json::to_vec(&SealedEditorCompletion {
            owner_digest: principal_digest.clone(),
            client_operation_id: client_operation_id.clone(),
            project_root: root_text.clone(),
            lease_id: lease_id.clone(),
            markdown: markdown.clone(),
        })
        .map_err(internal)?,
    );
    let reservation_lease_id = lease_id.clone();
    let reservation_owner = principal_digest.clone();
    let reservation_operation = client_operation_id.clone();
    let reservation_handle = completion_handle.clone();
    let snapshot_handle = editor_replay_handle(&lease_id);
    let vault = ctx.secret_vault.clone();
    // Sealing the submitted bytes, removing the now-obsolete edit snapshot,
    // and claiming completion authority are one SQLite transaction. There is
    // therefore no crash window with a completing row but no replay evidence.
    let lease = ctx
        .db
        .transaction(move |conn| {
            vault
                .mutate_item_on_conn(
                    conn,
                    cockpit_db::secret_vault::SecretVaultKind::SealedState,
                    &reservation_handle,
                    Some(sealed_completion.as_slice()),
                )
                .map_err(|error| anyhow::anyhow!(error))?;
            let claim = crate::db::agent_editor_leases::reserve_agent_editor_completion_conn(
                conn,
                &reservation_lease_id,
                &reservation_owner,
                completion_identity,
                &reservation_handle,
                &reservation_operation,
                force_reclaim,
            )?;
            if matches!(
                claim,
                crate::db::agent_editor_leases::AgentEditorCompletionClaim::Execute(_)
            ) {
                vault
                    .mutate_item_on_conn(
                        conn,
                        cockpit_db::secret_vault::SecretVaultKind::SealedState,
                        &snapshot_handle,
                        None,
                    )
                    .map_err(|error| anyhow::anyhow!(error))?;
            }
            Ok(claim)
        })
        .await
        .map_err(|error| conflict(error.to_string()))?;
    let lease = match lease {
        crate::db::agent_editor_leases::AgentEditorCompletionClaim::Execute(lease) => lease,
        crate::db::agent_editor_leases::AgentEditorCompletionClaim::Pending => {
            return Ok(Response::AgentEditorLeaseCompleted(editor_completion(
                &known_lease,
                &client_operation_id,
                &root_text,
                AgentEditorSettlementStatus::Pending,
            )));
        }
        crate::db::agent_editor_leases::AgentEditorCompletionClaim::Terminal(lease) => lease,
    };
    if let Some(json) = lease.terminal_result_json.as_deref() {
        let result: AgentEditorCompletion = serde_json::from_str(&json).map_err(internal)?;
        return Ok(Response::AgentEditorLeaseCompleted(result));
    }
    if let Some(json) = lease.terminal_error_json.as_deref() {
        let result: AgentEditorCompletion = serde_json::from_str(&json).map_err(internal)?;
        return Ok(Response::AgentEditorLeaseCompleted(result));
    }
    let completed_lease_id = lease_id.clone();
    let consumed_lease_revision = lease.consumed_revision.clone();
    let is_save = markdown.is_some();
    let result = match markdown {
        Some(markdown) => {
            // A prior daemon may have committed the file and crashed before
            // recording its terminal receipt. Reconcile exact content before
            // attempting the CAS again.
            let current = match tokio::task::spawn_blocking({
                let root = root.clone();
                let name = lease.agent_name.clone();
                move || snapshot_sync(&root, &name)
            })
            .await
            .map_err(join_error)
            .and_then(|result| result)
            {
                Ok(current) => current,
                Err(error) => {
                    let receipt = terminalize_editor_failure(
                        ctx,
                        &lease,
                        &root_text,
                        completion_identity,
                        &error,
                    )
                    .await?;
                    return Ok(Response::AgentEditorLeaseCompleted(receipt));
                }
            };
            if current.markdown == markdown {
                Response::AgentMutated(AgentMutationResult {
                    changed: true,
                    affected: 1,
                    snapshot: Some(current),
                    config_generation: crate::daemon::server::inventory::current_config_generation(
                    ),
                    inventory_revision: None,
                    consumed_revision: Some(consumed_lease_revision.clone()),
                    completed_lease_id: None,
                    outcome: cockpit_proto::AgentMutationOutcome::Reconciled,
                })
            } else {
                let agent_name = lease.agent_name.clone();
                let consumed_revision = lease.consumed_revision.clone();
                let submitted_markdown = markdown.clone();
                let reconcile_root = root.clone();
                let reconcile_name = agent_name.clone();
                match tokio::task::spawn_blocking(move || {
                    mutate_sync(
                        &root,
                        AgentMutation::SaveDefinition {
                            name: agent_name,
                            markdown,
                        },
                        Some(consumed_revision),
                    )
                })
                .await
                .map_err(join_error)
                .and_then(|result| result)
                {
                    Ok(result) => result,
                    Err(error) => {
                        let reconciled = tokio::task::spawn_blocking(move || {
                            snapshot_sync(&reconcile_root, &reconcile_name)
                        })
                        .await
                        .ok()
                        .and_then(Result::ok)
                        .filter(|snapshot| snapshot.markdown == submitted_markdown);
                        if let Some(snapshot) = reconciled {
                            Response::AgentMutated(AgentMutationResult {
                                changed: true,
                                affected: 1,
                                snapshot: Some(snapshot),
                                config_generation:
                                    crate::daemon::server::inventory::current_config_generation(),
                                inventory_revision: None,
                                consumed_revision: Some(consumed_lease_revision.clone()),
                                completed_lease_id: None,
                                outcome: cockpit_proto::AgentMutationOutcome::Reconciled,
                            })
                        } else {
                            let receipt = terminalize_editor_failure(
                                ctx,
                                &lease,
                                &root_text,
                                completion_identity,
                                &error,
                            )
                            .await?;
                            return Ok(Response::AgentEditorLeaseCompleted(receipt));
                        }
                    }
                }
            }
        }
        None => Response::AgentMutated(AgentMutationResult {
            changed: false,
            affected: 0,
            snapshot: None,
            config_generation: crate::daemon::server::inventory::current_config_generation(),
            inventory_revision: None,
            consumed_revision: Some(consumed_lease_revision),
            completed_lease_id: None,
            outcome: cockpit_proto::AgentMutationOutcome::Reconciled,
        }),
    };
    let Response::AgentMutated(mut result) = result else {
        unreachable!("agent mutation always returns AgentMutated")
    };
    result.completed_lease_id = Some(completed_lease_id);
    let status = if is_save {
        let Some(result_revision) = result
            .snapshot
            .as_ref()
            .map(|snapshot| snapshot.revision.clone())
        else {
            return Ok(Response::AgentEditorLeaseCompleted(editor_completion(
                &lease,
                &client_operation_id,
                &root_text,
                AgentEditorSettlementStatus::Pending,
            )));
        };
        AgentEditorSettlementStatus::Saved {
            result_revision,
            outcome: result.outcome.clone(),
        }
    } else {
        AgentEditorSettlementStatus::Cancelled
    };
    // Durable settlement is a typed metadata receipt, not another copy of the
    // agent document. A replay can refresh the authoritative snapshot.
    let receipt = editor_completion(&lease, &client_operation_id, &root_text, status);
    let result_json = match serde_json::to_string(&receipt) {
        Ok(json) => json,
        Err(error) => {
            let error = internal(error);
            if let Ok(receipt) =
                terminalize_editor_failure(ctx, &lease, &root_text, completion_identity, &error)
                    .await
            {
                return Ok(Response::AgentEditorLeaseCompleted(receipt));
            }
            return Ok(Response::AgentEditorLeaseCompleted(editor_completion(
                &lease,
                &client_operation_id,
                &root_text,
                AgentEditorSettlementStatus::Pending,
            )));
        }
    };
    let vault = ctx.secret_vault.clone();
    let terminal_completion_handle = completion_handle;
    let settlement_operation_id = client_operation_id.clone();
    if let Err(error) = ctx
        .db
        .transaction(move |conn| {
            vault
                .mutate_item_on_conn(
                    conn,
                    cockpit_db::secret_vault::SecretVaultKind::SealedState,
                    &terminal_completion_handle,
                    None,
                )
                .map_err(|error| anyhow::anyhow!(error))?;
            crate::db::agent_editor_leases::finish_agent_editor_completion_conn(
                conn,
                &lease_id,
                completion_identity,
                &settlement_operation_id,
                &result_json,
            )
        })
        .await
    {
        // The filesystem mutation may already be durable. Leave the exact
        // completion identity claimed so retry/restart reconciliation checks
        // authoritative content rather than reporting a false failure.
        tracing::warn!(error = %error, "editor settlement receipt persistence is unresolved");
        return Ok(Response::AgentEditorLeaseCompleted(editor_completion(
            &lease,
            &client_operation_id,
            &root_text,
            AgentEditorSettlementStatus::Pending,
        )));
    }
    Ok(Response::AgentEditorLeaseCompleted(receipt))
}

pub async fn editor_lease_settlement(
    ctx: &DaemonContext,
    client_operation_id: String,
    project_root: String,
    lease_id: String,
    principal_digest: String,
) -> Result<Response, ErrorPayload> {
    Uuid::parse_str(&lease_id).map_err(|_| bad_request("invalid editor lease"))?;
    let row = ctx
        .db
        .agent_editor_lease_by_id(lease_id)
        .await
        .map_err(internal)?
        .ok_or_else(|| conflict("editor lease is absent or expired"))?;
    if row.owner_digest != principal_digest {
        return Err(ErrorPayload {
            code: ErrorCode::Authorization,
            message: "agent editor lease belongs to another client principal".into(),
        });
    }
    if row.project_root != project_root {
        return Err(bad_request("editor lease belongs to another workspace"));
    }
    let root_text = row.project_root.clone();
    let status = match row.completion_operation_id.as_deref() {
        None => AgentEditorSettlementStatus::NotStarted,
        Some(operation) if operation != client_operation_id => {
            return Err(conflict(
                "agent editor lease was settled by a different client operation",
            ));
        }
        Some(_)
            if row.state == "completing"
                && row.updated_at_unix_ms.saturating_add(
                    crate::db::agent_editor_leases::AGENT_EDITOR_COMPLETION_CLAIM_MS,
                ) <= chrono::Utc::now().timestamp_millis() =>
        {
            AgentEditorSettlementStatus::NotStarted
        }
        Some(_) if row.state == "completing" => AgentEditorSettlementStatus::Pending,
        Some(_) => {
            let json = row
                .terminal_result_json
                .as_deref()
                .or(row.terminal_error_json.as_deref())
                .ok_or_else(|| internal("terminal editor lease omitted its receipt"))?;
            let receipt: AgentEditorCompletion = serde_json::from_str(json).map_err(internal)?;
            validate_editor_completion_receipt(&row, &receipt)?;
            return Ok(Response::AgentEditorLeaseCompleted(receipt));
        }
    };
    Ok(Response::AgentEditorLeaseCompleted(editor_completion(
        &row,
        &client_operation_id,
        &root_text,
        status,
    )))
}

fn editor_completion(
    row: &crate::db::agent_editor_leases::AgentEditorLeaseRow,
    client_operation_id: &str,
    project_root: &str,
    status: AgentEditorSettlementStatus,
) -> AgentEditorCompletion {
    AgentEditorCompletion {
        client_operation_id: client_operation_id.to_owned(),
        project_root: project_root.to_owned(),
        agent_name: row.agent_name.clone(),
        lease_id: row.lease_id.clone(),
        consumed_revision: row.consumed_revision.clone(),
        status,
    }
}

fn validate_editor_completion_receipt(
    row: &crate::db::agent_editor_leases::AgentEditorLeaseRow,
    receipt: &AgentEditorCompletion,
) -> Result<(), ErrorPayload> {
    if receipt.client_operation_id != row.completion_operation_id.as_deref().unwrap_or_default()
        || receipt.project_root != row.project_root
        || receipt.agent_name != row.agent_name
        || receipt.lease_id != row.lease_id
        || receipt.consumed_revision != row.consumed_revision
    {
        return Err(internal("editor completion receipt binding mismatch"));
    }
    Ok(())
}

fn safe_editor_rejection(error: &ErrorPayload) -> ErrorPayload {
    let message = match &error.code {
        ErrorCode::Conflict => {
            "agent editor settlement conflicted with current authority; reopen the editor"
        }
        ErrorCode::BadRequest => {
            "agent editor content was rejected; reopen the editor to correct it"
        }
        _ => "agent editor settlement failed after reservation; retry the exact operation",
    };
    ErrorPayload {
        code: error.code.clone(),
        message: message.into(),
    }
}

async fn trusted_root(ctx: &DaemonContext, root: &str) -> Result<PathBuf, ErrorPayload> {
    let root = crate::daemon::fs_api::canonical_project_root(root)?;
    trusted_canonical_root(ctx, root).await
}

async fn trusted_canonical_root(
    ctx: &DaemonContext,
    root: PathBuf,
) -> Result<PathBuf, ErrorPayload> {
    let policy = crate::config::trust::resolve_workspace_trust_policy_from_db(&ctx.db, &root)
        .await
        .map_err(|error| ErrorPayload {
            code: ErrorCode::WorkspaceTrust,
            message: format!("workspace trust is required for agent management: {error:#}"),
        })?;
    if policy.mode != crate::db::workspace_trust::WorkspaceTrustMode::Trust {
        return Err(ErrorPayload {
            code: ErrorCode::WorkspaceTrust,
            message: "agent management requires a trusted workspace".into(),
        });
    }
    Ok(root)
}

fn inventory_sync(
    root: &Path,
    guard: &cockpit_config::config::HeldConfigMutationLock,
) -> Result<Response, ErrorPayload> {
    recover_reset_all_locked(root, guard)?;
    let entries = inventory_entries(root)?;
    let inventory_revision = inventory_revision(&entries);
    Ok(Response::AgentInventory {
        entries,
        inventory_revision,
        config_generation: crate::daemon::server::inventory::current_config_generation(),
    })
}

fn inventory_entries(root: &Path) -> Result<Vec<AgentInventoryEntry>, ErrorPayload> {
    let all = crate::agents::list_all(root);
    if all.len() > cockpit_proto::MAX_AGENT_INVENTORY_ENTRIES {
        return Err(bad_request(format!(
            "agent inventory exceeds the {}-entry local response limit; remove unused definitions",
            cockpit_proto::MAX_AGENT_INVENTORY_ENTRIES
        )));
    }
    all.into_iter()
        .map(|entry| {
            let source = source_snapshot_parts(root, &entry.name).or_else(|error| {
                let Some(path) = crate::agents::find_override(root, &entry.name) else {
                    return Err(error);
                };
                let metadata = std::fs::symlink_metadata(&path).map_err(internal)?;
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    return Err(error);
                }
                let target = project_agent_path(root, &entry.name)?;
                let layer = classify_source_layer(root, &path, &target);
                Ok((
                    layer,
                    opaque_source_identity(root, &path, layer, b"")?,
                    String::new(),
                    nofollow_read(&target)?.is_some(),
                ))
            });
            let (description, model, valid, diagnostic) = match entry.def {
                Ok(def) => (Some(def.description), def.model, true, None),
                Err(_) => (
                    None,
                    None,
                    false,
                    Some(
                        "agent definition is invalid; inspect it through the daemon editor".into(),
                    ),
                ),
            };
            if [
                description.as_deref(),
                model.as_deref(),
                diagnostic.as_deref(),
            ]
            .into_iter()
            .flatten()
            .any(|value| value.len() > cockpit_proto::MAX_AGENT_METADATA_BYTES)
            {
                return Err(bad_request(format!(
                    "agent `{}` metadata exceeds the safe local response bounds",
                    entry.name
                )));
            }
            let (source_layer, source_identity, markdown, target_exists) = source?;
            let revision = definition_revision(
                &entry.name,
                source_layer,
                &source_identity,
                &crate::assistants::markdown_content_hash(&markdown),
                target_exists,
            );
            Ok(AgentInventoryEntry {
                name: entry.name,
                kind: match entry.kind {
                    crate::agents::AgentKind::Builtin { .. } => AgentEntryKind::Builtin,
                    crate::agents::AgentKind::Custom => AgentEntryKind::Custom,
                },
                overridden: matches!(
                    entry.kind,
                    crate::agents::AgentKind::Builtin { overridden: true }
                ),
                description,
                model,
                valid,
                diagnostic,
                source_layer,
                source_identity: source_identity.to_string(),
                revision,
                editable: source_layer == AgentSourceLayer::Workspace && !markdown.is_empty(),
                projection_digest: String::new(),
            })
        })
        .collect()
}

fn snapshot_sync(root: &Path, name: &str) -> Result<AgentEditSnapshot, ErrorPayload> {
    validate_name(name)?;
    let def = crate::agents::resolve(root, name)
        .map_err(bad_config)?
        .ok_or_else(|| bad_request(format!("agent `{name}` was not found")))?;
    let canonical_preview = def.to_markdown().map_err(bad_config)?;
    if canonical_preview.len() > cockpit_proto::MAX_AGENT_MARKDOWN_BYTES {
        return Err(bad_request(format!(
            "canonical agent preview exceeds the {}-byte local editor limit",
            cockpit_proto::MAX_AGENT_MARKDOWN_BYTES
        )));
    }
    let (source_layer, source_identity, markdown, target_exists) =
        source_snapshot_parts(root, name)?;
    let revision = definition_revision(
        name,
        source_layer,
        &source_identity,
        &crate::assistants::markdown_content_hash(&markdown),
        target_exists,
    );
    let goal_supervision_json = (!def.goal_supervision.is_empty())
        .then(|| serde_json::to_string(&def.goal_supervision).map_err(bad_config))
        .transpose()?;
    if goal_supervision_json
        .as_ref()
        .is_some_and(|value| value.len() > cockpit_proto::MAX_AGENT_METADATA_BYTES)
    {
        return Err(bad_request(
            "agent goal supervision projection is too large",
        ));
    }
    Ok(AgentEditSnapshot {
        name: name.to_string(),
        kind: if crate::agents::is_builtin_agent(name) {
            AgentEntryKind::Builtin
        } else {
            AgentEntryKind::Custom
        },
        overridden: source_layer != AgentSourceLayer::Embedded,
        markdown: markdown.to_string(),
        canonical_preview,
        source_layer,
        source_identity: source_identity.to_string(),
        edit_target: AgentEditTarget::Workspace,
        revision,
        goal_supervision_json,
        editable: source_layer == AgentSourceLayer::Workspace,
        supports_goal_supervision: def.vnext.is_none(),
        projection_digest: String::new(),
    })
}

fn source_snapshot_parts(
    root: &Path,
    name: &str,
) -> Result<(AgentSourceLayer, String, String, bool), ErrorPayload> {
    let project_override = project_agent_path(root, name)?;
    let target_exists = nofollow_read(&project_override)?.is_some();
    match crate::agents::find_override(root, name) {
        Some(source) => {
            if std::fs::symlink_metadata(&source)
                .map_err(internal)?
                .file_type()
                .is_dir()
            {
                return Err(bad_request(
                    "directory-form agents are read-only in the settings editor",
                ));
            }
            let raw = nofollow_read(&source)?.ok_or_else(|| {
                conflict("agent source changed while the snapshot was being acquired")
            })?;
            if raw.len() > cockpit_proto::MAX_AGENT_MARKDOWN_BYTES {
                return Err(bad_request(format!(
                    "agent definition exceeds the {}-byte local editor limit",
                    cockpit_proto::MAX_AGENT_MARKDOWN_BYTES
                )));
            }
            let markdown = String::from_utf8(raw)
                .map_err(|_| bad_request("agent definition is not valid UTF-8"))?;
            let layer = classify_source_layer(root, &source, &project_override);
            let identity = opaque_source_identity(root, &source, layer, markdown.as_bytes())?;
            Ok((layer, identity, markdown, target_exists))
        }
        None => {
            let markdown = crate::agents::resolve(root, name)
                .map_err(bad_config)?
                .ok_or_else(|| bad_request(format!("agent `{name}` was not found")))?
                .to_markdown()
                .map_err(bad_config)?;
            if markdown.len() > cockpit_proto::MAX_AGENT_MARKDOWN_BYTES {
                return Err(bad_request(format!(
                    "embedded agent definition exceeds the {}-byte local editor limit",
                    cockpit_proto::MAX_AGENT_MARKDOWN_BYTES
                )));
            }
            let identity = embedded_source_identity(root, name, markdown.as_bytes());
            Ok((
                AgentSourceLayer::Embedded,
                identity,
                markdown,
                target_exists,
            ))
        }
    }
}

fn mutate_sync(
    root: &Path,
    mutation: AgentMutation,
    expected_revision: Option<String>,
) -> Result<Response, ErrorPayload> {
    let consumed_revision = expected_revision.clone();
    let lock_target = root.join(".cockpit/config.json");
    let guard =
        cockpit_config::config::hold_config_mutation_lock(&lock_target).map_err(internal)?;
    recover_reset_all_locked(root, &guard)?;
    let generation_before = crate::daemon::server::inventory::current_config_generation();
    let resets_inventory = matches!(&mutation, AgentMutation::ResetAllBuiltins);
    let (changed, affected, snapshot) = match mutation {
        AgentMutation::EjectBuiltin { name } => {
            validate_name(&name)?;
            if !crate::agents::is_builtin_agent(&name) {
                return Err(bad_request("only a built-in agent can be ejected"));
            }
            let before = snapshot_sync(root, &name)?;
            ensure_revision(&before.revision, expected_revision.as_deref())?;
            ensure_workspace_source_or_embedded(&before)?;
            let target = project_agent_path(root, &name)?;
            if nofollow_read(&target)?.is_some() {
                (false, 0, Some(snapshot_sync(root, &name)?))
            } else {
                let parent = target.parent().expect("agent path has parent");
                std::fs::create_dir_all(parent).map_err(internal)?;
                cockpit_config::config::write_config_bytes_atomic(
                    &target,
                    before.markdown.as_bytes(),
                )
                .map_err(internal)?;
                (true, 1, Some(snapshot_sync(root, &name)?))
            }
        }
        AgentMutation::SaveDefinition { name, markdown } => {
            validate_name(&name)?;
            let current = snapshot_sync(root, &name)?;
            ensure_revision(&current.revision, expected_revision.as_deref())?;
            if !matches!(
                current.source_layer,
                AgentSourceLayer::Workspace | AgentSourceLayer::Embedded
            ) {
                return Err(conflict(
                    "save refused: another configuration layer owns this agent",
                ));
            }
            let parsed =
                crate::agents::parse_agent(&markdown, &name, PathBuf::from("<daemon-agent-edit>"))
                    .map_err(bad_config)?;
            crate::agents::validate_invariants(&parsed).map_err(bad_config)?;
            let target = project_agent_path(root, &name)?;
            std::fs::create_dir_all(target.parent().expect("agent path has parent"))
                .map_err(internal)?;
            let old = nofollow_read(&target)?;
            if old.as_deref() == Some(markdown.as_bytes()) {
                (false, 0, Some(current))
            } else {
                cockpit_config::config::write_config_bytes_atomic(&target, markdown.as_bytes())
                    .map_err(internal)?;
                (true, 1, Some(snapshot_sync(root, &name)?))
            }
        }
        AgentMutation::CreateDefinition { name, markdown } => {
            validate_name(&name)?;
            if crate::agents::resolve(root, &name)
                .map_err(bad_config)?
                .is_some()
            {
                return Err(conflict(
                    "agent name already resolves in a configuration layer",
                ));
            }
            let target = project_agent_path(root, &name)?;
            if nofollow_read(&target)?.is_some() {
                return Err(conflict("workspace agent already exists"));
            }
            if expected_revision.is_some() {
                return Err(bad_request(
                    "create uses the daemon's authoritative absence check, not a document revision",
                ));
            }
            let parsed = crate::agents::parse_agent(
                &markdown,
                &name,
                PathBuf::from("<daemon-agent-create>"),
            )
            .map_err(bad_config)?;
            crate::agents::validate_invariants(&parsed).map_err(bad_config)?;
            std::fs::create_dir_all(target.parent().expect("agent path has parent"))
                .map_err(internal)?;
            cockpit_config::config::write_config_bytes_atomic(&target, markdown.as_bytes())
                .map_err(internal)?;
            (true, 1, Some(snapshot_sync(root, &name)?))
        }
        AgentMutation::DeleteCustom { name } => {
            validate_name(&name)?;
            if crate::agents::is_builtin_agent(&name) {
                return Err(bad_request("built-in agents cannot be deleted"));
            }
            let current = snapshot_sync(root, &name)?;
            ensure_revision(&current.revision, expected_revision.as_deref())?;
            if current.source_layer != AgentSourceLayer::Workspace {
                return Err(conflict("custom agent is not owned by the workspace layer"));
            }
            let target = project_agent_path(root, &name)?;
            if !target.is_file() {
                return Err(bad_request(
                    "custom agent is not owned by this workspace layer",
                ));
            }
            cockpit_config::config::remove_config_file_atomic(&target).map_err(internal)?;
            (true, 1, None)
        }
        AgentMutation::ResetBuiltin { name } => {
            validate_name(&name)?;
            if !crate::agents::is_builtin_agent(&name) {
                return Err(bad_request("only a built-in agent can be reset"));
            }
            let current = snapshot_sync(root, &name)?;
            ensure_revision(&current.revision, expected_revision.as_deref())?;
            if current.source_layer != AgentSourceLayer::Workspace {
                return Err(conflict(
                    "built-in override is not owned by the workspace layer",
                ));
            }
            let target = project_agent_path(root, &name)?;
            if target.is_file() {
                cockpit_config::config::remove_config_file_atomic(&target).map_err(internal)?;
                (true, 1, Some(snapshot_sync(root, &name)?))
            } else {
                (false, 0, Some(current))
            }
        }
        AgentMutation::ResetAllBuiltins => {
            let current_inventory_revision = current_inventory_revision(root)?;
            ensure_revision(&current_inventory_revision, expected_revision.as_deref())?;
            let affected = reset_all_builtins_atomic_locked(root, &guard)?;
            (affected != 0, affected, None)
        }
        AgentMutation::SaveGoalSupervision { name, patch } => {
            validate_name(&name)?;
            let current = snapshot_sync(root, &name)?;
            ensure_revision(&current.revision, expected_revision.as_deref())?;
            if !matches!(
                current.source_layer,
                AgentSourceLayer::Workspace | AgentSourceLayer::Embedded
            ) {
                return Err(conflict(
                    "goal settings cannot shadow an agent owned by another configuration layer",
                ));
            }
            let mut def = crate::agents::parse_agent(
                &current.markdown,
                &name,
                PathBuf::from("<daemon-agent-goal-settings>"),
            )
            .map_err(bad_config)?;
            if def.vnext.is_some() {
                return Err(bad_request(
                    "agent-scoped goal settings are unavailable for vNext agents",
                ));
            }
            if let Some(value) = patch.cold_skeptic_count {
                def.goal_supervision.cold_skeptic_count = value;
            }
            if let Some(value) = patch.cold_skeptic_model {
                def.goal_supervision.cold_skeptic_model = value;
            }
            if let Some(value) = patch.max_verification_attempts {
                def.goal_supervision.max_verification_attempts = value;
            }
            def.goal_supervision.validate().map_err(bad_config)?;
            crate::agents::validate_invariants(&def).map_err(bad_config)?;
            let markdown = def.to_markdown().map_err(bad_config)?;
            let target = project_agent_path(root, &name)?;
            std::fs::create_dir_all(target.parent().expect("agent path has parent"))
                .map_err(internal)?;
            if markdown.as_bytes() == current.markdown.as_bytes() {
                (false, 0, Some(current))
            } else {
                cockpit_config::config::write_config_bytes_atomic(&target, markdown.as_bytes())
                    .map_err(internal)?;
                (true, 1, Some(snapshot_sync(root, &name)?))
            }
        }
    };
    let generation = if changed {
        crate::daemon::server::inventory::publish_committed_config_generation()
    } else {
        generation_before
    };
    let (result_inventory_revision, outcome) = if resets_inventory {
        match current_inventory_revision(root) {
            Ok(revision) => (
                Some(revision),
                cockpit_proto::AgentMutationOutcome::Reconciled,
            ),
            Err(_) => (
                Some(crate::daemon::authority_token::mint(
                    b"agent-reset-commit-receipt/v1",
                    &[
                        root.as_os_str().as_encoded_bytes(),
                        consumed_revision.as_deref().unwrap_or_default().as_bytes(),
                        &affected.to_le_bytes(),
                        &generation.to_le_bytes(),
                    ],
                )),
                cockpit_proto::AgentMutationOutcome::CommittedRefreshNeeded {
                    warning: "built-in overrides were committed, but the refreshed agent inventory is unavailable; reopen Agents to refresh".into(),
                },
            ),
        }
    } else {
        (None, cockpit_proto::AgentMutationOutcome::Reconciled)
    };
    Ok(Response::AgentMutated(AgentMutationResult {
        changed,
        affected,
        snapshot,
        config_generation: generation,
        inventory_revision: result_inventory_revision,
        consumed_revision,
        completed_lease_id: None,
        outcome,
    }))
}

fn project_agent_path(root: &Path, name: &str) -> Result<PathBuf, ErrorPayload> {
    validate_name(name)?;
    let relative = format!(".cockpit/agents/{name}.md");
    crate::daemon::fs_api::resolve_authorized_canonical_path(
        root.to_string_lossy().as_ref(),
        &relative,
        crate::daemon::fs_api::AuthorizedCanonicalPathMode::WriteTarget,
    )
}

fn validate_name(name: &str) -> Result<(), ErrorPayload> {
    if name.is_empty()
        || name.len() > cockpit_proto::MAX_AGENT_NAME_BYTES
        || name == "."
        || name == ".."
        || name.contains('/')
        || name.contains('\\')
        || name.contains('\0')
    {
        return Err(bad_request("agent name is invalid"));
    }
    Ok(())
}

fn nofollow_read(path: &Path) -> Result<Option<Vec<u8>>, ErrorPayload> {
    cockpit_config::config::read_config_file_nofollow(path).map_err(internal)
}

fn classify_source_layer(root: &Path, source: &Path, target: &Path) -> AgentSourceLayer {
    if source == target {
        return AgentSourceLayer::Workspace;
    }
    // Flat definitions are owned by their exact parent directory. Prefix
    // matching misclassified nested configured directories according to the
    // first broader layer rather than the effective, most-specific owner.
    let Some(owner) = source.parent() else {
        return AgentSourceLayer::OtherConfigLayer;
    };
    let ordinary: std::collections::HashSet<PathBuf> =
        crate::config::dirs::discover_config_dirs(root)
            .into_iter()
            .map(|dir| dir.path.join("agents"))
            .collect();
    if ordinary.contains(owner) {
        AgentSourceLayer::OtherConfigLayer
    } else if crate::agents::agent_search_dirs(root)
        .into_iter()
        .any(|dir| dir == owner)
    {
        AgentSourceLayer::ConfiguredDirectory
    } else {
        AgentSourceLayer::OtherConfigLayer
    }
}

fn ensure_workspace_source_or_embedded(snapshot: &AgentEditSnapshot) -> Result<(), ErrorPayload> {
    if matches!(
        snapshot.source_layer,
        AgentSourceLayer::Workspace | AgentSourceLayer::Embedded
    ) {
        Ok(())
    } else {
        Err(conflict(
            "eject refused: another configuration layer already owns this override",
        ))
    }
}

fn embedded_source_identity(root: &Path, name: &str, content: &[u8]) -> String {
    crate::daemon::authority_token::mint(
        b"agent-source/embedded/v1",
        &[
            root.as_os_str().as_encoded_bytes(),
            name.as_bytes(),
            content,
        ],
    )
}

fn opaque_source_identity(
    root: &Path,
    source: &Path,
    layer: AgentSourceLayer,
    content: &[u8],
) -> Result<String, ErrorPayload> {
    let metadata = std::fs::symlink_metadata(source).map_err(internal)?;
    if metadata.file_type().is_symlink() {
        return Err(conflict(
            "agent source became a symlink while minting its identity",
        ));
    }
    let layer = [layer as u8];
    let length = metadata.len().to_le_bytes();
    let mut platform_identity = Vec::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        platform_identity.extend_from_slice(&metadata.dev().to_le_bytes());
        platform_identity.extend_from_slice(&metadata.ino().to_le_bytes());
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;
        platform_identity.extend_from_slice(&metadata.file_attributes().to_le_bytes());
        platform_identity.extend_from_slice(&metadata.creation_time().to_le_bytes());
        platform_identity.extend_from_slice(&metadata.last_write_time().to_le_bytes());
    }
    Ok(crate::daemon::authority_token::mint(
        b"agent-source/file/v1",
        &[
            &layer,
            root.as_os_str().as_encoded_bytes(),
            source.as_os_str().as_encoded_bytes(),
            content,
            &length,
            &platform_identity,
        ],
    ))
}

fn current_inventory_revision(root: &Path) -> Result<String, ErrorPayload> {
    Ok(inventory_revision(&inventory_entries(root)?))
}

fn definition_revision(
    name: &str,
    source_layer: AgentSourceLayer,
    source_identity: &str,
    source_content_hash: &str,
    target_exists: bool,
) -> String {
    let layer = [source_layer as u8];
    let exists = [u8::from(target_exists)];
    crate::daemon::authority_token::mint(
        b"agent-definition-revision/v1",
        &[
            name.as_bytes(),
            &layer,
            source_identity.as_bytes(),
            source_content_hash.as_bytes(),
            &exists,
        ],
    )
}

fn inventory_revision(entries: &[AgentInventoryEntry]) -> String {
    let mut ordered = entries.iter().collect::<Vec<_>>();
    ordered.sort_by(|left, right| left.name.cmp(&right.name));
    let mut canonical = Vec::new();
    for entry in ordered {
        for value in [&entry.name, &entry.source_identity, &entry.revision] {
            canonical.extend_from_slice(&(value.len() as u64).to_le_bytes());
            canonical.extend_from_slice(value.as_bytes());
        }
        canonical.extend_from_slice(&[
            entry.kind as u8,
            u8::from(entry.overridden),
            u8::from(entry.editable),
        ]);
    }
    crate::daemon::authority_token::mint(b"agent-inventory-revision/v1", &[&canonical])
}

#[derive(serde::Serialize, serde::Deserialize)]
struct ResetAllJournal {
    operation_id: String,
    #[serde(default = "prepared_reset_phase")]
    phase: ResetAllPhase,
    /// Validated built-in agent names only. Paths and staging names are always
    /// derived by the daemon after parsing the journal.
    entries: Vec<String>,
}

#[derive(Clone, Copy, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum ResetAllPhase {
    Prepared,
    Committed,
}

fn prepared_reset_phase() -> ResetAllPhase {
    ResetAllPhase::Prepared
}

fn reset_journal_path(root: &Path) -> PathBuf {
    root.join(".cockpit/agent-reset-all.journal.json")
}

fn validated_reset_journal(
    root: &Path,
    raw: &[u8],
) -> Result<(ResetAllJournal, PathBuf), ErrorPayload> {
    let journal: ResetAllJournal = serde_json::from_slice(raw).map_err(bad_config)?;
    let operation_id = Uuid::parse_str(&journal.operation_id)
        .map_err(|_| bad_request("agent reset journal has an invalid operation ID"))?;
    if operation_id.to_string() != journal.operation_id {
        return Err(bad_request(
            "agent reset journal operation ID is not canonical",
        ));
    }
    let mut seen = std::collections::HashSet::new();
    for name in &journal.entries {
        validate_name(name)?;
        if !crate::agents::is_builtin_agent(name) || !seen.insert(name.clone()) {
            return Err(bad_request("agent reset journal contains an invalid entry"));
        }
    }
    let trash_root = root.join(".cockpit/.agent-reset-trash");
    if std::fs::symlink_metadata(&trash_root)
        .is_ok_and(|metadata| metadata.file_type().is_symlink())
    {
        return Err(bad_request("agent reset trash root is a symlink"));
    }
    let trash = trash_root.join(operation_id.to_string());
    // Reject substituted staging directories. We never recurse through this
    // path; each expected leaf is derived from a validated agent name.
    if std::fs::symlink_metadata(&trash).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
        return Err(bad_request("agent reset staging directory is a symlink"));
    }
    Ok((journal, trash))
}

fn staged_agent_path(trash: &Path, name: &str) -> Result<PathBuf, ErrorPayload> {
    validate_name(name)?;
    Ok(trash.join(format!("{name}.md")))
}

fn sync_dir(path: &Path) -> Result<(), ErrorPayload> {
    cockpit_config::config::sync_directory_nofollow(path).map_err(internal)
}

/// Recover an interrupted reset conservatively by restoring every staged
/// override. A reset is externally committed only after every rename lands
/// and the journal is removed, so boot/request recovery never exposes a
/// silently partial reset as success.
fn recover_reset_all_locked(
    root: &Path,
    guard: &cockpit_config::config::HeldConfigMutationLock,
) -> Result<(), ErrorPayload> {
    let journal_path = reset_journal_path(root);
    let Some(raw) = nofollow_read(&journal_path)? else {
        return Ok(());
    };
    let (journal, trash) = validated_reset_journal(root, &raw)?;
    let agents_dir = root.join(".cockpit/agents");
    match journal.phase {
        ResetAllPhase::Prepared => {
            for name in journal.entries.iter().rev() {
                let target = project_agent_path(root, name)?;
                let staged = staged_agent_path(&trash, name)?;
                let staged_exists = nofollow_read(&staged)?.is_some();
                let target_exists = nofollow_read(&target)?.is_some();
                match (staged_exists, target_exists) {
                    (true, false) => rename_config_noreplace(guard, &staged, &target)?,
                    // This entry was not staged yet, or an earlier recovery
                    // pass already restored it.
                    (false, true) => {}
                    (true, true) => {
                        if cockpit_config::config::same_config_file_identity_nofollow(
                            &staged, &target,
                        )
                        .map_err(internal)?
                        {
                            // Portable link/unlink no-replace can durably
                            // publish the second name before unlinking the
                            // first. Prepared recovery treats identical names
                            // as a recoverable rollback state and retains the
                            // authoritative target.
                            cockpit_config::config::remove_config_file_atomic(&staged)
                                .map_err(internal)?;
                        } else {
                            return Err(conflict(
                                "agent reset rollback found different staged and authoritative files",
                            ));
                        }
                    }
                    (false, false) => {
                        return Err(conflict(
                            "agent reset rollback found neither staged nor authoritative file",
                        ));
                    }
                }
            }
            if agents_dir.is_dir() {
                sync_dir(&agents_dir)?;
            }
            if trash.is_dir() {
                sync_dir(&trash)?;
            }
        }
        ResetAllPhase::Committed => {
            for name in &journal.entries {
                let staged = staged_agent_path(&trash, name)?;
                let target = project_agent_path(root, name)?;
                let staged_exists = nofollow_read(&staged)?.is_some();
                let target_exists = nofollow_read(&target)?.is_some();
                match (staged_exists, target_exists) {
                    (true, false) => cockpit_config::config::remove_config_file_atomic(&staged)
                        .map_err(internal)?,
                    // A previous committed recovery already deleted it.
                    (false, false) => {}
                    // Once committed, an authoritative target is unexpected;
                    // never bless or delete it because it may be newer data.
                    (_, true) => {
                        return Err(conflict(
                            "committed agent reset found an unexpected authoritative file",
                        ));
                    }
                }
            }
            if trash.is_dir() {
                sync_dir(&trash)?;
            }
        }
    }
    cockpit_config::config::remove_config_file_atomic(&journal_path).map_err(internal)?;
    sync_dir(journal_path.parent().expect("journal has parent"))?;
    if trash.is_dir() {
        std::fs::remove_dir(&trash).map_err(internal)?;
        sync_dir(trash.parent().expect("trash operation has parent"))?;
    }
    Ok(())
}

pub async fn recover_known_workspace_resets(ctx: &DaemonContext) -> Result<(), ErrorPayload> {
    let sessions = ctx
        .db
        .list_sessions(false, 100_000)
        .await
        .map_err(internal)?;
    let mut roots = std::collections::BTreeSet::new();
    roots.extend(sessions.into_iter().map(|session| session.project_root));
    let mut trusted_roots = Vec::new();
    for root in roots {
        let historical = PathBuf::from(&root);
        match std::fs::symlink_metadata(reset_journal_path(&historical)) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(internal(error)),
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(bad_request("historical agent reset journal is a symlink"));
            }
            Ok(_) => {}
        }
        let root = crate::daemon::fs_api::canonical_project_root(&root)?;
        let policy = crate::config::trust::resolve_workspace_trust_policy_from_db(&ctx.db, &root)
            .await
            .map_err(internal)?;
        if policy.mode != crate::db::workspace_trust::WorkspaceTrustMode::Trust {
            return Err(ErrorPayload {
                code: ErrorCode::WorkspaceTrust,
                message: format!(
                    "refusing agent reset recovery for untrusted historical root {}",
                    root.display()
                ),
            });
        }
        trusted_roots.push(root);
    }
    tokio::task::spawn_blocking(move || {
        for root in trusted_roots {
            let lock_target = root.join(".cockpit/config.json");
            let guard = cockpit_config::config::hold_config_mutation_lock(&lock_target)
                .map_err(internal)?;
            recover_reset_all_locked(&root, &guard)?;
        }
        Ok(())
    })
    .await
    .map_err(join_error)?
}

fn reset_all_builtins_atomic_locked(
    root: &Path,
    guard: &cockpit_config::config::HeldConfigMutationLock,
) -> Result<u32, ErrorPayload> {
    recover_reset_all_locked(root, guard)?;
    let operation_id = Uuid::new_v4();
    let trash = root
        .join(".cockpit/.agent-reset-trash")
        .join(operation_id.to_string());
    let mut entries = Vec::new();
    for name in crate::agents::BUILTIN_AGENT_NAMES {
        let target = project_agent_path(root, name)?;
        if nofollow_read(&target)?.is_some() {
            entries.push((*name).to_string());
        }
    }
    if entries.is_empty() {
        return Ok(0);
    }
    let trash_root = trash.parent().expect("trash has parent");
    crate::private_fs::ensure_private_dir(trash_root).map_err(internal)?;
    #[cfg(unix)]
    let _trash_root_handle =
        crate::private_fs::open_private_dir_handle(trash_root).map_err(internal)?;
    crate::private_fs::ensure_private_dir(&trash).map_err(internal)?;
    #[cfg(unix)]
    let _trash_handle = crate::private_fs::open_private_dir_handle(&trash).map_err(internal)?;
    // The prepared journal may refer to this staging directory immediately
    // after publication, so persist both the directory itself and its parent
    // first. Recovery must never observe a durable journal naming a directory
    // that existed only in volatile metadata.
    sync_dir(&trash)?;
    sync_dir(trash_root)?;
    let journal = ResetAllJournal {
        operation_id: operation_id.to_string(),
        phase: ResetAllPhase::Prepared,
        entries,
    };
    let encoded = serde_json::to_vec_pretty(&journal).map_err(internal)?;
    cockpit_config::config::write_config_bytes_atomic(&reset_journal_path(root), &encoded)
        .map_err(internal)?;

    let agents_dir = root.join(".cockpit/agents");
    for name in &journal.entries {
        let source = project_agent_path(root, name)?;
        let staged = staged_agent_path(&trash, name)?;
        if let Err(error) = rename_config_noreplace(guard, &source, &staged) {
            // The durable journal makes rollback retryable if this immediate
            // recovery itself encounters an I/O failure.
            let _ = recover_reset_all_locked(root, guard);
            return Err(error);
        }
    }
    sync_dir(&agents_dir)?;
    sync_dir(&trash)?;
    // The committed marker is the linearization point. Recovery before it
    // restores staged files; recovery after it finishes deletion.
    let committed = ResetAllJournal {
        phase: ResetAllPhase::Committed,
        ..journal
    };
    let encoded = serde_json::to_vec_pretty(&committed).map_err(internal)?;
    cockpit_config::config::write_config_bytes_atomic(&reset_journal_path(root), &encoded)
        .map_err(internal)?;
    recover_reset_all_locked(root, guard)?;
    Ok(committed.entries.len() as u32)
}

fn ensure_revision(current: &str, expected: Option<&str>) -> Result<(), ErrorPayload> {
    match expected {
        Some(expected) if expected == current => Ok(()),
        Some(_) => Err(conflict("agent changed since the snapshot was read")),
        None => Err(conflict("agent mutation requires an expected revision")),
    }
}

fn rename_config_noreplace(
    guard: &cockpit_config::config::HeldConfigMutationLock,
    source: &Path,
    destination: &Path,
) -> Result<(), ErrorPayload> {
    cockpit_config::config::rename_config_file_nofollow(guard, source, destination).map_err(
        |error| {
            let destination_exists = error.chain().any(|cause| {
                cause
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|io| io.kind() == std::io::ErrorKind::AlreadyExists)
            });
            if destination_exists {
                conflict(format!(
                    "agent reset destination already exists: {}",
                    destination.display()
                ))
            } else {
                internal(error)
            }
        },
    )
}

fn bad_request(message: impl Into<String>) -> ErrorPayload {
    ErrorPayload {
        code: ErrorCode::BadRequest,
        message: message.into(),
    }
}

pub(crate) fn conflict(message: impl Into<String>) -> ErrorPayload {
    ErrorPayload {
        code: ErrorCode::Conflict,
        message: message.into(),
    }
}

fn bad_config(error: impl std::fmt::Display) -> ErrorPayload {
    bad_request(format!("invalid agent definition: {error}"))
}

fn internal(error: impl std::fmt::Display) -> ErrorPayload {
    ErrorPayload {
        code: ErrorCode::Internal,
        message: format!("agent management failed: {error}"),
    }
}

fn join_error(error: tokio::task::JoinError) -> ErrorPayload {
    internal(format!("agent management worker failed: {error}"))
}
