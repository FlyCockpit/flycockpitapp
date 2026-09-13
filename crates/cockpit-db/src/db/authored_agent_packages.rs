//! Durable authored-package apply journals and draft CAS.

use anyhow::{Context, Result, bail, ensure};
use rusqlite::{OptionalExtension, params};

use super::Db;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthoredAgentPackageJournalRow {
    pub owner_digest: String,
    pub client_operation_id: String,
    pub request_hash: Vec<u8>,
    pub fencing_generation: i64,
    pub policy_revision: String,
    pub package_digest: String,
    pub draft_revision: String,
    pub installation_id: Option<String>,
    pub default_selected: bool,
    pub onboarding_run_id: Option<String>,
    pub onboarding_attempt_id: Option<String>,
    pub onboarding_stage_revision: Option<i64>,
    pub terminal_response_json: String,
    pub created_at_unix_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthoredAgentPackageDraftRow {
    pub agent_name: String,
    pub draft_revision: String,
    pub package_digest: String,
    pub updated_at_unix_ms: i64,
}

impl Db {
    pub async fn authored_agent_package_journal(
        &self,
        owner_digest: String,
        client_operation_id: String,
    ) -> Result<Option<AuthoredAgentPackageJournalRow>> {
        self.read(move |conn| {
            conn.query_row(
                "SELECT owner_digest,client_operation_id,request_hash,fencing_generation,policy_revision,package_digest,draft_revision,installation_id,default_selected,onboarding_run_id,onboarding_attempt_id,onboarding_stage_revision,terminal_response_json,created_at_unix_ms
                 FROM authored_agent_package_journals WHERE owner_digest=?1 AND client_operation_id=?2",
                params![owner_digest, client_operation_id],
                decode_journal,
            )
            .optional()
            .context("loading authored agent package journal")
        })
        .await
    }

    pub async fn list_authored_agent_package_journals(
        &self,
    ) -> Result<Vec<AuthoredAgentPackageJournalRow>> {
        self.read(|conn| {
            let mut statement = conn.prepare(
                "SELECT owner_digest,client_operation_id,request_hash,fencing_generation,policy_revision,package_digest,draft_revision,installation_id,default_selected,onboarding_run_id,onboarding_attempt_id,onboarding_stage_revision,terminal_response_json,created_at_unix_ms
                 FROM authored_agent_package_journals ORDER BY created_at_unix_ms",
            )?;
            let rows = statement
                .query_map([], decode_journal)?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
        .await
    }

    pub async fn record_authored_agent_package_journal(
        &self,
        row: AuthoredAgentPackageJournalRow,
    ) -> Result<()> {
        self.write(move |conn| {
            ensure!(
                row.request_hash.len() == 32,
                "authored package journal request hash must be 32 bytes"
            );
            let changed = conn.execute(
                "INSERT INTO authored_agent_package_journals(
                    owner_digest,client_operation_id,request_hash,fencing_generation,policy_revision,package_digest,draft_revision,installation_id,default_selected,onboarding_run_id,onboarding_attempt_id,onboarding_stage_revision,terminal_response_json,created_at_unix_ms
                 ) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)
                 ON CONFLICT(owner_digest,client_operation_id) DO UPDATE SET
                    terminal_response_json=excluded.terminal_response_json
                 WHERE authored_agent_package_journals.request_hash=excluded.request_hash
                   AND authored_agent_package_journals.fencing_generation=excluded.fencing_generation
                   AND authored_agent_package_journals.policy_revision=excluded.policy_revision
                   AND authored_agent_package_journals.package_digest=excluded.package_digest
                   AND authored_agent_package_journals.draft_revision=excluded.draft_revision",
                params![
                    row.owner_digest,
                    row.client_operation_id,
                    row.request_hash,
                    row.fencing_generation,
                    row.policy_revision,
                    row.package_digest,
                    row.draft_revision,
                    row.installation_id,
                    i64::from(row.default_selected),
                    row.onboarding_run_id,
                    row.onboarding_attempt_id,
                    row.onboarding_stage_revision,
                    row.terminal_response_json,
                    row.created_at_unix_ms,
                ],
            )?;
            ensure!(
                changed == 1,
                "authored package journal identity does not match the original request"
            );
            Ok(())
        })
        .await
    }

    pub async fn authored_agent_package_draft(
        &self,
        agent_name: String,
    ) -> Result<Option<AuthoredAgentPackageDraftRow>> {
        self.read(move |conn| {
            conn.query_row(
                "SELECT agent_name,draft_revision,package_digest,updated_at_unix_ms FROM authored_agent_package_drafts WHERE agent_name=?1",
                params![agent_name],
                |row| {
                    Ok(AuthoredAgentPackageDraftRow {
                        agent_name: row.get(0)?,
                        draft_revision: row.get(1)?,
                        package_digest: row.get(2)?,
                        updated_at_unix_ms: row.get(3)?,
                    })
                },
            )
            .optional()
            .context("loading authored agent package draft")
        })
        .await
    }

    /// Commit a new authoritative draft revision. `expected_revision` is
    /// `None` only for the first submit of a name; a mismatch fails closed
    /// without changing the stored draft.
    pub async fn cas_authored_agent_package_draft(
        &self,
        agent_name: String,
        expected_revision: Option<String>,
        new_revision: String,
        package_digest: String,
        now_unix_ms: i64,
    ) -> Result<bool> {
        self.transaction(move |conn| {
            ensure!(
                !agent_name.is_empty() && !new_revision.is_empty() && package_digest.len() == 64,
                "authored draft CAS identity is invalid"
            );
            let current: Option<String> = conn
                .query_row(
                    "SELECT draft_revision FROM authored_agent_package_drafts WHERE agent_name=?1",
                    params![agent_name],
                    |row| row.get(0),
                )
                .optional()?;
            match (expected_revision.as_deref(), current.as_deref()) {
                (None, Some(_)) | (Some(_), None) => return Ok(false),
                (None, None) => {
                    conn.execute(
                        "INSERT INTO authored_agent_package_drafts(agent_name,draft_revision,package_digest,updated_at_unix_ms) VALUES(?1,?2,?3,?4)",
                        params![agent_name, new_revision, package_digest, now_unix_ms],
                    )?;
                    Ok(true)
                }
                (Some(expected), Some(actual)) if expected == actual => {
                    if actual == new_revision {
                        return Ok(true);
                    }
                    let changed = conn.execute(
                        "UPDATE authored_agent_package_drafts SET draft_revision=?2,package_digest=?3,updated_at_unix_ms=?4 WHERE agent_name=?1 AND draft_revision=?5",
                        params![agent_name, new_revision, package_digest, now_unix_ms, expected],
                    )?;
                    if changed != 1 {
                        bail!("authored draft revision was fenced during CAS");
                    }
                    Ok(true)
                }
                (Some(_), Some(_)) => Ok(false),
            }
        })
        .await
    }
}

fn decode_journal(row: &rusqlite::Row<'_>) -> rusqlite::Result<AuthoredAgentPackageJournalRow> {
    Ok(AuthoredAgentPackageJournalRow {
        owner_digest: row.get(0)?,
        client_operation_id: row.get(1)?,
        request_hash: row.get(2)?,
        fencing_generation: row.get(3)?,
        policy_revision: row.get(4)?,
        package_digest: row.get(5)?,
        draft_revision: row.get(6)?,
        installation_id: row.get(7)?,
        default_selected: row.get::<_, i64>(8)? != 0,
        onboarding_run_id: row.get(9)?,
        onboarding_attempt_id: row.get(10)?,
        onboarding_stage_revision: row.get(11)?,
        terminal_response_json: row.get(12)?,
        created_at_unix_ms: row.get(13)?,
    })
}
