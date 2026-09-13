//! Durable authored-package apply journals and draft CAS.
//!
//! Intent is inserted before any recoverable publication effect. The terminal
//! receipt is attached only after installation, sidecar publication, default
//! selection, and draft CAS have completed.

use anyhow::{Context, Result, bail, ensure};
use rusqlite::{OptionalExtension, params};

use super::Db;

pub const AUTHORED_PACKAGE_SETTLEMENT_PENDING: &str = "publication_pending";
pub const AUTHORED_PACKAGE_SETTLEMENT_TERMINAL: &str = "terminal";

/// Canonical whole-tree agent package cap, in raw file bytes. Must stay equal
/// to `cockpit_core::agents::MAX_PACKAGE_BYTES`.
pub const MAX_CANONICAL_AGENT_PACKAGE_BYTES: usize = 4 * 1024 * 1024;
/// JSON object wrapping and relative-path keys around hex-encoded file bytes.
pub const MAX_AUTHORED_PACKAGE_FILES_JSON_WRAP_BYTES: usize = 2 * 1024 * 1024;
/// Durable hex-encoded package-file map. Hex doubles canonical package bytes;
/// the wrap budget covers JSON syntax and closed-namespace relative paths.
pub const MAX_AUTHORED_PACKAGE_FILES_JSON_BYTES: usize = MAX_CANONICAL_AGENT_PACKAGE_BYTES
    .saturating_mul(2)
    .saturating_add(MAX_AUTHORED_PACKAGE_FILES_JSON_WRAP_BYTES);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthoredAgentPackageJournalRow {
    pub owner_digest: String,
    pub client_operation_id: String,
    pub request_hash: Vec<u8>,
    pub fencing_generation: i64,
    pub policy_revision: String,
    pub package_digest: String,
    pub draft_revision: String,
    pub expected_draft_revision: Option<String>,
    pub agent_name: String,
    pub source_locator: String,
    pub source_pin: Option<String>,
    pub require_third_party: bool,
    pub third_party_trust_confirmed: bool,
    pub make_default: bool,
    pub sidecar_intent_json: String,
    pub package_files_json: String,
    pub review_json: String,
    pub installation_id: Option<String>,
    pub default_selected: bool,
    pub onboarding_run_id: Option<String>,
    pub onboarding_attempt_id: Option<String>,
    pub onboarding_stage_revision: Option<i64>,
    pub settlement_phase: String,
    pub terminal_response_json: Option<String>,
    pub created_at_unix_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthoredAgentPackageDraftRow {
    pub agent_name: String,
    pub draft_revision: String,
    pub package_digest: String,
    pub updated_at_unix_ms: i64,
}

const JOURNAL_COLUMNS: &str = "owner_digest,client_operation_id,request_hash,fencing_generation,policy_revision,package_digest,draft_revision,expected_draft_revision,agent_name,source_locator,source_pin,require_third_party,third_party_trust_confirmed,make_default,sidecar_intent_json,package_files_json,review_json,installation_id,default_selected,onboarding_run_id,onboarding_attempt_id,onboarding_stage_revision,settlement_phase,terminal_response_json,created_at_unix_ms";

impl Db {
    pub async fn authored_agent_package_journal(
        &self,
        owner_digest: String,
        client_operation_id: String,
    ) -> Result<Option<AuthoredAgentPackageJournalRow>> {
        self.read(move |conn| {
            conn.query_row(
                &format!(
                    "SELECT {JOURNAL_COLUMNS}
                     FROM authored_agent_package_journals WHERE owner_digest=?1 AND client_operation_id=?2"
                ),
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
            let mut statement = conn.prepare(&format!(
                "SELECT {JOURNAL_COLUMNS}
                 FROM authored_agent_package_journals ORDER BY created_at_unix_ms"
            ))?;
            let rows = statement
                .query_map([], decode_journal)?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
        .await
    }

    /// Persist publication intent. Callers must invoke this before any
    /// installation, sidecar, default-selection, or draft-CAS effect.
    pub async fn begin_authored_agent_package_journal(
        &self,
        row: AuthoredAgentPackageJournalRow,
    ) -> Result<AuthoredAgentPackageJournalRow> {
        self.write(move |conn| {
            ensure!(
                row.request_hash.len() == 32,
                "authored package journal request hash must be 32 bytes"
            );
            ensure!(
                row.settlement_phase == AUTHORED_PACKAGE_SETTLEMENT_PENDING,
                "authored package intent must start publication_pending"
            );
            ensure!(
                row.terminal_response_json.is_none() && row.installation_id.is_none(),
                "authored package intent must not carry a terminal receipt"
            );
            ensure!(
                json_valid_len(&row.package_files_json, MAX_AUTHORED_PACKAGE_FILES_JSON_BYTES),
                "authored package files JSON exceeds the durable intent limit"
            );
            let intended = row.clone();
            let changed = conn.execute(
                "INSERT INTO authored_agent_package_journals(
                    owner_digest,client_operation_id,request_hash,fencing_generation,policy_revision,package_digest,draft_revision,expected_draft_revision,agent_name,source_locator,source_pin,require_third_party,third_party_trust_confirmed,make_default,sidecar_intent_json,package_files_json,review_json,installation_id,default_selected,onboarding_run_id,onboarding_attempt_id,onboarding_stage_revision,settlement_phase,terminal_response_json,created_at_unix_ms
                 ) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22,?23,?24,?25)
                 ON CONFLICT(owner_digest,client_operation_id) DO NOTHING",
                params![
                    row.owner_digest,
                    row.client_operation_id,
                    row.request_hash,
                    row.fencing_generation,
                    row.policy_revision,
                    row.package_digest,
                    row.draft_revision,
                    row.expected_draft_revision,
                    row.agent_name,
                    row.source_locator,
                    row.source_pin,
                    i64::from(row.require_third_party),
                    i64::from(row.third_party_trust_confirmed),
                    i64::from(row.make_default),
                    row.sidecar_intent_json,
                    row.package_files_json,
                    row.review_json,
                    row.installation_id,
                    i64::from(row.default_selected),
                    row.onboarding_run_id,
                    row.onboarding_attempt_id,
                    row.onboarding_stage_revision,
                    row.settlement_phase,
                    row.terminal_response_json,
                    row.created_at_unix_ms,
                ],
            )?;
            let stored = conn
                .query_row(
                    &format!(
                        "SELECT {JOURNAL_COLUMNS}
                         FROM authored_agent_package_journals WHERE owner_digest=?1 AND client_operation_id=?2"
                    ),
                    params![intended.owner_digest, intended.client_operation_id],
                    decode_journal,
                )
                .context("loading authored package journal after intent insert")?;
            if changed == 0 {
                ensure!(
                    stored.request_hash == intended.request_hash
                        && stored.fencing_generation == intended.fencing_generation
                        && stored.policy_revision == intended.policy_revision
                        && stored.package_digest == intended.package_digest
                        && stored.draft_revision == intended.draft_revision
                        && stored.expected_draft_revision == intended.expected_draft_revision
                        && stored.agent_name == intended.agent_name
                        && stored.source_locator == intended.source_locator
                        && stored.source_pin == intended.source_pin
                        && stored.require_third_party == intended.require_third_party
                        && stored.third_party_trust_confirmed
                            == intended.third_party_trust_confirmed
                        && stored.make_default == intended.make_default
                        && stored.sidecar_intent_json == intended.sidecar_intent_json
                        && stored.package_files_json == intended.package_files_json
                        && stored.review_json == intended.review_json
                        && stored.default_selected == intended.default_selected
                        && stored.onboarding_run_id == intended.onboarding_run_id
                        && stored.onboarding_attempt_id == intended.onboarding_attempt_id
                        && stored.onboarding_stage_revision == intended.onboarding_stage_revision,
                    "authored package journal identity does not match the original request"
                );
            }
            Ok(stored)
        })
        .await
    }

    pub async fn finish_authored_agent_package_journal(
        &self,
        owner_digest: String,
        client_operation_id: String,
        installation_id: Option<String>,
        terminal_response_json: String,
    ) -> Result<()> {
        self.write(move |conn| {
            ensure!(
                json_valid_len(&terminal_response_json, 1_048_576),
                "authored package terminal receipt is not valid JSON"
            );
            let existing: Option<(Option<String>, String, Option<String>)> = conn
                .query_row(
                    "SELECT installation_id,settlement_phase,terminal_response_json
                     FROM authored_agent_package_journals
                     WHERE owner_digest=?1 AND client_operation_id=?2",
                    params![owner_digest, client_operation_id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()?;
            let Some((current_install, phase, current_terminal)) = existing else {
                bail!("authored package journal disappeared before terminal settlement");
            };
            if phase == AUTHORED_PACKAGE_SETTLEMENT_TERMINAL {
                ensure!(
                    current_terminal.as_deref() == Some(terminal_response_json.as_str())
                        && current_install == installation_id,
                    "authored package journal terminal receipt does not match"
                );
                return Ok(());
            }
            let changed = conn.execute(
                "UPDATE authored_agent_package_journals
                 SET installation_id=?3,settlement_phase=?4,terminal_response_json=?5
                 WHERE owner_digest=?1 AND client_operation_id=?2 AND settlement_phase=?6",
                params![
                    owner_digest,
                    client_operation_id,
                    installation_id,
                    AUTHORED_PACKAGE_SETTLEMENT_TERMINAL,
                    terminal_response_json,
                    AUTHORED_PACKAGE_SETTLEMENT_PENDING,
                ],
            )?;
            ensure!(
                changed == 1,
                "authored package journal lost its publication_pending claim"
            );
            Ok(())
        })
        .await
    }

    pub async fn delete_authored_agent_package_journals_by_client_operation(
        &self,
        client_operation_id: String,
    ) -> Result<u64> {
        self.write(move |conn| {
            Ok(conn.execute(
                "DELETE FROM authored_agent_package_journals WHERE client_operation_id=?1",
                params![client_operation_id],
            )? as u64)
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

fn json_valid_len(value: &str, max_bytes: usize) -> bool {
    value.len() <= max_bytes && serde_json::from_str::<serde_json::Value>(value).is_ok()
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
        expected_draft_revision: row.get(7)?,
        agent_name: row.get(8)?,
        source_locator: row.get(9)?,
        source_pin: row.get(10)?,
        require_third_party: row.get::<_, i64>(11)? != 0,
        third_party_trust_confirmed: row.get::<_, i64>(12)? != 0,
        make_default: row.get::<_, i64>(13)? != 0,
        sidecar_intent_json: row.get(14)?,
        package_files_json: row.get(15)?,
        review_json: row.get(16)?,
        installation_id: row.get(17)?,
        default_selected: row.get::<_, i64>(18)? != 0,
        onboarding_run_id: row.get(19)?,
        onboarding_attempt_id: row.get(20)?,
        onboarding_stage_revision: row.get(21)?,
        settlement_phase: row.get(22)?,
        terminal_response_json: row.get(23)?,
        created_at_unix_ms: row.get(24)?,
    })
}
