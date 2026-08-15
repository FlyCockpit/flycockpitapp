//! Validation and store helpers for session sealed values.
//! Child-environment injection of sealed literals is retired.

use std::fmt;

use anyhow::{Context, Result};

use super::Session;

/// A legacy `sealed_values` row to upsert inside the sealed-adoption
/// transaction (F7), so the sealed row, the redaction-table union, and the
/// protected-history journal append are one atomic unit.
pub(crate) struct LegacySealedUpsert {
    pub value_id: String,
    pub value: String,
    pub reason: String,
    pub origin: String,
}

pub const MIN_SEALED_VALUE_LENGTH: usize = 12;
const REJECTED_LITERALS: &[&str] = &[
    "password",
    "password123",
    "letmein",
    "qwerty",
    "correcthorsebatterystaple",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SealedValueError {
    EmptyValue,
    PoisoningRisk,
    InvalidId,
}

impl fmt::Display for SealedValueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyValue => f.write_str("sealed value must not be empty"),
            Self::PoisoningRisk => f.write_str("sealed value is unsafe for the redaction table"),
            Self::InvalidId => {
                f.write_str("sealed value id must use lowercase letters, digits, '-' or '_'")
            }
        }
    }
}

impl std::error::Error for SealedValueError {}

/// Validate a caller-provided identifier and literal before it can expand the
/// session's global redaction table.
pub fn validate_sealed_value(value_id: &str, value: &str) -> Result<(), SealedValueError> {
    if value_id.is_empty()
        || !value_id.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
    {
        return Err(SealedValueError::InvalidId);
    }
    if value.trim().is_empty() {
        return Err(SealedValueError::EmptyValue);
    }
    if value.len() < MIN_SEALED_VALUE_LENGTH
        || REJECTED_LITERALS
            .iter()
            .any(|rejected| value.eq_ignore_ascii_case(rejected))
    {
        return Err(SealedValueError::PoisoningRisk);
    }
    Ok(())
}

impl Session {
    /// Store a sealed literal only after its unioned redaction table has been
    /// persisted.  The caller installs the returned table into the live worker
    /// before exposing any operation that could emit text.
    ///
    /// Owner-only. Creating, listing, deleting, and existence-testing sealed
    /// values are all Owner lifecycle operations: an agent that could reach
    /// any of them would have an inventory and an existence oracle over the
    /// session's sealed values, which is exactly what this feature denies. The
    /// [`OwnerAuthority`] token cannot be forged by agent-reachable code, and
    /// these are `pub(crate)` so no new transport can grow onto them without
    /// passing through the daemon's `owner_only` command table.
    #[allow(dead_code)]
    pub(crate) async fn set_sealed_value(
        &self,
        _owner: crate::sealed::OwnerAuthority,
        redaction: &crate::redact::RedactionTable,
        value_id: &str,
        value: &str,
        reason: &str,
        origin: &str,
    ) -> Result<crate::db::sealed_values::SealedValueMetadata> {
        validate_sealed_value(value_id, value).map_err(anyhow::Error::from)?;
        // Register through the typed sealed API: a legacy session value keyed by
        // name alone (no record id, unversioned). Sealedness is stored as typed
        // classification, never as a `sealed:<id>` origin string egress reparses.
        let identity = crate::sealed::identity::SealedRedactionIdentity {
            scope: crate::sealed::identity::SealedScopeKind::Session,
            record_id: None,
            name: crate::sealed::identity::SealedName::canonical(value_id)?,
            version: 0,
        };
        // Take the sealed identity ids from the typed identity, never from a
        // parsed origin display string. A legacy session entry has no record id
        // and is unversioned, so both are `None`.
        let sealed_record_id = identity.record_id.map(|record| record.to_string());
        let sealed_version = identity.record_id.map(|_| i64::from(identity.version));
        let unioned = redaction.with_forced_sealed_literal(value.to_owned(), identity)?;

        // Journal the sealed literal on session adoption (decision 10.1). The
        // union of the redaction table is the durability event, so the journal
        // append carries zero artifact refs and commits in the same transaction
        // that persists the union. Honor the unjournaled-inference opt-out.
        if self.unjournaled_inference_allowed() {
            self.persist_redaction_table(&unioned)?;
            let vault = crate::secure_key::vault_for_db(&self.db)
                .map_err(|e| anyhow::anyhow!("opening vault for unjournaled sealed value: {e}"))?;
            let session_id = self.id;
            let value_id_owned = value_id.to_owned();
            let value_owned = value.to_owned();
            let reason_owned = reason.to_owned();
            let origin_owned = origin.to_owned();
            return self
                .db
                .transaction(move |conn| {
                    let meta = crate::db::sealed_values::upsert_sealed_value_conn(
                        conn,
                        session_id,
                        &value_id_owned,
                        &value_owned,
                        &reason_owned,
                        &origin_owned,
                    )?;
                    let item_id = crate::secure_key::session_sealed_item_id(
                        &session_id.to_string(),
                        &value_id_owned,
                        1,
                    );
                    vault
                        .put_item_on_conn(
                            conn,
                            cockpit_db::secret_vault::SecretVaultKind::SessionSealedValue,
                            &item_id,
                            value_owned.as_bytes(),
                        )
                        .map_err(|e| anyhow::anyhow!("{e}"))?;
                    Ok(meta)
                })
                .await;
        }

        let protected = crate::redact::protected_redaction_history::ProtectedLiteral::new(
            value.to_owned(),
            crate::redact::protected_redaction_history::RedactionHistorySource::Sealed,
            sealed_record_id,
            sealed_version,
        )?;
        let history = crate::redact::protected_redaction_history::ProtectedRedactionHistory::new(
            &self.db,
            self.redaction_key_resolver().as_ref(),
        );
        // Prepare off the DB thread (async key load + AEAD). A failure here rolls
        // nothing back because nothing has persisted yet (fail closed): the union
        // is not persisted and the sealed row is not written.
        let prepared = history
            .prepare_append(&self.id.to_string(), protected)
            .await?;
        // F7: compose the legacy sealed-row upsert INTO the same transaction as
        // the redaction-table union and the journal append, so a failure of any
        // one leaves none of them (no half-adopted sealed value).
        self.persist_redaction_table_with_sealed_journal(
            &unioned,
            prepared,
            Some(LegacySealedUpsert {
                value_id: value_id.to_owned(),
                value: value.to_owned(),
                reason: reason.to_owned(),
                origin: origin.to_owned(),
            }),
        )
        .await?
        .context("legacy sealed upsert metadata missing from composed transaction")
    }

    /// Adopt a sealed literal into the session redaction table and journal it to
    /// protected history atomically (decision 10.1). Prepares the encrypted
    /// append off the DB thread (async key load + AEAD), then persists the
    /// unioned `table` and the journal row in one transaction. A failure of
    /// either the prepare or the transaction rolls the whole adoption back, so a
    /// sealed literal is never adopted half-journaled. Zero artifact refs — the
    /// session-table union is itself the durability event.
    ///
    /// Callers that hold the unjournaled-inference opt-out must skip this and
    /// persist the table directly; this is the journaling seam.
    pub(crate) async fn adopt_sealed_literal_journaled(
        &self,
        table: &crate::redact::RedactionTable,
        literal: String,
        sealed_record_id: Option<String>,
        sealed_version: Option<i64>,
    ) -> Result<()> {
        let protected = crate::redact::protected_redaction_history::ProtectedLiteral::new(
            literal,
            crate::redact::protected_redaction_history::RedactionHistorySource::Sealed,
            sealed_record_id,
            sealed_version,
        )?;
        let history = crate::redact::protected_redaction_history::ProtectedRedactionHistory::new(
            &self.db,
            self.redaction_key_resolver().as_ref(),
        );
        let prepared = history
            .prepare_append(&self.id.to_string(), protected)
            .await?;
        self.persist_redaction_table_with_sealed_journal(table, prepared, None)
            .await?;
        Ok(())
    }

    /// Persist the unioned session redaction table and journal a prepared sealed
    /// adoption append in one transaction. Either both commit or both roll back,
    /// so a sealed value never persists half-journaled (decision 10.1). The
    /// journal carries zero artifact refs because the session-table union is
    /// itself the durability event.
    ///
    /// When `legacy_upsert` is `Some`, the legacy `sealed_values` row is written
    /// inside the *same* transaction (F7), so the sealed row, the table union,
    /// and the journal append are one atomic unit; the resulting metadata is
    /// returned. When `None` (the F6 live adoption path), only the table and the
    /// journal commit and `Ok(None)` is returned.
    pub(crate) async fn persist_redaction_table_with_sealed_journal(
        &self,
        table: &crate::redact::RedactionTable,
        prepared: crate::redact::protected_redaction_history::PreparedProtectedAppend,
        legacy_upsert: Option<LegacySealedUpsert>,
    ) -> Result<Option<crate::db::sealed_values::SealedValueMetadata>> {
        use crate::redact::protected_redaction_history::append_and_attach_conn;

        let json = table.to_persisted_json()?;
        let session_id = self.id;
        let write_json = json.clone();
        let vault = crate::secure_key::vault_for_db(&self.db)
            .map_err(|e| anyhow::anyhow!("opening vault for sealed journal: {e}"))?;
        let metadata = self
            .db
            .transaction(move |conn| {
                let updated = conn.execute(
                    "UPDATE sessions SET redaction_table_json = NULL WHERE session_id = ?1",
                    rusqlite::params![session_id.to_string()],
                )?;
                if updated == 0 {
                    // A sealed adoption requires a persisted session row: the
                    // history row's FK targets `sessions(session_id)`. Fail
                    // closed rather than journal an orphan.
                    anyhow::bail!(
                        "cannot journal sealed adoption: session {session_id} is not persisted"
                    );
                }
                let table_id = crate::secure_key::redaction_table_item_id(&session_id.to_string());
                vault
                    .put_item_on_conn(
                        conn,
                        cockpit_db::secret_vault::SecretVaultKind::RedactionTable,
                        &table_id,
                        write_json.as_bytes(),
                    )
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
                append_and_attach_conn(conn, &prepared, &[])?;
                let metadata = match &legacy_upsert {
                    Some(upsert) => {
                        let meta = crate::db::sealed_values::upsert_sealed_value_conn(
                            conn,
                            session_id,
                            &upsert.value_id,
                            &upsert.value,
                            &upsert.reason,
                            &upsert.origin,
                        )?;
                        let item_id = crate::secure_key::session_sealed_item_id(
                            &session_id.to_string(),
                            &upsert.value_id,
                            1,
                        );
                        vault
                            .put_item_on_conn(
                                conn,
                                cockpit_db::secret_vault::SecretVaultKind::SessionSealedValue,
                                &item_id,
                                upsert.value.as_bytes(),
                            )
                            .map_err(|e| anyhow::anyhow!("{e}"))?;
                        Some(meta)
                    }
                    None => None,
                };
                Ok(metadata)
            })
            .await?;
        // Mirror the durable write into the in-memory cache only after the
        // transaction commits, so a rollback never leaves a stale table.
        *self.redaction_table_json.lock().unwrap() = Some(json);
        Ok(metadata)
    }

    /// Owner-only inventory. See [`Session::set_sealed_value`].
    #[allow(dead_code)]
    pub(crate) async fn list_sealed_value_metadata(
        &self,
        _owner: crate::sealed::OwnerAuthority,
    ) -> Result<Vec<crate::db::sealed_values::SealedValueMetadata>> {
        self.db.list_sealed_value_metadata(self.id).await
    }

    /// Owner-only. See [`Session::set_sealed_value`].
    ///
    /// Routes through the scoped delete rather than the bare legacy row
    /// delete: a session-scope *scoped* value is dual-written, so removing
    /// only the `sealed_values` row would leave its `sealed_value_records`
    /// row resolvable with no literal behind it, its name un-tombstoned and
    /// its grants unfenced.
    pub(crate) async fn delete_sealed_value(
        &self,
        _owner: crate::sealed::OwnerAuthority,
        value_id: &str,
    ) -> Result<bool> {
        self.db
            .delete_sealed_value_for_session(
                self.id.to_string(),
                value_id.to_owned(),
                chrono::Utc::now().timestamp_millis(),
            )
            .await
    }

    /// Owner-only existence check. Sealed literals are never returned for
    /// injection or generic child handoff, and existence itself is an oracle,
    /// so this is gated like the rest. See [`Session::set_sealed_value`].
    #[allow(dead_code)]
    pub(crate) async fn sealed_value_exists(
        &self,
        _owner: crate::sealed::OwnerAuthority,
        value_id: &str,
    ) -> Result<bool> {
        self.db.sealed_value_exists(self.id, value_id).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn poisoning_guard_distinguishes_empty_and_unsafe_literals() {
        assert_eq!(
            validate_sealed_value("value", "   "),
            Err(SealedValueError::EmptyValue)
        );
        assert_eq!(
            validate_sealed_value("value", "short"),
            Err(SealedValueError::PoisoningRisk)
        );
        assert_eq!(
            validate_sealed_value("value", "password"),
            Err(SealedValueError::PoisoningRisk)
        );
        assert!(validate_sealed_value("prod_token-1", "high-entropy-value-123").is_ok());
        assert!(validate_sealed_value("private_key", &"x".repeat(8192)).is_ok());
        assert_eq!(
            validate_sealed_value("UPPER", "high-entropy-value-123"),
            Err(SealedValueError::InvalidId)
        );
    }

    #[tokio::test]
    async fn create_overwrite_delete_and_resume_keep_redaction_union_only() {
        let db = crate::db::Db::open_in_memory().unwrap();
        let session = Session::create(
            db.clone(),
            PathBuf::from("/repo"),
            "Build",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap();
        let initial = crate::redact::RedactionTable::empty();
        session
            .set_sealed_value(
                crate::sealed::OwnerAuthority::for_test("owner"),
                &initial,
                "prod_token",
                "first-high-entropy-token",
                "deploy",
                "user",
            )
            .await
            .unwrap();
        let first_table = session.persisted_redaction_table().unwrap().unwrap();
        assert!(
            !first_table
                .scrub("first-high-entropy-token")
                .contains("first-high-entropy-token")
        );
        session
            .set_sealed_value(
                crate::sealed::OwnerAuthority::for_test("owner"),
                &first_table,
                "prod_token",
                "second-high-entropy-token",
                "deploy",
                "user",
            )
            .await
            .unwrap();
        let second_table = session.persisted_redaction_table().unwrap().unwrap();
        assert!(
            !second_table
                .scrub("first-high-entropy-token")
                .contains("first-high-entropy-token")
        );
        assert!(
            session
                .sealed_value_exists(
                    crate::sealed::OwnerAuthority::for_test("owner"),
                    "prod_token"
                )
                .await
                .unwrap()
        );
        session
            .delete_sealed_value(
                crate::sealed::OwnerAuthority::for_test("owner"),
                "prod_token",
            )
            .await
            .unwrap();
        assert!(
            !session
                .sealed_value_exists(
                    crate::sealed::OwnerAuthority::for_test("owner"),
                    "prod_token"
                )
                .await
                .unwrap()
        );
        let resumed = Session::resume(
            db,
            session.id,
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap()
        .unwrap();
        assert!(
            !resumed
                .persisted_redaction_table()
                .unwrap()
                .unwrap()
                .scrub("first-high-entropy-token")
                .contains("first-high-entropy-token")
        );
    }

    #[tokio::test]
    async fn fork_inherits_preexisting_value_but_not_later_parent_value() {
        let db = crate::db::Db::open_in_memory().unwrap();
        let parent = Session::create(
            db.clone(),
            PathBuf::from("/repo"),
            "Build",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap();
        let table = crate::redact::RedactionTable::empty();
        parent
            .set_sealed_value(
                crate::sealed::OwnerAuthority::for_test("owner"),
                &table,
                "before",
                "before-high-entropy-token",
                "test",
                "user",
            )
            .await
            .unwrap();
        let child = Session::create_fork(
            db,
            parent.id,
            None,
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap();
        assert!(
            child
                .sealed_value_exists(crate::sealed::OwnerAuthority::for_test("owner"), "before")
                .await
                .unwrap()
        );
        let parent_table = parent.persisted_redaction_table().unwrap().unwrap();
        parent
            .set_sealed_value(
                crate::sealed::OwnerAuthority::for_test("owner"),
                &parent_table,
                "after",
                "after-high-entropy-token",
                "test",
                "user",
            )
            .await
            .unwrap();
        assert!(
            !child
                .sealed_value_exists(crate::sealed::OwnerAuthority::for_test("owner"), "after")
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn session_sealed_value_not_plaintext_in_sql() {
        let db = crate::db::Db::open_in_memory().unwrap();
        let session = Session::create(
            db.clone(),
            PathBuf::from("/repo"),
            "Build",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap();
        session
            .set_sealed_value(
                crate::sealed::OwnerAuthority::for_test("owner"),
                &crate::redact::RedactionTable::empty(),
                "prod_token",
                "first-high-entropy-token",
                "deploy",
                "user",
            )
            .await
            .unwrap();
        let raw: Option<String> = db
            .blocking_write_for_sync_maintenance({
                let sid = session.id.to_string();
                move |conn| {
                    Ok(conn.query_row(
                        "SELECT value FROM sealed_values WHERE session_id = ?1 AND value_id = 'prod_token'",
                        rusqlite::params![sid],
                        |row| row.get(0),
                    )?)
                }
            })
            .unwrap();
        assert!(
            raw.as_deref()
                .is_none_or(|value| value != "first-high-entropy-token"),
            "sealed_values.value must not store the literal"
        );
        let vault = crate::secure_key::vault_for_db(&db).unwrap();
        let item_id =
            crate::secure_key::session_sealed_item_id(&session.id.to_string(), "prod_token", 1);
        let got = vault
            .get_item(
                cockpit_db::secret_vault::SecretVaultKind::SessionSealedValue,
                &item_id,
            )
            .unwrap();
        assert_eq!(got.as_slice(), b"first-high-entropy-token");
    }

    #[tokio::test]
    async fn redaction_table_not_plaintext_in_sessions_column() {
        let db = crate::db::Db::open_in_memory().unwrap();
        let session = Session::create(
            db.clone(),
            PathBuf::from("/repo"),
            "Build",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap();
        session
            .set_sealed_value(
                crate::sealed::OwnerAuthority::for_test("owner"),
                &crate::redact::RedactionTable::empty(),
                "prod_token",
                "first-high-entropy-token",
                "deploy",
                "user",
            )
            .await
            .unwrap();
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
                .is_none_or(|json| !json.contains("first-high-entropy-token")),
            "sessions.redaction_table_json must not hold plaintext literals"
        );
        let table = session.persisted_redaction_table().unwrap().unwrap();
        assert!(
            !table
                .scrub("first-high-entropy-token")
                .contains("first-high-entropy-token")
        );
    }

    #[tokio::test]
    async fn session_fork_copies_vault_sealed_and_redaction_without_plaintext() {
        let db = crate::db::Db::open_in_memory().unwrap();
        let parent = Session::create(
            db.clone(),
            PathBuf::from("/repo"),
            "Build",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap();
        parent
            .set_sealed_value(
                crate::sealed::OwnerAuthority::for_test("owner"),
                &crate::redact::RedactionTable::empty(),
                "before",
                "before-high-entropy-token",
                "test",
                "user",
            )
            .await
            .unwrap();
        let child = Session::create_fork(
            db.clone(),
            parent.id,
            None,
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap();
        let child_value: Option<String> = db
            .blocking_write_for_sync_maintenance({
                let sid = child.id.to_string();
                move |conn| {
                    Ok(conn.query_row(
                        "SELECT value FROM sealed_values WHERE session_id = ?1 AND value_id = 'before'",
                        rusqlite::params![sid],
                        |row| row.get(0),
                    )?)
                }
            })
            .unwrap();
        assert!(
            child_value
                .as_deref()
                .is_none_or(|value| value != "before-high-entropy-token")
        );
        let child_table: Option<String> = db
            .blocking_write_for_sync_maintenance({
                let sid = child.id.to_string();
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
            child_table
                .as_deref()
                .is_none_or(|json| !json.contains("before-high-entropy-token"))
        );
        assert!(
            child
                .sealed_value_exists(crate::sealed::OwnerAuthority::for_test("owner"), "before")
                .await
                .unwrap()
        );
        let table = child.persisted_redaction_table().unwrap().unwrap();
        assert!(
            !table
                .scrub("before-high-entropy-token")
                .contains("before-high-entropy-token")
        );
    }

    /// Source inspection: no injection resolver or literal-return API remains.
    #[test]
    fn sealed_value_surface_has_no_public_literal_read_or_migration() {
        let source = include_str!("sealed_values.rs");
        let production = source
            .split("\n#[cfg(test)]\nmod tests")
            .next()
            .expect("production module precedes test module");
        assert!(
            !production.contains("resolve_sealed_value_for_injection"),
            "injection resolver must be retired from session API"
        );
        assert!(
            !production.contains("SealedValueForInjection"),
            "injection wrapper type must be removed"
        );
        assert!(
            production.contains("sealed_value_exists"),
            "existence check is the remaining public store API"
        );
        assert!(
            !production.contains("pub async fn get_sealed_value")
                && !production.contains("pub fn get_sealed_value")
                && !production.contains("pub fn into_inner")
                && !production.contains("pub fn reveal")
                && !production.contains("pub fn plaintext"),
            "no new public literal-read API"
        );

        let migrations = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../cockpit-db/src/db/migrations");
        let entries = std::fs::read_dir(&migrations)
            .unwrap_or_else(|error| panic!("read migrations dir: {error}"))
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        let sql_migrations: Vec<_> = entries
            .iter()
            .filter(|name| name.ends_with(".sql"))
            .cloned()
            .collect();
        // The schema is append-only: the squashed initial migration carries the
        // sealed-value tables, and later migrations (e.g. 0002/0003) add
        // unrelated features. The invariant the sealed-value repair must hold is
        // narrower than "only one migration exists": it must not append a
        // *dedicated* sealed-value migration — its tables stay in the initial
        // squashed schema — so no migration beyond the initial one names sealed
        // values.
        assert!(
            sql_migrations.contains(&"0001_initial.sql".to_string()),
            "the sealed-value schema lives in the squashed initial migration"
        );
        assert!(
            !sql_migrations
                .iter()
                .any(|name| name != "0001_initial.sql" && name.contains("sealed")),
            "sealed-value repair must not append a dedicated sealed-value migration"
        );
    }
}
