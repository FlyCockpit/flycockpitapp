//! Validation and store helpers for session sealed values.
//! Child-environment injection of sealed literals is retired.

use std::fmt;

use anyhow::Result;

use super::Session;

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
        let unioned =
            redaction.with_forced_literal(value.to_owned(), format!("sealed:{value_id}"))?;
        self.persist_redaction_table(&unioned)?;
        self.db
            .upsert_sealed_value(self.id, value_id, value, reason, origin)
            .await
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
        let session = Session::create(db.clone(), PathBuf::from("/repo"), "Build").unwrap();
        let initial = crate::redact::RedactionTable::empty();
        session
            .set_sealed_value(
                crate::sealed::OwnerAuthority::for_test(),
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
                crate::sealed::OwnerAuthority::for_test(),
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
                .sealed_value_exists(crate::sealed::OwnerAuthority::for_test(), "prod_token")
                .await
                .unwrap()
        );
        session
            .delete_sealed_value(crate::sealed::OwnerAuthority::for_test(), "prod_token")
            .await
            .unwrap();
        assert!(
            !session
                .sealed_value_exists(crate::sealed::OwnerAuthority::for_test(), "prod_token")
                .await
                .unwrap()
        );
        let resumed = Session::resume(db, session.id).unwrap().unwrap();
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
        let parent = Session::create(db.clone(), PathBuf::from("/repo"), "Build").unwrap();
        let table = crate::redact::RedactionTable::empty();
        parent
            .set_sealed_value(
                crate::sealed::OwnerAuthority::for_test(),
                &table,
                "before",
                "before-high-entropy-token",
                "test",
                "user",
            )
            .await
            .unwrap();
        let child = Session::create_fork(db, parent.id, None).unwrap();
        assert!(
            child
                .sealed_value_exists(crate::sealed::OwnerAuthority::for_test(), "before")
                .await
                .unwrap()
        );
        let parent_table = parent.persisted_redaction_table().unwrap().unwrap();
        parent
            .set_sealed_value(
                crate::sealed::OwnerAuthority::for_test(),
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
                .sealed_value_exists(crate::sealed::OwnerAuthority::for_test(), "after")
                .await
                .unwrap()
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
        assert_eq!(
            sql_migrations,
            vec!["0001_initial.sql".to_string()],
            "sealed-value repair must not add any migration beyond the squashed initial schema"
        );
    }
}
