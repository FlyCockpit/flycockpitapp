//! Validation and injection-only types for session sealed values.

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

/// Deliberately non-Debug/Display wrapper used only by injection consumers.
#[allow(dead_code)]
pub struct SealedValueForInjection(String);

#[allow(dead_code)]
impl SealedValueForInjection {
    pub(crate) fn new(value: String) -> Self {
        Self(value)
    }
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl Session {
    /// Store a sealed literal only after its unioned redaction table has been
    /// persisted.  The caller installs the returned table into the live worker
    /// before exposing any operation that could emit text.
    pub async fn set_sealed_value(
        &self,
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

    pub async fn list_sealed_value_metadata(
        &self,
    ) -> Result<Vec<crate::db::sealed_values::SealedValueMetadata>> {
        self.db.list_sealed_value_metadata(self.id).await
    }

    pub async fn delete_sealed_value(&self, value_id: &str) -> Result<bool> {
        self.db.delete_sealed_value(self.id, value_id).await
    }

    pub async fn resolve_sealed_value_for_injection(
        &self,
        value_id: &str,
    ) -> Result<Option<SealedValueForInjection>> {
        Ok(self
            .db
            .resolve_sealed_value_for_injection(self.id, value_id)
            .await?
            .map(SealedValueForInjection::new))
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
        assert_eq!(
            SealedValueForInjection::new("high-entropy-value-123".into()).as_str(),
            "high-entropy-value-123"
        );
    }

    #[tokio::test]
    async fn create_overwrite_delete_and_resume_keep_redaction_union_only() {
        let db = crate::db::Db::open_in_memory().unwrap();
        let session = Session::create(db.clone(), PathBuf::from("/repo"), "Build").unwrap();
        let initial = crate::redact::RedactionTable::empty();
        session
            .set_sealed_value(
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
        assert_eq!(
            session
                .resolve_sealed_value_for_injection("prod_token")
                .await
                .unwrap()
                .unwrap()
                .as_str(),
            "second-high-entropy-token"
        );
        session.delete_sealed_value("prod_token").await.unwrap();
        assert!(
            session
                .resolve_sealed_value_for_injection("prod_token")
                .await
                .unwrap()
                .is_none()
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
                .resolve_sealed_value_for_injection("before")
                .await
                .unwrap()
                .is_some()
        );
        let parent_table = parent.persisted_redaction_table().unwrap().unwrap();
        parent
            .set_sealed_value(
                &parent_table,
                "after",
                "after-high-entropy-token",
                "test",
                "user",
            )
            .await
            .unwrap();
        assert!(
            child
                .resolve_sealed_value_for_injection("after")
                .await
                .unwrap()
                .is_none()
        );
    }
}
