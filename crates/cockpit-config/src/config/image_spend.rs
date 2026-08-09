//! Explicit image-generation spend policy.
//!
//! Absence is deliberately represented as `Unconfigured`; suggestions are a
//! presentation aid and never participate in authorization.

pub use cockpit_db::db::image_spend::{
    BudgetBlockReason, BudgetPolicy, CurrentImageSpendPolicy, ImageSpendSettings,
    ProjectEpochPolicy, SavedInstant,
};

/// Persist a user-reviewed file-backed policy into the immutable ledger and
/// return the exact version tokens preflight must use. Finite project policy
/// additionally requires a caller-resolved, explicit window label/start.
pub async fn activate_saved_policy(
    db: &cockpit_db::Db,
    project_key: String,
    saved: ImageSpendSettings,
    expected_current_version: Option<u64>,
    epoch_membership: Option<(String, i64)>,
    saved_at_ms: i64,
) -> anyhow::Result<CurrentImageSpendPolicy> {
    saved.validate().map_err(anyhow::Error::new)?;
    if matches!(saved.project, BudgetPolicy::Finite { .. }) && epoch_membership.is_none() {
        return Err(BudgetBlockReason::ProjectEpochUnconfigured.into());
    }
    let version = db
        .save_image_spend_policy(
            project_key.clone(),
            saved,
            expected_current_version,
            saved_at_ms,
        )
        .await?;
    let mut current = db
        .current_image_spend_policy(project_key.clone())
        .await?
        .ok_or_else(|| anyhow::anyhow!("saved image spend policy disappeared"))?;
    debug_assert_eq!(current.policy_version, version);
    if matches!(current.settings.project, BudgetPolicy::Finite { .. }) {
        let (label, start) = epoch_membership
            .ok_or_else(|| anyhow::Error::new(BudgetBlockReason::ProjectEpochUnconfigured))?;
        current.epoch_sequence = Some(
            db.resolve_image_spend_epoch(
                project_key,
                current.epoch_policy_version,
                label,
                start,
                saved_at_ms,
            )
            .await?,
        );
    }
    Ok(current)
}

/// Editable UI suggestions. These values are not a default and must never be
/// merged into [`ImageSpendSettings`] by a loader.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImageSpendSuggestions {
    pub request_usd_micros: u64,
    pub session_usd_micros: u64,
    pub project_usd_micros: u64,
}

impl ImageSpendSuggestions {
    pub const DISPLAY_ONLY: Self = Self {
        request_usd_micros: 1_000_000,
        session_usd_micros: 10_000_000,
        project_usd_micros: 100_000_000,
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suggestions_are_not_saved_policy() {
        let settings: ImageSpendSettings = serde_json::from_str("{}").unwrap();
        assert_eq!(settings, ImageSpendSettings::default());
        assert_eq!(
            settings.validate(),
            Err(BudgetBlockReason::RequestUnconfigured)
        );
        assert_eq!(
            ImageSpendSuggestions::DISPLAY_ONLY.request_usd_micros,
            1_000_000
        );
    }

    #[test]
    fn finite_must_be_positive_and_epoch_has_no_default() {
        assert!(serde_json::from_str::<BudgetPolicy>(r#"{"finite":{"usd_micros":0}}"#).is_err());
        let raw = r#"{"request":{"finite":{"usd_micros":1}},"session":"unlimited","project":{"finite":{"usd_micros":2}}}"#;
        let settings: ImageSpendSettings = serde_json::from_str(raw).unwrap();
        assert_eq!(
            settings.validate(),
            Err(BudgetBlockReason::ProjectEpochUnconfigured)
        );
    }
}
