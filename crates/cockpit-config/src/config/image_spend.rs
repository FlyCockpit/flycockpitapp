//! Explicit image-generation spend policy.
//!
//! Absence is deliberately represented as `Unconfigured`; suggestions are a
//! presentation aid and never participate in authorization.

pub use cockpit_db::db::image_spend::{
    BudgetBlockReason, BudgetPolicy, CurrentImageSpendPolicy, ImageSpendSettings,
    ProjectEpochPolicy, SavedInstant,
};

/// Persist a user-reviewed file-backed policy into the immutable ledger and
/// return the exact version tokens preflight must use. This versions policy
/// only; reservation derives epoch membership from the server-owned clock.
pub async fn activate_saved_policy(
    db: &cockpit_db::Db,
    project_key: String,
    saved: ImageSpendSettings,
    expected_current_version: Option<u64>,
    saved_at_ms: i64,
) -> anyhow::Result<CurrentImageSpendPolicy> {
    saved.validate().map_err(anyhow::Error::new)?;
    let version = db
        .save_image_spend_policy(
            project_key.clone(),
            saved,
            expected_current_version,
            saved_at_ms,
        )
        .await?;
    let current = db
        .current_image_spend_policy(project_key.clone())
        .await?
        .ok_or_else(|| anyhow::anyhow!("saved image spend policy disappeared"))?;
    debug_assert_eq!(current.policy_version, version);
    Ok(current)
}

/// Persist a reviewed policy through the application-owned database without
/// exposing the database crate to UI layers.
pub async fn activate_saved_policy_default(
    project_key: String,
    saved: ImageSpendSettings,
    expected_current_version: Option<u64>,
    saved_at_ms: i64,
) -> anyhow::Result<CurrentImageSpendPolicy> {
    let db = cockpit_db::Db::open_default()?;
    activate_saved_policy(
        &db,
        project_key,
        saved,
        expected_current_version,
        saved_at_ms,
    )
    .await
}

pub async fn current_saved_policy_default(
    project_key: String,
) -> anyhow::Result<Option<CurrentImageSpendPolicy>> {
    cockpit_db::Db::open_default()?
        .current_image_spend_policy(project_key)
        .await
}

/// Application-layer image spend policy persistence with the database
/// implementation kept behind the config crate boundary.
#[derive(Clone)]
pub struct ImageSpendPolicyStore {
    db: cockpit_db::Db,
}

impl ImageSpendPolicyStore {
    pub fn open(path: &std::path::Path) -> anyhow::Result<Self> {
        Ok(Self {
            db: cockpit_db::Db::open(path)?,
        })
    }

    pub async fn current(
        &self,
        project_key: String,
    ) -> anyhow::Result<Option<CurrentImageSpendPolicy>> {
        self.db.current_image_spend_policy(project_key).await
    }

    pub async fn activate(
        &self,
        project_key: String,
        saved: ImageSpendSettings,
        expected_current_version: Option<u64>,
        saved_at_ms: i64,
    ) -> anyhow::Result<CurrentImageSpendPolicy> {
        activate_saved_policy(
            &self.db,
            project_key,
            saved,
            expected_current_version,
            saved_at_ms,
        )
        .await
    }
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

    #[tokio::test]
    async fn reviewed_policy_saves_and_reopens_without_creating_epoch_head() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("spend.db");
        let settings = ImageSpendSettings {
            request: BudgetPolicy::Finite { usd_micros: 1 },
            session: BudgetPolicy::Unlimited,
            project: BudgetPolicy::Finite {
                usd_micros: u64::MAX,
            },
            // No user-supplied anchor: the server stamps the effective anchor.
            project_epoch: Some(ProjectEpochPolicy::Rolling {
                duration_seconds: 86_400,
            }),
        };
        {
            let db = cockpit_db::Db::open(&path).unwrap();
            let saved = activate_saved_policy(&db, "project".into(), settings, None, 1_000)
                .await
                .unwrap();
            assert_eq!(saved.epoch_sequence, None);
            assert!(matches!(
                saved.settings.project_epoch,
                Some(ProjectEpochPolicy::Rolling {
                    duration_seconds: 86_400
                })
            ));
            // The anchor is exposed only through the server-owned read model.
            assert_eq!(
                saved.effective_rolling_anchor,
                Some(SavedInstant {
                    unix_ms: 1_000,
                    monotonic_sequence: 1,
                })
            );
        }
        let reopened = cockpit_db::Db::open(&path).unwrap();
        let current = reopened
            .current_image_spend_policy("project".into())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            current.settings.project,
            BudgetPolicy::Finite {
                usd_micros: u64::MAX
            }
        );
        assert_eq!(current.epoch_sequence, None);
    }
}
