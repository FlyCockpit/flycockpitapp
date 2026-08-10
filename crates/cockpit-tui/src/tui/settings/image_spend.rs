#![allow(dead_code)]
//! Presentation-only image spend settings model.

use cockpit_config::config::image_spend::{
    BudgetBlockReason, ImageSpendSettings, ImageSpendSuggestions,
};

pub(crate) struct ImageSpendSettingsView {
    pub(crate) saved: ImageSpendSettings,
    pub(crate) suggestions: ImageSpendSuggestions,
    pub(crate) block_reason: Option<BudgetBlockReason>,
}

impl ImageSpendSettingsView {
    pub(crate) fn from_saved(saved: ImageSpendSettings) -> Self {
        let block_reason = saved.validate().err();
        Self {
            saved,
            suggestions: ImageSpendSuggestions::DISPLAY_ONLY,
            block_reason,
        }
    }

    pub(crate) fn replace_reviewed(&mut self, reviewed: ImageSpendSettings) {
        self.block_reason = reviewed.validate().err();
        self.saved = reviewed;
    }

    /// Persist the exact reviewed editor value and refresh version state. The
    /// display-only suggestions never enter this path.
    pub(crate) async fn save(
        &mut self,
        db: &cockpit_db::Db,
        project_key: String,
        expected_version: Option<u64>,
        saved_at_ms: i64,
    ) -> anyhow::Result<u64> {
        let current = cockpit_config::config::image_spend::activate_saved_policy(
            db,
            project_key,
            self.saved.clone(),
            expected_version,
            saved_at_ms,
        )
        .await?;
        self.block_reason = None;
        Ok(current.policy_version)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suggestions_never_mutate_saved_policy() {
        let view = ImageSpendSettingsView::from_saved(ImageSpendSettings::default());
        assert_eq!(view.saved, ImageSpendSettings::default());
        assert_eq!(
            view.block_reason,
            Some(BudgetBlockReason::RequestUnconfigured)
        );
        assert_eq!(view.suggestions.project_usd_micros, 100_000_000);
    }
}
