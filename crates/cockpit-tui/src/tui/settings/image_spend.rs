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
