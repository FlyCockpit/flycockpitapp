//! Installed updater composition. Production callers must use this funnel.

use super::disabled::DisabledUpdater;
use super::traits::Updater;

/// Installed updater composition for the shipped binary.
#[derive(Debug, Clone)]
pub struct InstalledUpdaterComposition {
    updater: DisabledUpdater,
}

impl InstalledUpdaterComposition {
    pub fn updater(&self) -> &DisabledUpdater {
        &self.updater
    }
}

/// Return the only production updater composition.
pub fn installed_composition() -> InstalledUpdaterComposition {
    InstalledUpdaterComposition {
        updater: DisabledUpdater::new(),
    }
}

/// Convenience accessor for the installed [`Updater`] implementation.
pub fn installed_updater() -> DisabledUpdater {
    DisabledUpdater::new()
}
