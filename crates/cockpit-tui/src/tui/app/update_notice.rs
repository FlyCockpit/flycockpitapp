use cockpit_core::updater::{UpdateNotice, effective_update_channel, update_notice};

use super::App;

impl App {
    pub(super) fn sync_update_notice(&mut self) -> bool {
        let next =
            effective_update_channel()
                .ok()
                .and_then(update_notice)
                .map(|notice| match notice {
                    UpdateNotice::Available { version } => version,
                });
        if self.update_available_version != next {
            self.update_available_version = next;
            return true;
        }
        false
    }
}
