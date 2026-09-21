use cockpit_config::config::update_channel::UpdateChannel;
use cockpit_core::updater::{UpdateNotice, update_notice};

use super::App;

impl App {
    pub(super) fn sync_update_notice(&mut self) -> bool {
        let next = update_notice(UpdateChannel::Auto).map(|notice| match notice {
            UpdateNotice::Available { version } => version,
        });
        if self.update_available_version != next {
            self.update_available_version = next;
            return true;
        }
        false
    }
}
