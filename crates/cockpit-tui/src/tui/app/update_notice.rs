use cockpit_core::updater::{UpdateNotice, effective_update_channel, update_notice};

use super::App;

impl App {
    pub(super) fn sync_update_notice(&mut self) -> bool {
        let next = match effective_update_channel() {
            Ok(channel) => update_notice(channel).map(update_notice_text),
            Err(error) => Some(format!("updates misconfigured: {error}")),
        };
        if self.update_disabled_notice != next {
            self.update_disabled_notice = next;
            return true;
        }
        false
    }

    pub(super) fn update_disabled_notice_text(&self) -> Option<&str> {
        self.update_disabled_notice.as_deref()
    }
}

fn update_notice_text(notice: UpdateNotice) -> String {
    match notice {
        UpdateNotice::Disabled(reason) => format!("updates disabled: {reason}"),
    }
}
