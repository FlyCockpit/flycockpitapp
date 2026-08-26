//! App-side wiring for the read-only session-setup overlay: open, fetch the
//! daemon-owned snapshot, and apply the result into the open pane.

use super::*;

/// Async-action name for the session-setup snapshot fetch. `Replace` policy
/// keyed on this name coalesces bursts (e.g. repeated `AgentTreeChanged`
/// invalidations) into a single in-flight request.
const SESSION_SETUP_SNAPSHOT_ACTION: &str = "session_setup.snapshot";

impl App {
    /// Open the read-only session-setup overlay and schedule its first
    /// snapshot fetch. The daemon owns the snapshot; before attach the pane
    /// shows a fixed unavailable message rather than any local guess.
    pub(super) fn open_session_setup(&mut self) {
        // Colour is supplementary here; render with styling and let the
        // terminal honour NO_COLOR. The plain projection is exercised by tests.
        self.overlay =
            Overlay::SessionSetup(crate::tui::session_setup::SessionSetupPane::loading(true));
        self.request_session_setup_snapshot_refresh();
    }

    /// Schedule an async `GetSessionSetupSnapshot` fetch for the attached
    /// session. A no-op (with a fixed error surfaced in the pane) when there is
    /// no attached runner, since the snapshot is daemon-owned.
    pub(super) fn request_session_setup_snapshot_refresh(&mut self) {
        let Some(Ok(runner)) = self.agent_runner.as_ref() else {
            if let Overlay::SessionSetup(pane) = &mut self.overlay {
                pane.set_error("Session setup is only available once attached to a session.");
            }
            return;
        };
        let attached = runner.attached_request_binding();
        let session_id = attached.session_id();
        self.async_actions.start(
            crate::tui::async_action::AsyncActionKind::DaemonRpc(SESSION_SETUP_SNAPSHOT_ACTION),
            crate::tui::async_action::AsyncActionPolicy::Replace(
                crate::tui::async_action::AsyncActionKey::new(SESSION_SETUP_SNAPSHOT_ACTION),
            ),
            async move {
                let response = attached
                    .request(cockpit_proto::Request::GetSessionSetupSnapshot { session_id })
                    .await
                    .map_err(|error| error.to_string())?;
                Ok(crate::tui::async_action::AsyncActionPayload::SessionSetupSnapshot(response))
            },
        );
    }

    /// Apply a completed `GetSessionSetupSnapshot` response into the open
    /// overlay. Inert if the overlay was closed or already replaced.
    pub(super) fn apply_session_setup_snapshot_response(&mut self, response: cockpit_proto::Response) {
        let cockpit_proto::Response::SessionSetupSnapshot { snapshot } = response else {
            return;
        };
        if let Overlay::SessionSetup(pane) = &mut self.overlay {
            pane.apply_snapshot(snapshot);
        }
    }

    /// Surface a fixed error into the open session-setup overlay.
    pub(super) fn apply_session_setup_snapshot_error(&mut self, error: String) {
        if let Overlay::SessionSetup(pane) = &mut self.overlay {
            pane.set_error(format!("Session setup could not be loaded: {error}"));
        }
    }
}
