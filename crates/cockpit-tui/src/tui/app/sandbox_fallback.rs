//! One-time, explicitly consented fallback when the host shell sandbox cannot
//! start because the host restricts unprivileged user namespaces.
//!
//! Fail-closed stays the invariant: a sandbox intent the host cannot honor is
//! effective `Refuse` (never silent `Off`), and `bash` is refused. This module
//! only *offers* the user a decision the first time that refusal is caused by
//! a diagnosed host user-namespace restriction in an interactive session:
//!
//! - **Copy fix command** / **Copy persistent fix** copy the exact host
//!   command(s) and keep the dialog open.
//! - **Run unsandboxed** is the user's explicit consent: it takes the existing
//!   `/sandbox off` path, which persists `sandbox=off` for the project.
//! - **Keep refusing** (or Esc) dismisses it; it is not shown again this
//!   session.
//!
//! It is never shown for a headless `cockpit run` (no TUI) or under approval
//! mode Yolo — those stay fail-closed with the actionable error pointing at
//! `--no-sandbox` / `/sandbox off`. Nothing here flips the sandbox off
//! without the explicit button.

use super::*;
use cockpit_core::tools::shell_sandbox::UsernsRestriction;

pub(super) const SANDBOX_FALLBACK_TITLE: &str = "Sandbox can't start";
pub(super) const SANDBOX_FALLBACK_COPY_FIX_ID: &str = "copy_fix";
pub(super) const SANDBOX_FALLBACK_COPY_PERSIST_ID: &str = "copy_persist";
pub(super) const SANDBOX_FALLBACK_RUN_UNSANDBOXED_ID: &str = "run_unsandboxed";
pub(super) const SANDBOX_FALLBACK_KEEP_REFUSING_ID: &str = "keep_refusing";

/// Once-per-session lifecycle of the consent dialog.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum SandboxFallbackPrompt {
    /// Not raised yet this session.
    #[default]
    NotShown,
    /// Raised while another dialog owned the screen; shown when it closes.
    Deferred,
    /// Shown (open or answered). Never re-shown this session.
    Shown,
}

/// Body of the consent dialog. Pure so the wording is unit-testable.
pub(super) fn sandbox_fallback_prompt_text(
    reason: &str,
    fix_command: Option<&str>,
    persist_command: Option<&str>,
    alternative: Option<&str>,
    status: Option<&str>,
) -> String {
    let mut text = format!("{}.", reason.trim().trim_end_matches('.'));
    text.push_str(
        "\n\nbash is refused while the sandbox is on; nothing runs unconfined unless you choose it here.",
    );
    if let Some(fix) = fix_command {
        text.push_str("\n\nFix now (until reboot):\n  ");
        text.push_str(fix);
    }
    if let Some(persist) = persist_command {
        text.push_str("\nKeep across reboots:\n  ");
        text.push_str(persist);
    }
    if let Some(alternative) = alternative {
        text.push_str("\n\n");
        text.push_str(alternative);
    }
    text.push_str("\n\nAfter fixing the host, run /sandbox on.");
    if let Some(status) = status {
        text.push_str("\n\n");
        text.push_str(status);
    }
    text
}

impl App {
    /// The diagnosed host user-namespace restriction behind the current
    /// sandbox-down notice, if any.
    fn sandbox_fallback_restriction(&self) -> Option<UsernsRestriction> {
        let notice = self.sandbox_down_notice.as_ref()?;
        notice
            .fix_command
            .as_deref()
            .and_then(UsernsRestriction::from_fix_command)
            .or_else(|| UsernsRestriction::from_reason(&notice.remedy))
    }

    /// `(fix, persist)` commands for the current restriction.
    fn sandbox_fallback_commands(&self) -> (Option<String>, Option<String>) {
        let restriction = self.sandbox_fallback_restriction();
        let notice = self.sandbox_down_notice.as_ref();
        let fix = notice
            .and_then(|notice| notice.fix_command.clone())
            .or_else(|| restriction.map(|r| r.fix_command().to_string()));
        let persist = notice
            .and_then(|notice| notice.persist_command.clone())
            .or_else(|| restriction.map(|r| r.persist_command().to_string()));
        (fix, persist)
    }

    /// Whether this refusal may offer the consent dialog: an attached,
    /// interactive daemon session whose host-sandbox mode (or its fail-closed
    /// `Refuse`) is blocked by a diagnosed user-namespace restriction, outside
    /// approval mode Yolo.
    pub(super) fn sandbox_fallback_eligible(&self) -> bool {
        self.sandbox_fallback_restriction().is_some()
            && self.approval_mode != cockpit_config::extended::ApprovalMode::Yolo
            && matches!(
                self.sandbox_mode,
                cockpit_proto::SandboxMode::Sandbox | cockpit_proto::SandboxMode::Refuse
            )
            && !self.sandbox_intent.is_container()
            && self
                .agent_runner
                .as_ref()
                .is_some_and(|runner| runner.is_ok())
    }

    /// Offer the consent dialog on the first eligible refusal this session.
    /// Defers (rather than stacking) when another dialog owns the screen.
    pub(super) fn maybe_offer_sandbox_fallback(&mut self) {
        if self.sandbox_fallback_prompt == SandboxFallbackPrompt::Shown
            || !self.sandbox_fallback_eligible()
        {
            return;
        }
        if self.question_dialog.is_some() || self.pending_local_choice.is_some() {
            self.sandbox_fallback_prompt = SandboxFallbackPrompt::Deferred;
            return;
        }
        self.sandbox_fallback_prompt = SandboxFallbackPrompt::Shown;
        self.open_sandbox_fallback_dialog(None);
    }

    /// Show a deferred consent dialog once the blocking dialog has closed.
    pub(super) fn retry_deferred_sandbox_fallback(&mut self) {
        if self.sandbox_fallback_prompt == SandboxFallbackPrompt::Deferred {
            self.maybe_offer_sandbox_fallback();
        }
    }

    fn open_sandbox_fallback_dialog(&mut self, status: Option<&str>) {
        use cockpit_proto::{InterruptOption, InterruptQuestion, InterruptQuestionSet};

        let Some(notice) = self.sandbox_down_notice.clone() else {
            return;
        };
        let alternative = self
            .sandbox_fallback_restriction()
            .and_then(UsernsRestriction::alternative);
        let (fix, persist) = self.sandbox_fallback_commands();
        let prompt = sandbox_fallback_prompt_text(
            &notice.remedy,
            fix.as_deref(),
            persist.as_deref(),
            alternative.as_deref(),
            status,
        );
        let option = |id: &str, label: &str, description: &str| InterruptOption {
            id: id.to_string(),
            label: label.to_string(),
            description: Some(description.to_string()),
            secondary: false,
        };
        let mut options = Vec::new();
        if fix.is_some() {
            options.push(option(
                SANDBOX_FALLBACK_COPY_FIX_ID,
                "Copy fix command",
                "Copy the one-shot host fix; run it in a terminal, then /sandbox on.",
            ));
        }
        if persist.is_some() {
            options.push(option(
                SANDBOX_FALLBACK_COPY_PERSIST_ID,
                "Copy persistent fix",
                "Copy the command that keeps the fix across reboots.",
            ));
        }
        options.push(option(
            SANDBOX_FALLBACK_RUN_UNSANDBOXED_ID,
            "Run unsandboxed",
            "Turn the sandbox off for this project (saved as sandbox=off). Shell commands then run unconfined, still subject to approvals.",
        ));
        options.push(option(
            SANDBOX_FALLBACK_KEEP_REFUSING_ID,
            "Keep refusing",
            "Leave bash refused until the host is fixed. Not asked again this session.",
        ));
        let interrupt_id = uuid::Uuid::new_v4();
        self.pending_local_choice = Some(LocalChoice::SandboxFallback(interrupt_id));
        self.question_dialog = Some(
            crate::tui::dialog::question::QuestionDialog::new(
                interrupt_id,
                SANDBOX_FALLBACK_TITLE.to_string(),
                InterruptQuestionSet {
                    questions: vec![InterruptQuestion::Single {
                        prompt,
                        options,
                        allow_freetext: false,
                        command_detail: None,
                        permission: false,
                        approval_class: None,
                        sandbox_escalation: None,
                    }],
                },
                self.dialog_lockout(),
            )
            .with_keyboard_enhancement_active(self.keyboard_enhancement_active),
        );
    }

    /// Apply the user's answer to the consent dialog.
    pub(super) fn resolve_sandbox_fallback_choice(&mut self, selected: Option<&str>) {
        match selected {
            Some(SANDBOX_FALLBACK_COPY_FIX_ID) => {
                let (fix, _) = self.sandbox_fallback_commands();
                if let Some(fix) = fix {
                    self.copy_host_command(&fix, "Copied fix command.");
                }
                self.open_sandbox_fallback_dialog(Some(
                    "Fix command copied. Run it in a terminal, then choose Keep refusing and run /sandbox on.",
                ));
            }
            Some(SANDBOX_FALLBACK_COPY_PERSIST_ID) => {
                let (_, persist) = self.sandbox_fallback_commands();
                if let Some(persist) = persist {
                    self.copy_host_command(&persist, "Copied persistent fix command.");
                }
                self.open_sandbox_fallback_dialog(Some(
                    "Persistent fix copied. It applies from the next boot; run the one-shot fix too to use the sandbox now.",
                ));
            }
            Some(SANDBOX_FALLBACK_RUN_UNSANDBOXED_ID) => {
                // The user's explicit consent: exactly the `/sandbox off`
                // composer path, which persists `sandbox=off`.
                self.handle_sandbox_command("off");
            }
            _ => {
                self.show_toast(
                    "Sandbox stays on: bash is refused until the host is fixed (then /sandbox on); /sandbox off runs unconfined.",
                    ToastKind::Info,
                );
            }
        }
    }

    /// One-time non-modal hint: a capability refresh shows the host sandbox
    /// became available while this session runs Off (or fail-closed Refuse).
    /// Suggests `/sandbox on`; never changes the mode itself.
    pub(super) fn note_host_sandbox_recovery(
        &mut self,
        previous: &cockpit_proto::HostCapabilitySnapshot,
    ) {
        use cockpit_core::host_capabilities::FEATURE_SANDBOX_HOST;

        if self.sandbox_available_notice_shown {
            return;
        }
        // Only a published "down" → "available" transition counts; a host that
        // was always fine does not nag a user who deliberately chose Off.
        let was_down = previous
            .feature(FEATURE_SANDBOX_HOST)
            .is_some_and(|row| !row.state.is_available());
        let now_available = self
            .host_capabilities
            .feature(FEATURE_SANDBOX_HOST)
            .is_some_and(|row| row.state.is_available());
        if !was_down || !now_available || self.sandbox_intent.is_container() {
            return;
        }
        if !matches!(
            self.sandbox_mode,
            cockpit_proto::SandboxMode::Off | cockpit_proto::SandboxMode::Refuse
        ) {
            return;
        }
        self.sandbox_available_notice_shown = true;
        self.show_toast(
            "Host sandbox is available again. Run /sandbox on to confine shell commands.",
            ToastKind::Info,
        );
    }
}
