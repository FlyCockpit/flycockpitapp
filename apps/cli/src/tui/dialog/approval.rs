//! Command/path-approval wiring over the reusable [`DialogState`]
//! (sandboxing part 1, §3).
//!
//! The thin use-case layer the dialog core was designed to support
//! (mirroring [`super::question`]): it builds a single scoped decision page
//! for normal approvals, drives the shared state machine, and maps the
//! resulting [`Answer`] back to an [`ApprovalChoice`] the approval subsystem
//! records. A flagged wrapper collapses to a smaller once-only page because
//! wrappers can't be remembered in either polarity.

use std::time::Duration;

use crossterm::event::KeyEvent;
use uuid::Uuid;

use crate::approval::store::Scope;
use crate::tui::dialog::{Answer, DialogOption, DialogOutcome, DialogState, Page};

/// Stable option ids for the page-1 **verdict** select (approve vs reject).
/// They ride through the interrupt as the selected id and decide whether the
/// page-2 scope yields an [`ApprovalChoice::Approve`] or
/// [`ApprovalChoice::Reject`].
pub const ID_APPROVE: &str = "approve";
pub const ID_REJECT: &str = "reject";

/// Stable option ids for the single-surface scoped approval prompt.
pub const ID_APPROVE_ONCE: &str = "approve_once";
pub const ID_APPROVE_SESSION: &str = "approve_session";
pub const ID_APPROVE_PROJECT: &str = "approve_project";
pub const ID_APPROVE_GLOBAL: &str = "approve_global";
pub const ID_REJECT_ONCE: &str = "reject_once";
pub const ID_REJECT_SESSION: &str = "reject_session";
pub const ID_REJECT_PROJECT: &str = "reject_project";
pub const ID_REJECT_GLOBAL: &str = "reject_global";

/// Stable option ids for approval-adjacent scope selects, such as gitignore
/// persistence and package-add once approval.
pub const ID_ONCE: &str = "once";
pub const ID_SESSION: &str = "session";
pub const ID_PROJECT: &str = "project";
pub const ID_GLOBAL: &str = "global";

/// Stable option ids for the loop-guard approval prompt (back-to-back
/// identical tool call). These ride through the generic interrupt the
/// same way the scope-select ids do; the loop guard maps the selected id
/// back to an accept/reject verdict + scope. No TUI special-casing is
/// needed — the answering dialog renders any option set generically.
pub const ID_LOOP_ACCEPT_ONCE: &str = "loop_accept_once";
pub const ID_LOOP_REJECT_ONCE: &str = "loop_reject_once";
pub const ID_LOOP_ACCEPT_SESSION: &str = "loop_accept_session";
pub const ID_LOOP_REJECT_SESSION: &str = "loop_reject_session";
pub const ID_LOOP_ACCEPT_PROJECT: &str = "loop_accept_project";
pub const ID_LOOP_REJECT_PROJECT: &str = "loop_reject_project";

/// Stable option ids for the gitignore read-allowlist two-stage approval
/// (implementation note). Stage 1 chooses the glob *shape*
/// (this exact file / its parent directory) or rejects; stage 2 reuses the
/// scope ids ([`ID_ONCE`]/[`ID_SESSION`]/[`ID_PROJECT`]) for *persistence*.
/// They ride the generic interrupt exactly like the scope-select ids; no TUI
/// special-casing is needed.
pub const ID_GITIGNORE_FILE: &str = "gitignore_file";
pub const ID_GITIGNORE_PARENT: &str = "gitignore_parent";
pub const ID_GITIGNORE_REJECT: &str = "gitignore_reject";

/// The user's choice on an approval prompt. `Deny` is the dismissal
/// path (Esc / cancel — persists nothing); `Approve(scope)` allows at the
/// named scope; `Reject(scope)` persists a standing reject at the named
/// scope. `Reject(Scope::Once)` is the explicit-menu equivalent of Esc
/// (deny this invocation, persist nothing) and is normalized to `Deny`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalChoice {
    Approve(Scope),
    Reject(Scope),
    Deny,
}

/// What the host should do once the approval dialog closes.
#[derive(Debug, Clone)]
pub enum ApprovalResult {
    /// Resolve `interrupt_id` with the chosen scope (or deny).
    Resolved {
        interrupt_id: Uuid,
        choice: ApprovalChoice,
    },
}

/// The App-facing approval dialog overlay. Owns a [`DialogState`] built
/// from a scoped decision page (or a smaller wrapper page), plus the interrupt
/// id it resolves.
pub struct ApprovalDialog {
    interrupt_id: Uuid,
    /// Whether this is the wrapper-restricted variant (once/deny only).
    wrapper: bool,
    state: DialogState,
    result: Option<ApprovalResult>,
}

impl ApprovalDialog {
    /// Build the dialog for a raised approval interrupt. `prompt` is the
    /// command or path being requested (already terse, §10). `wrapper`
    /// selects the restricted variant. `lockout` is the anti-misfire
    /// delay shared with the question dialog.
    pub fn new(interrupt_id: Uuid, prompt: String, wrapper: bool, lockout: Duration) -> Self {
        let pages = if wrapper {
            vec![wrapper_page(prompt)]
        } else {
            vec![scoped_approval_page(prompt)]
        };
        let state = DialogState::new(pages, lockout);
        Self {
            interrupt_id,
            wrapper,
            state,
            result: None,
        }
    }

    /// The dialog state, for the host renderer.
    pub fn state(&self) -> &DialogState {
        &self.state
    }

    /// Whether this is the wrapper-restricted variant — the renderer
    /// shows the "wrappers can't be remembered" note when true.
    pub fn is_wrapper(&self) -> bool {
        self.wrapper
    }

    /// Drain the close result once [`handle_key`](Self::handle_key)
    /// returned `true`.
    pub fn take_result(&mut self) -> Option<ApprovalResult> {
        self.result.take()
    }

    /// Route a key. Returns `true` when the dialog wants to close.
    pub fn handle_key(&mut self, key: KeyEvent) -> bool {
        match self.state.handle_key(key) {
            DialogOutcome::Continue => false,
            DialogOutcome::Cancel => {
                self.result = Some(ApprovalResult::Resolved {
                    interrupt_id: self.interrupt_id,
                    choice: ApprovalChoice::Deny,
                });
                true
            }
            DialogOutcome::Submit(answers) => {
                let choice = answers_to_choice(&answers, self.wrapper);
                self.result = Some(ApprovalResult::Resolved {
                    interrupt_id: self.interrupt_id,
                    choice,
                });
                true
            }
        }
    }
}

/// Build the normal approval page: each row is a final scoped decision.
fn scoped_approval_page(prompt: String) -> Page {
    let title = format!("Run `{prompt}`?");
    let options = vec![
        opt(ID_APPROVE_ONCE, "Approve once"),
        opt(ID_APPROVE_SESSION, "Approve for this session"),
        opt(ID_APPROVE_PROJECT, "Approve for this project"),
        opt(ID_APPROVE_GLOBAL, "Approve everywhere"),
        opt(ID_REJECT_ONCE, "Reject once"),
        opt(ID_REJECT_SESSION, "Reject for this session"),
        opt(ID_REJECT_PROJECT, "Reject for this project"),
        opt(ID_REJECT_GLOBAL, "Reject everywhere"),
    ];
    Page::select(title, options).permission()
}

/// Build the wrapper-restricted page. Both choices are transient because a
/// wrapper is never persistable in either polarity.
fn wrapper_page(prompt: String) -> Page {
    let title = format!("Run `{prompt}`? (wrapper — can't be remembered)");
    let options = vec![
        opt(ID_APPROVE, "Approve once"),
        opt(ID_REJECT, "Reject once"),
    ];
    Page::select(title, options).permission()
}

fn opt(id: &str, label: &str) -> DialogOption {
    DialogOption::new(id, label)
}

/// Map the one-page answer into an [`ApprovalChoice`]. Any malformed/unknown
/// answer reads as a deny — the safe default.
fn answers_to_choice(answers: &[Answer], wrapper: bool) -> ApprovalChoice {
    let Some(answer) = answers.first() else {
        return ApprovalChoice::Deny;
    };
    if wrapper {
        return answer_wrapper_choice(answer);
    }
    answer_scoped_choice(answer)
}

fn answer_wrapper_choice(answer: &Answer) -> ApprovalChoice {
    match answer {
        Answer::Single { id } => match id.as_str() {
            ID_APPROVE => ApprovalChoice::Approve(Scope::Once),
            ID_REJECT => ApprovalChoice::Deny,
            _ => ApprovalChoice::Deny,
        },
        _ => ApprovalChoice::Deny,
    }
}

fn answer_scoped_choice(answer: &Answer) -> ApprovalChoice {
    match answer {
        Answer::Single { id } => match id.as_str() {
            ID_APPROVE_ONCE => ApprovalChoice::Approve(Scope::Once),
            ID_APPROVE_SESSION => ApprovalChoice::Approve(Scope::Session),
            ID_APPROVE_PROJECT => ApprovalChoice::Approve(Scope::Project),
            ID_APPROVE_GLOBAL => ApprovalChoice::Approve(Scope::Global),
            ID_REJECT_ONCE => ApprovalChoice::Deny,
            ID_REJECT_SESSION => ApprovalChoice::Reject(Scope::Session),
            ID_REJECT_PROJECT => ApprovalChoice::Reject(Scope::Project),
            ID_REJECT_GLOBAL => ApprovalChoice::Reject(Scope::Global),
            _ => ApprovalChoice::Deny,
        },
        _ => ApprovalChoice::Deny,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyCode, KeyEventKind, KeyEventState, KeyModifiers};

    fn press(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: KeyModifiers::empty(),
            kind: KeyEventKind::Press,
            state: KeyEventState::empty(),
        }
    }

    /// Drain the resolved choice, asserting a result was produced.
    fn drain(d: &mut ApprovalDialog) -> ApprovalChoice {
        match d.take_result() {
            Some(ApprovalResult::Resolved { choice, .. }) => choice,
            None => panic!("expected a result"),
        }
    }

    #[test]
    fn full_variant_is_one_scoped_decision_page() {
        let d = ApprovalDialog::new(Uuid::new_v4(), "gh pr".into(), false, Duration::ZERO);
        assert_eq!(d.state().pages().len(), 1);
        let options = &d.state().pages()[0].options;
        assert_eq!(options.len(), 8);
        assert_eq!(options[0].label, "Approve once");
        assert_eq!(options[1].label, "Approve for this session");
        assert_eq!(options[2].label, "Approve for this project");
        assert_eq!(options[3].label, "Approve everywhere");
        assert_eq!(options[4].label, "Reject once");
        assert_eq!(options[5].label, "Reject for this session");
        assert_eq!(options[6].label, "Reject for this project");
        assert_eq!(options[7].label, "Reject everywhere");
    }

    #[test]
    fn both_pages_are_permission_pages() {
        // Both pages opt into the stripped presentation (no marker, no
        // free-text custom row).
        let d = ApprovalDialog::new(Uuid::new_v4(), "gh pr".into(), false, Duration::ZERO);
        for page in d.state().pages() {
            assert!(page.permission);
            assert!(
                !page.has_custom(),
                "permission page suppresses the free-text affordance"
            );
        }
    }

    #[test]
    fn wrapper_variant_is_one_page_two_once_verdicts() {
        let d = ApprovalDialog::new(Uuid::new_v4(), "bash".into(), true, Duration::ZERO);
        assert_eq!(d.state().pages().len(), 1, "wrapper is a single page");
        // `Approve once` / `Reject once` — both transient.
        assert_eq!(d.state().pages()[0].options.len(), 2);
        assert!(d.is_wrapper());
    }

    #[test]
    fn approve_session_resolves_from_first_surface() {
        let iid = Uuid::new_v4();
        let mut d = ApprovalDialog::new(iid, "gh pr".into(), false, Duration::ZERO);
        d.handle_key(press(KeyCode::Char('j')));
        assert!(d.handle_key(press(KeyCode::Enter)));
        assert_eq!(drain(&mut d), ApprovalChoice::Approve(Scope::Session));
    }

    #[test]
    fn reject_project_resolves_from_first_surface() {
        let iid = Uuid::new_v4();
        let mut d = ApprovalDialog::new(iid, "gh pr".into(), false, Duration::ZERO);
        for _ in 0..6 {
            d.handle_key(press(KeyCode::Char('j')));
        }
        assert!(d.handle_key(press(KeyCode::Enter)));
        assert_eq!(drain(&mut d), ApprovalChoice::Reject(Scope::Project));
    }

    #[test]
    fn reject_once_is_treated_as_deny() {
        // `Reject(Once)` is the explicit-menu equivalent of Esc: deny this
        // invocation, persist nothing.
        let iid = Uuid::new_v4();
        let mut d = ApprovalDialog::new(iid, "rm".into(), false, Duration::ZERO);
        for _ in 0..4 {
            d.handle_key(press(KeyCode::Char('j')));
        }
        assert!(d.handle_key(press(KeyCode::Enter)));
        assert_eq!(drain(&mut d), ApprovalChoice::Deny);
    }

    #[test]
    fn esc_on_verdict_page_denies() {
        let iid = Uuid::new_v4();
        let mut d = ApprovalDialog::new(iid, "rm".into(), false, Duration::ZERO);
        assert!(d.handle_key(press(KeyCode::Esc)));
        assert_eq!(drain(&mut d), ApprovalChoice::Deny);
    }

    #[test]
    fn unknown_answer_denies() {
        let choice = answers_to_choice(
            &[Answer::Single {
                id: "not-an-approval-choice".into(),
            }],
            false,
        );
        assert_eq!(choice, ApprovalChoice::Deny);
        let d = ApprovalDialog::new(Uuid::new_v4(), "rm".into(), false, Duration::ZERO);
        assert_eq!(d.state().current_page(), 0);
    }

    #[test]
    fn wrapper_approve_once_resolves_to_approve_once() {
        let iid = Uuid::new_v4();
        let mut d = ApprovalDialog::new(iid, "bash".into(), true, Duration::ZERO);
        // Single page, first option = `Approve once` → fast-path submit.
        assert!(d.handle_key(press(KeyCode::Enter)));
        assert_eq!(drain(&mut d), ApprovalChoice::Approve(Scope::Once));
    }

    #[test]
    fn wrapper_reject_once_is_treated_as_deny() {
        let iid = Uuid::new_v4();
        let mut d = ApprovalDialog::new(iid, "bash".into(), true, Duration::ZERO);
        // Second option = `Reject once` → fast-path submit → Deny.
        d.handle_key(press(KeyCode::Char('j')));
        assert!(d.handle_key(press(KeyCode::Enter)));
        assert_eq!(drain(&mut d), ApprovalChoice::Deny);
    }
}
