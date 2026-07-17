//! Command-approval & escalation subsystem (sandboxing, part 1 of 2).
//!
//! The reusable layer that decides *whether a shell command or path is
//! already approved* and *prompts the user when it isn't* — the
//! "ask-and-remember" machinery the filesystem-sandbox (part 2) consumes
//! via the run-fail-escalate model. This part ships **no confinement**;
//! it's the deterministic classifier ([`classify`]), the grant store
//! ([`store`]), and the prompt orchestration here.
//!
//! ## The four public entry points part 2 calls
//!
//! 1. [`classify::classify`] — parse a command string into its simple
//!    commands + approval keys + wrapper flag (pure, sync).
//! 2. [`GrantStore::is_command_granted`] / [`GrantStore::is_path_granted`]
//!    — query the store for the current session/project/global context
//!    (pure-ish, sync — DB + file reads, no blocking on the user).
//! 3. [`Approver::approve_command`] / [`Approver::approve_path`] — the
//!    full decision: query the store, and if not already granted, raise
//!    the approval prompt through the existing [`InterruptHub`], block on
//!    the answer, record the grant at the chosen scope, and return the
//!    decision.
//!
//! ## How the prompt reuses the existing interrupt path
//!
//! The prompt is **not** a parallel mechanism. It raises an
//! [`InterruptQuestion::Single`] (one scope-select question) through the
//! exact same path the `question` tool uses: persist via
//! [`Db::raise_interrupt_questions`], [`InterruptHub::register`] a
//! wakeup, [`InterruptHub::emit_raised`] to attached clients, then block
//! on [`PendingInterrupt::wait`]. The TUI renders it with
//! [`crate::tui::dialog::question::QuestionDialog`] over the shared
//! [`crate::tui::dialog::DialogState`]. The resolved option id maps back
//! to a [`Scope`]; a non-`Once` choice records the grant *before* the
//! decision returns.
//!
//! [`InterruptHub`]: crate::engine::interrupt::InterruptHub
//! [`Db::raise_interrupt_questions`]: crate::db::Db
//! [`PendingInterrupt::wait`]: crate::engine::interrupt::PendingInterrupt::wait

pub mod classify;
pub mod store;

mod command;
mod paths;
mod policy;
mod prompt;

use std::sync::Arc;

use anyhow::Result;

use crate::approval::classify::{Classification, RiskTier, SimpleCommandInfo};
use crate::approval::store::{GrantKind, GrantStore, LoopVerdict, Scope};
use crate::daemon::proto::{
    CharSpan, CommandDetail, InterruptOption, InterruptQuestion, InterruptQuestionSet,
    ResolveResponse, SandboxEscalation, WriteContentPreview,
};
use crate::engine::interrupt::InterruptHub;

/// Stable option ids for approval prompts. These are approval-domain ids that
/// ride through generic interrupt answers; the TUI renders them generically.
pub const ID_APPROVE: &str = "approve";
pub const ID_REJECT: &str = "reject";
pub const ID_APPROVE_ONCE: &str = "approve_once";
pub const ID_APPROVE_SESSION: &str = "approve_session";
pub const ID_APPROVE_PROJECT: &str = "approve_project";
pub const ID_APPROVE_GLOBAL: &str = "approve_global";
pub const ID_REJECT_SESSION: &str = "reject_session";
pub const ID_REJECT_PROJECT: &str = "reject_project";
pub const ID_REJECT_GLOBAL: &str = "reject_global";
pub const ID_MORE_OPTIONS: &str = "more_options";
pub const ID_APPROVE_ALL_ONCE: &str = "approve_all_once";
pub const ID_ESCALATE_GRANT_SESSION: &str = "escalate_grant_session";
pub const ID_ESCALATE_GRANT_PROJECT: &str = "escalate_grant_project";
pub const ID_ESCALATE_GRANT_GLOBAL: &str = "escalate_grant_global";
pub const ID_ESCALATE_RUN_UNCONFINED_ONCE: &str = "escalate_run_unconfined_once";
pub const ID_ONCE: &str = "once";
pub const ID_SESSION: &str = "session";
pub const ID_PROJECT: &str = "project";
pub const ID_LOOP_ACCEPT_ONCE: &str = "loop_accept_once";
pub const ID_LOOP_REJECT_ONCE: &str = "loop_reject_once";
pub const ID_LOOP_ACCEPT_SESSION: &str = "loop_accept_session";
pub const ID_LOOP_REJECT_SESSION: &str = "loop_reject_session";
pub const ID_LOOP_ACCEPT_PROJECT: &str = "loop_accept_project";
pub const ID_LOOP_REJECT_PROJECT: &str = "loop_reject_project";
pub const ID_GITIGNORE_FILE: &str = "gitignore_file";
pub const ID_GITIGNORE_PARENT: &str = "gitignore_parent";
pub const ID_GITIGNORE_REJECT: &str = "gitignore_reject";

/// The decision a prompt (or an already-granted query) produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Access is allowed. `scope` is `Once` when it was approved for this
    /// invocation only (or was a wrapper), or the scope it was recorded
    /// at / found already granted under.
    Allow { scope: Scope },
    /// Access is denied (the user dismissed the prompt).
    Deny,
    /// A `cockpit run` client denied the parked decision in-process. Tool
    /// callers preserve this distinction so the model receives the stable
    /// noninteractive denial instead of generic interactive-dismissal copy.
    NoninteractiveDeny,
}

/// Model-readable denial returned when a headless run resolves an approval
/// instead of leaving the engine parked forever.
pub(crate) const NONINTERACTIVE_RUN_DENIAL: &str =
    "noninteractive run: approval auto-denied; re-run with --approve <class> or use the TUI";

impl Decision {
    pub fn is_allowed(&self) -> bool {
        matches!(self, Decision::Allow { .. })
    }
}

/// How an approval decision was reached. The `permission_decision` event's
/// `source` field; lets a log reviewer tell a store-shortcut from a real
/// user answer, a headless auto-reject, or a standing loop-guard rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecisionSource {
    /// Short-circuited because the grant was already recorded at an
    /// applicable scope (the store query said yes; no prompt was raised).
    AlreadyGranted,
    /// A prompt was raised and the user answered it (allow at a scope, or
    /// dismiss → deny).
    UserPrompt,
    /// No interactive client to answer → auto-rejected without blocking.
    HeadlessAutoReject,
    /// A standing loop-guard always-accept/always-reject rule decided it
    /// without prompting.
    LoopGuardRule,
    /// A standing user **reject** grant (command or path) auto-denied the
    /// access without prompting — the mirror of `AlreadyGranted`. The
    /// timeline reflects a reject decision and its scope, not a plain deny
    /// (wire-vs-user split, §14).
    StandingReject,
}

impl DecisionSource {
    fn as_str(self) -> &'static str {
        match self {
            DecisionSource::AlreadyGranted => "already_granted",
            DecisionSource::UserPrompt => "user_prompt",
            DecisionSource::HeadlessAutoReject => "headless_auto_reject",
            DecisionSource::LoopGuardRule => "loop_guard_rule",
            DecisionSource::StandingReject => "standing_reject",
        }
    }
}

/// The loop-guard's verdict on a back-to-back identical tool call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepeatDecision {
    /// Run the repeated call (one-off accept or an always-accept rule).
    Accept,
    /// Block the repeated call; the dispatcher returns the guidance error
    /// as the tool result so the model changes course.
    Reject,
}

impl RepeatDecision {
    pub fn is_accept(&self) -> bool {
        matches!(self, RepeatDecision::Accept)
    }
}

/// Drives the approve-or-prompt decision. Holds the grant store plus the
/// bits needed to raise an interrupt: the session/agent identity, the
/// DB (to persist the interrupt), and the shared [`InterruptHub`].
pub struct Approver {
    store: GrantStore,
    db: crate::db::Db,
    session_id: uuid::Uuid,
    agent_id: String,
    interrupts: Arc<InterruptHub>,
}

impl Approver {}

/// The user's scoped approval choice — the in-crate twin of the TUI dialog's
/// `ApprovalChoice`, kept here so the public API doesn't depend on the
/// `tui` module shape. `Reject(scope)` persists a standing reject at the
/// chosen scope (`Reject(Once)` is the menu equivalent of Esc — deny this
/// invocation, persist nothing — and is mapped to `Deny`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ApprovalChoice {
    Approve(Scope),
    ApproveAllOnce,
    GrantPaths(Scope),
    Reject(Scope),
    Deny,
    NoninteractiveDeny,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxEscalationGrantOffer {
    pub paths: Vec<std::path::PathBuf>,
    pub access: crate::tools::shell_sandbox::SandboxPathAccess,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SandboxEscalationApproval {
    GrantAndRetryConfined { scope: Scope },
    RunUnconfinedOnce,
    Deny,
    NoninteractiveDeny,
}

/// The user's choice on a loop-guard prompt. `Always` carries the verdict
/// and the scope to persist it at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RepeatChoice {
    AcceptOnce,
    RejectOnce,
    Always { verdict: LoopVerdict, scope: Scope },
}

/// The resolved verdict of a two-stage gitignore read approval
/// (implementation note). The read gate acts on it: a
/// rejection refuses the read and remembers it for the session; an approval
/// proceeds and records the chosen glob per the persistence choice (`once`
/// records nothing).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GitignoreReadOutcome {
    /// The read is allowed this once; persist nothing.
    ApproveOnce,
    /// The read is allowed; add `glob` to the in-memory session allowlist.
    ApproveSession { glob: String },
    /// The read is allowed; append `glob` to the project config allowlist.
    ApproveProject { glob: String },
    /// The user declined; refuse the read and remember the rejection.
    Reject,
    /// A noninteractive run resolved the prompt with its structured denial.
    NoninteractiveReject,
}

/// Stage-1 (scope) gitignore choice: the glob shape, or reject.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GitignoreShape {
    File,
    Parent,
    Reject,
    NoninteractiveReject,
}

/// Stage-2 (persistence) gitignore choice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GitignorePersistence {
    Once,
    Session,
    Project,
    Reject,
    NoninteractiveReject,
}

/// Extract the selected option id from a `Single` (or single-element `Batch`)
/// response; `None` for a cancel/other shape. Shared by the gitignore stages.
fn response_single_id(response: &ResolveResponse) -> Option<&str> {
    match response {
        ResolveResponse::Single { selected_id } => Some(selected_id.as_str()),
        ResolveResponse::Batch { responses } => match responses.first() {
            Some(ResolveResponse::Single { selected_id }) => Some(selected_id.as_str()),
            _ => None,
        },
        _ => None,
    }
}

/// Build the six-option loop-guard question. The options ride through the
/// generic interrupt; the answering dialog renders them with no
/// special-casing, exactly like a `question`-tool prompt.
fn repeat_question(tool: &str) -> InterruptQuestion {
    InterruptQuestion::Single {
        prompt: format!("`{tool}` repeated the previous call exactly — likely a loop. Run it?"),
        options: vec![
            opt(ID_LOOP_ACCEPT_ONCE, "Accept (once)"),
            opt(ID_LOOP_ACCEPT_PROJECT, "Always accept for this project"),
            opt(ID_REJECT, "Deny"),
            opt(ID_MORE_OPTIONS, "More options…"),
            secondary_opt(ID_LOOP_ACCEPT_SESSION, "Always accept for this session"),
            secondary_opt(ID_LOOP_REJECT_SESSION, "Always reject for this session"),
            secondary_opt(ID_LOOP_REJECT_PROJECT, "Always reject for this project"),
        ],
        // Fixed choices; no free-text.
        allow_freetext: false,
        // The loop-guard prompt carries no bash command-detail block.
        command_detail: None,
        // Loop-guard is a permission/approval prompt (accept/reject at a
        // scope) — stripped presentation, like the scope select.
        permission: true,
        approval_class: None,
        // The loop-guard prompt is never a sandbox-escalation.
        sandbox_escalation: None,
    }
}

/// Map a resolved interrupt response back to a loop-guard choice. An
/// unknown id, a non-`Single` response, or a `Cancel` reads as
/// reject-once — the safe default for a likely loop.
fn response_to_repeat_choice(response: &ResolveResponse) -> RepeatChoice {
    let id = match response {
        ResolveResponse::Single { selected_id } => selected_id.as_str(),
        ResolveResponse::Batch { responses } => match responses.first() {
            Some(ResolveResponse::Single { selected_id }) => selected_id.as_str(),
            _ => return RepeatChoice::RejectOnce,
        },
        _ => return RepeatChoice::RejectOnce,
    };
    match id {
        ID_LOOP_ACCEPT_ONCE => RepeatChoice::AcceptOnce,
        ID_REJECT | ID_LOOP_REJECT_ONCE => RepeatChoice::RejectOnce,
        ID_LOOP_ACCEPT_SESSION => RepeatChoice::Always {
            verdict: LoopVerdict::Accept,
            scope: Scope::Session,
        },
        ID_LOOP_REJECT_SESSION => RepeatChoice::Always {
            verdict: LoopVerdict::Reject,
            scope: Scope::Session,
        },
        ID_LOOP_ACCEPT_PROJECT => RepeatChoice::Always {
            verdict: LoopVerdict::Accept,
            scope: Scope::Project,
        },
        ID_LOOP_REJECT_PROJECT => RepeatChoice::Always {
            verdict: LoopVerdict::Reject,
            scope: Scope::Project,
        },
        _ => RepeatChoice::RejectOnce,
    }
}

/// Build the approval question. Normal approvals expose each scoped approve
/// and reject action on the first surface; wrappers offer only once-only
/// approve/reject because they are never persistable.
#[allow(clippy::too_many_arguments)] // The wire question has independent policy dimensions.
fn approval_question(
    label: &str,
    wrapper: bool,
    approval_class: GrantKind,
    prompt_override: Option<&str>,
    detail: Option<CommandDetail>,
    escalation: Option<SandboxEscalation>,
    offered_scopes: &[Scope],
    batch_count: Option<u32>,
) -> InterruptQuestion {
    // The escalation variant reframes the ask: the command already ran
    // confined and failed, so the question is "re-run WITHOUT the sandbox?"
    // — never "the sandbox blocked this" (zerobox gives no such signal).
    let prompt = if let Some(prompt) = prompt_override {
        prompt.to_string()
    } else {
        match (&escalation, wrapper) {
            (Some(_), true) => format!(
                "`{label}` failed while sandboxed. Re-run it without the sandbox? Wrappers can't be remembered — once only."
            ),
            (Some(_), false) => {
                format!("`{label}` failed while sandboxed. Re-run it without the sandbox?")
            }
            (None, true) => format!("Run `{label}`? Wrappers can't be remembered."),
            (None, false) => format!("Run `{label}`?"),
        }
    };
    let options = if wrapper {
        // Both transient: a wrapper can only ever be approved/rejected once.
        vec![
            opt(ID_APPROVE, "Approve once"),
            opt(ID_REJECT, "Reject once"),
        ]
    } else {
        let mut options = scoped_approval_options(label, offered_scopes);
        if let Some(count) = batch_count.filter(|count| *count > 1) {
            options.insert(
                1,
                opt(
                    ID_APPROVE_ALL_ONCE,
                    &format!("Approve all {count} steps once"),
                ),
            );
        }
        options
    };
    InterruptQuestion::Single {
        prompt,
        options,
        // No free-text on an approval select — the choices are fixed.
        allow_freetext: false,
        command_detail: detail.map(Box::new),
        // Approval entry point #2: the approval select rides this `Single`.
        // Marking it a permission interrupt threads the stripped presentation
        // (no marker, no free-text) into the one render path.
        permission: true,
        approval_class: Some(approval_class),
        // Present only on the run-fail-escalate path; makes this the distinct
        // escalation variant the dialog renders specially.
        sandbox_escalation: escalation,
    }
}

/// Build the presentational command-detail block for one constituent.
/// `step`/`step_count` give the `step N of M` indicator; the highlight span
/// is omitted for a single-prompt command (no step indicator) so the dialog
/// shows the full command without an inline highlight. The span is also
/// dropped if it doesn't lie within the command's char length (defensive:
/// a stale/degenerate span must never produce a wrong highlight — the
/// silent-corruption hazard the project forbids).
fn command_detail(
    info: &SimpleCommandInfo,
    policy: &ApprovalPromptPolicy,
    full_command: &str,
    cwd: &std::path::Path,
    write_content: Option<WriteContentPreview>,
    step: u32,
    step_count: u32,
) -> Option<CommandDetail> {
    // Only highlight when there's more than one prompting constituent;
    // a lone prompt shows the full command with no step/highlight.
    let highlight = if step_count > 1 {
        info.span.and_then(|s| {
            let char_len = full_command.chars().count();
            if s.start <= s.end && s.end <= char_len {
                Some(CharSpan {
                    start: s.start as u32,
                    end: s.end as u32,
                })
            } else {
                None
            }
        })
    } else {
        None
    };
    let offered_scope_keys: Vec<String> = policy
        .offered_scopes
        .iter()
        .map(|scope| scope.as_str().to_string())
        .collect();
    let remembered_key = (!info.wrapper
        && policy
            .offered_scopes
            .iter()
            .any(|scope| !matches!(scope, Scope::Once)))
    .then(|| info.key.as_storage_str());
    Some(CommandDetail {
        full_command: full_command.to_string(),
        highlight,
        step,
        step_count,
        cwd: Some(cwd.display().to_string()),
        remembered_key,
        write_content,
        risk_tier: Some(info.risk.tier.as_str().to_string()),
        risk_reasons: info.risk.reasons.clone(),
        affected_targets: info.risk.affected_paths.clone(),
        native_tool_hints: info.risk.native_tool_hints.clone(),
        offered_scopes: offered_scope_keys,
        policy_cap: Some(policy.max_scope.as_str().to_string()),
    })
}

fn command_description_suffix(cd: &CommandDetail) -> String {
    let cwd = cd
        .cwd
        .as_deref()
        .map(|cwd| format!(" (in {cwd})"))
        .unwrap_or_default();
    if cd.step_count > 1 {
        format!(
            " — `{}` (step {} of {}){cwd}",
            cd.full_command, cd.step, cd.step_count
        )
    } else {
        format!(" — `{}`{cwd}", cd.full_command)
    }
}

fn path_access_label(required: crate::tools::shell_sandbox::SandboxPathAccess) -> &'static str {
    match required {
        crate::tools::shell_sandbox::SandboxPathAccess::Read => "read",
        crate::tools::shell_sandbox::SandboxPathAccess::ReadWrite => "read-write",
    }
}

fn path_prompt_label(
    path: &str,
    required: crate::tools::shell_sandbox::SandboxPathAccess,
) -> String {
    format!("{} access to {path}", path_access_label(required))
}

fn path_prompt_description(
    path: &str,
    required: crate::tools::shell_sandbox::SandboxPathAccess,
) -> String {
    format!("Allow {} access to {path}?", path_access_label(required))
}

fn shell_write_command_detail(
    full_command: &str,
    cwd: &std::path::Path,
    targets: &[std::path::PathBuf],
    preview: WriteContentPreview,
) -> CommandDetail {
    CommandDetail {
        full_command: full_command.to_string(),
        highlight: None,
        step: 1,
        step_count: 1,
        cwd: Some(cwd.display().to_string()),
        remembered_key: None,
        write_content: Some(preview),
        risk_tier: Some("mutating".to_string()),
        risk_reasons: vec!["writes shell redirect target".to_string()],
        affected_targets: targets.iter().map(|p| p.display().to_string()).collect(),
        native_tool_hints: Vec::new(),
        offered_scopes: vec![
            Scope::Once.as_str().to_string(),
            Scope::Session.as_str().to_string(),
            Scope::Project.as_str().to_string(),
            Scope::Global.as_str().to_string(),
        ],
        policy_cap: Some(Scope::Global.as_str().to_string()),
    }
}

fn prompt_description(
    label: &str,
    wrapper: bool,
    detail: Option<&CommandDetail>,
    escalation: Option<&SandboxEscalation>,
) -> String {
    // Include the full command (and step indicator) so headless / log
    // surfaces aren't worse off than the TUI.
    let suffix = detail.map(command_description_suffix).unwrap_or_default();
    // The escalation variant: state honestly that it failed WHILE sandboxed
    // (not that the sandbox blocked it — zerobox is a silent deny) and carry
    // the confined exit + stderr so a non-TUI surface isn't worse off.
    if let Some(esc) = escalation {
        let stderr = if esc.confined_stderr.trim().is_empty() {
            String::new()
        } else {
            format!("; stderr: {}", esc.confined_stderr.trim())
        };
        let scope = if wrapper {
            " (wrapper — once only)"
        } else {
            ""
        };
        return format!(
            "`{label}` failed while sandboxed (exit {}{stderr}). Re-run without the sandbox?{scope}{suffix}",
            esc.confined_exit
        );
    }
    if wrapper {
        format!("Approve wrapper `{label}` (once only){suffix}?")
    } else {
        format!("Approve `{label}`{suffix}?")
    }
}

fn opt(id: &str, label: &str) -> InterruptOption {
    InterruptOption {
        id: id.to_string(),
        label: label.to_string(),
        description: None,
        secondary: false,
    }
}

fn secondary_opt(id: &str, label: &str) -> InterruptOption {
    let mut option = opt(id, label);
    option.secondary = true;
    option
}

fn scoped_approval_options(label: &str, scopes: &[Scope]) -> Vec<InterruptOption> {
    let remember = if scopes.contains(&Scope::Project) {
        Some(Scope::Project)
    } else if scopes.contains(&Scope::Session) {
        Some(Scope::Session)
    } else {
        None
    };
    let mut options = vec![opt(ID_APPROVE_ONCE, "Approve once")];
    if let Some(scope) = remember {
        options.push(opt(
            match scope {
                Scope::Session => ID_APPROVE_SESSION,
                Scope::Project => ID_APPROVE_PROJECT,
                _ => unreachable!(),
            },
            &format!("Approve `{label}` for {}", scope_label(scope)),
        ));
    }
    options.push(opt(ID_REJECT, "Deny"));

    let mut secondary = Vec::new();
    for scope in scopes.iter().copied().filter(|scope| *scope != Scope::Once) {
        if Some(scope) != remember {
            secondary.push(secondary_opt(
                match scope {
                    Scope::Session => ID_APPROVE_SESSION,
                    Scope::Project => ID_APPROVE_PROJECT,
                    Scope::Global => ID_APPROVE_GLOBAL,
                    Scope::Once => unreachable!(),
                },
                &format!("Approve `{label}` for {}", scope_label(scope)),
            ));
        }
        secondary.push(secondary_opt(
            match scope {
                Scope::Session => ID_REJECT_SESSION,
                Scope::Project => ID_REJECT_PROJECT,
                Scope::Global => ID_REJECT_GLOBAL,
                Scope::Once => unreachable!(),
            },
            &format!("Reject `{label}` for {}", scope_label(scope)),
        ));
    }
    if !secondary.is_empty() {
        options.push(opt(ID_MORE_OPTIONS, "More options…"));
        options.extend(secondary);
    }
    options
}

fn scope_label(scope: Scope) -> &'static str {
    match scope {
        Scope::Once => "once",
        Scope::Session => "this session",
        Scope::Project => "this project",
        Scope::Global => "everywhere",
    }
}

/// Map the single approval response back to the final choice. A cancel,
/// unknown id, or non-`Single` shape reads as deny-once.
fn response_to_approval_choice(response: &ResolveResponse, wrapper: bool) -> ApprovalChoice {
    if matches!(
        response,
        ResolveResponse::Freetext { text } if text == NONINTERACTIVE_RUN_DENIAL
    ) {
        return ApprovalChoice::NoninteractiveDeny;
    }
    let Some(id) = response_single_id(response) else {
        return ApprovalChoice::Deny;
    };
    if wrapper {
        return match id {
            ID_APPROVE => ApprovalChoice::Approve(Scope::Once),
            ID_REJECT => ApprovalChoice::Deny,
            _ => ApprovalChoice::Deny,
        };
    }
    match id {
        ID_APPROVE_ONCE => ApprovalChoice::Approve(Scope::Once),
        ID_APPROVE_SESSION => ApprovalChoice::Approve(Scope::Session),
        ID_APPROVE_PROJECT => ApprovalChoice::Approve(Scope::Project),
        ID_APPROVE_GLOBAL => ApprovalChoice::Approve(Scope::Global),
        ID_APPROVE_ALL_ONCE => ApprovalChoice::ApproveAllOnce,
        ID_ESCALATE_GRANT_SESSION => ApprovalChoice::GrantPaths(Scope::Session),
        ID_ESCALATE_GRANT_PROJECT => ApprovalChoice::GrantPaths(Scope::Project),
        ID_ESCALATE_GRANT_GLOBAL => ApprovalChoice::GrantPaths(Scope::Global),
        ID_ESCALATE_RUN_UNCONFINED_ONCE => ApprovalChoice::Approve(Scope::Once),
        ID_REJECT => ApprovalChoice::Deny,
        ID_REJECT_SESSION => ApprovalChoice::Reject(Scope::Session),
        ID_REJECT_PROJECT => ApprovalChoice::Reject(Scope::Project),
        ID_REJECT_GLOBAL => ApprovalChoice::Reject(Scope::Global),
        _ => ApprovalChoice::Deny,
    }
}

/// Map a loop-guard repeat verdict onto the allow/deny shape the
/// `permission_decision` event records: accepting the repeat is an allow
/// (the chosen rule scope, when one was set, is persisted separately by the
/// store), rejecting it is a deny.
fn repeat_to_decision(repeat: RepeatDecision) -> Decision {
    match repeat {
        RepeatDecision::Accept => Decision::Allow { scope: Scope::Once },
        RepeatDecision::Reject => Decision::Deny,
    }
}

/// The scope set a command prompt offers, for the `permission_decision`
/// event's `offered_scopes`. A non-wrapper constituent offers all four
/// scopes; if **every** prompting constituent is a wrapper (never
/// persistable) the only choice is once-only. A mixed chain offers the full
/// set, since at least one prompt presented it.
#[derive(Debug, Clone)]
struct ApprovalPromptPolicy {
    max_scope: Scope,
    offered_scopes: Vec<Scope>,
}

impl ApprovalPromptPolicy {
    fn new(max_scope: Scope) -> Self {
        Self {
            max_scope,
            offered_scopes: scopes_through(max_scope),
        }
    }
}

#[derive(Debug, Clone)]
struct PermissionDecisionAudit {
    risk_tier: String,
    risk_reasons: Vec<String>,
    affected_targets: Vec<String>,
    native_tool_hints: Vec<String>,
    policy_cap: Scope,
}

impl PermissionDecisionAudit {
    fn from_prompting(prompting: &[(&SimpleCommandInfo, &ApprovalPromptPolicy)]) -> Self {
        let mut risk_tier = RiskTier::Ordinary;
        let mut risk_reasons = Vec::new();
        let mut affected_targets = Vec::new();
        let mut native_tool_hints = Vec::new();
        let mut policy_cap = Scope::Global;

        for (info, policy) in prompting {
            risk_tier = max_risk_tier(risk_tier, info.risk.tier);
            risk_reasons.extend(info.risk.reasons.clone());
            affected_targets.extend(info.risk.affected_paths.clone());
            native_tool_hints.extend(info.risk.native_tool_hints.clone());
            policy_cap = narrowest(policy_cap, policy.max_scope);
        }
        dedup_strings(&mut risk_reasons);
        dedup_strings(&mut affected_targets);
        dedup_strings(&mut native_tool_hints);
        Self {
            risk_tier: risk_tier.as_str().to_string(),
            risk_reasons,
            affected_targets,
            native_tool_hints,
            policy_cap,
        }
    }

    fn risk_json(&self) -> serde_json::Value {
        serde_json::json!({
            "tier": self.risk_tier,
            "reasons": self.risk_reasons,
            "affected_targets": self.affected_targets,
            "native_tool_hints": self.native_tool_hints,
        })
    }
}

fn approval_policy_for(
    info: &SimpleCommandInfo,
    cfg: &crate::config::extended::ApprovalPolicyConfig,
) -> ApprovalPromptPolicy {
    if info.wrapper {
        return ApprovalPromptPolicy::new(Scope::Once);
    }
    let key = info.key.as_storage_str();
    let max = cfg
        .key_max_scope
        .get(&key)
        .copied()
        .map(Scope::from)
        .or_else(|| {
            cfg.program_max_scope
                .get(&info.normalized_program)
                .copied()
                .map(Scope::from)
        })
        .or_else(|| {
            cfg.risk_max_scope
                .get(info.risk.tier.as_str())
                .copied()
                .map(Scope::from)
        })
        .unwrap_or_else(|| default_max_scope_for_risk(info.risk.tier));
    ApprovalPromptPolicy::new(max)
}

pub(crate) fn command_grant_allowed_by_policy(
    store: &GrantStore,
    info: &SimpleCommandInfo,
) -> bool {
    if info.wrapper {
        return false;
    }
    let policy = approval_policy_for(info, store.approval_policy());
    store
        .command_grant_scope(&info.key)
        .is_some_and(|scope| scope.within(policy.max_scope))
}

fn default_max_scope_for_risk(tier: RiskTier) -> Scope {
    match tier {
        RiskTier::Ordinary => Scope::Global,
        RiskTier::Mutating => Scope::Session,
        RiskTier::Destructive | RiskTier::Privileged | RiskTier::Dynamic => Scope::Once,
    }
}

fn scopes_through(max: Scope) -> Vec<Scope> {
    [Scope::Once, Scope::Session, Scope::Project, Scope::Global]
        .into_iter()
        .filter(|scope| scope.within(max))
        .collect()
}

fn offered_scopes(prompting: &[(&SimpleCommandInfo, &ApprovalPromptPolicy)]) -> Vec<Scope> {
    let mut scopes = Vec::new();
    for (_, policy) in prompting {
        for scope in &policy.offered_scopes {
            if !scopes.contains(scope) {
                scopes.push(*scope);
            }
        }
    }
    scopes
}

/// Narrower of two scopes (for reporting a chain's effective scope).
fn narrowest(a: Scope, b: Scope) -> Scope {
    if a.rank() <= b.rank() { a } else { b }
}

fn max_risk_tier(a: RiskTier, b: RiskTier) -> RiskTier {
    if risk_rank(a) >= risk_rank(b) { a } else { b }
}

fn risk_rank(tier: RiskTier) -> u8 {
    match tier {
        RiskTier::Ordinary => 0,
        RiskTier::Mutating => 1,
        RiskTier::Destructive => 2,
        RiskTier::Privileged => 3,
        RiskTier::Dynamic => 4,
    }
}

fn dedup_strings(values: &mut Vec<String>) {
    let mut seen = std::collections::HashSet::new();
    values.retain(|value| seen.insert(value.clone()));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::approval::classify::ApprovalKey;

    fn approver(cwd: &std::path::Path) -> (Approver, uuid::Uuid) {
        let db = crate::db::Db::open_in_memory().unwrap();
        let session =
            crate::session::Session::create(db.clone(), cwd.to_path_buf(), "builder").unwrap();
        let sid = session.id;
        let store = GrantStore::new(db.clone(), sid, cwd.to_path_buf());
        let hub = Arc::new(InterruptHub::detached());
        (Approver::new(store, db, sid, "builder", hub), sid)
    }

    /// All `permission_decision` events recorded for the approver's session,
    /// in `seq` order — the same rows the exporter folds into `events.json`.
    fn permission_events(approver: &Approver) -> Vec<serde_json::Value> {
        approver
            .db
            .list_session_events(approver.session_id)
            .unwrap()
            .into_iter()
            .filter(|e| e.kind == "permission_decision")
            .map(|e| e.data)
            .collect()
    }

    #[test]
    fn approval_policy_defaults_and_overrides_scope_caps() {
        let ordinary = classify::classify("gh pr create");
        let ordinary_info = &ordinary.simple_commands()[0];
        let default_cfg = crate::config::extended::ApprovalPolicyConfig::default();
        let ordinary_policy = approval_policy_for(ordinary_info, &default_cfg);
        assert_eq!(ordinary_policy.max_scope, Scope::Global);

        let rm = classify::classify("rm foo");
        let rm_info = &rm.simple_commands()[0];
        let rm_policy = approval_policy_for(rm_info, &default_cfg);
        assert_eq!(rm_policy.max_scope, Scope::Once);
        assert_eq!(rm_policy.offered_scopes, vec![Scope::Once]);

        let mkdir = classify::classify("mkdir logs");
        let mkdir_info = &mkdir.simple_commands()[0];
        let mkdir_policy = approval_policy_for(mkdir_info, &default_cfg);
        assert_eq!(mkdir_policy.max_scope, Scope::Session);
        assert_eq!(
            mkdir_policy.offered_scopes,
            vec![Scope::Once, Scope::Session]
        );

        let mut cfg = crate::config::extended::ApprovalPolicyConfig::default();
        cfg.risk_max_scope.insert(
            "destructive".to_string(),
            crate::config::extended::ApprovalPolicyScope::Session,
        );
        let widened = approval_policy_for(rm_info, &cfg);
        assert_eq!(widened.max_scope, Scope::Session);
    }

    #[test]
    fn approval_question_omits_scopes_above_policy_cap() {
        let q = approval_question(
            "rm foo",
            false,
            GrantKind::Command,
            None,
            None,
            None,
            &[Scope::Once],
            None,
        );
        let InterruptQuestion::Single { options, .. } = q else {
            panic!("expected single");
        };
        let ids: Vec<_> = options.iter().map(|option| option.id.as_str()).collect();
        assert_eq!(ids, vec![ID_APPROVE_ONCE, ID_REJECT]);

        let q = approval_question(
            "mkdir logs",
            false,
            GrantKind::Command,
            None,
            None,
            None,
            &[Scope::Once, Scope::Session],
            None,
        );
        let InterruptQuestion::Single { options, .. } = q else {
            panic!("expected single");
        };
        let ids: Vec<_> = options.iter().map(|option| option.id.as_str()).collect();
        assert_eq!(
            ids,
            vec![
                ID_APPROVE_ONCE,
                ID_APPROVE_SESSION,
                ID_REJECT,
                ID_MORE_OPTIONS,
                ID_REJECT_SESSION
            ]
        );
    }

    #[test]
    fn path_approval_prompt_uses_allow_wording() {
        let path = "/tmp/outside";
        let description = path_prompt_description(
            path,
            crate::tools::shell_sandbox::SandboxPathAccess::ReadWrite,
        );
        let q = approval_question(
            &path_prompt_label(
                path,
                crate::tools::shell_sandbox::SandboxPathAccess::ReadWrite,
            ),
            false,
            GrantKind::Path,
            Some(&description),
            None,
            None,
            &[Scope::Once],
            None,
        );
        let InterruptQuestion::Single { prompt, .. } = q else {
            panic!("expected single");
        };
        assert_eq!(prompt, "Allow read-write access to /tmp/outside?");

        let description =
            path_prompt_description(path, crate::tools::shell_sandbox::SandboxPathAccess::Read);
        let q = approval_question(
            &path_prompt_label(path, crate::tools::shell_sandbox::SandboxPathAccess::Read),
            false,
            GrantKind::Path,
            Some(&description),
            None,
            None,
            &[Scope::Once],
            None,
        );
        let InterruptQuestion::Single { prompt, .. } = q else {
            panic!("expected single");
        };
        assert_eq!(prompt, "Allow read access to /tmp/outside?");
    }

    #[test]
    fn approval_response_mapping_is_fail_closed_and_scope_exact() {
        assert_eq!(
            response_to_approval_choice(
                &ResolveResponse::Single {
                    selected_id: ID_APPROVE_PROJECT.to_string(),
                },
                false,
            ),
            ApprovalChoice::Approve(Scope::Project)
        );
        assert_eq!(
            response_to_approval_choice(
                &ResolveResponse::Batch {
                    responses: vec![ResolveResponse::Single {
                        selected_id: ID_REJECT_SESSION.to_string(),
                    }],
                },
                false,
            ),
            ApprovalChoice::Reject(Scope::Session)
        );
        assert_eq!(
            response_to_approval_choice(
                &ResolveResponse::Single {
                    selected_id: ID_APPROVE_GLOBAL.to_string(),
                },
                true,
            ),
            ApprovalChoice::Deny,
            "wrapper prompts cannot persist broader approval ids"
        );
        assert_eq!(
            response_to_approval_choice(&ResolveResponse::Cancel, false),
            ApprovalChoice::Deny
        );
        assert_eq!(
            response_to_approval_choice(
                &ResolveResponse::Single {
                    selected_id: "unknown".to_string(),
                },
                false,
            ),
            ApprovalChoice::Deny
        );
    }

    #[test]
    fn repeat_response_mapping_is_fail_closed_and_records_rule_scope() {
        assert_eq!(
            response_to_repeat_choice(&ResolveResponse::Single {
                selected_id: ID_LOOP_ACCEPT_ONCE.to_string(),
            }),
            RepeatChoice::AcceptOnce
        );
        assert_eq!(
            response_to_repeat_choice(&ResolveResponse::Single {
                selected_id: ID_LOOP_REJECT_PROJECT.to_string(),
            }),
            RepeatChoice::Always {
                verdict: LoopVerdict::Reject,
                scope: Scope::Project,
            }
        );
        assert_eq!(
            response_to_repeat_choice(&ResolveResponse::Batch {
                responses: vec![ResolveResponse::Single {
                    selected_id: ID_LOOP_ACCEPT_SESSION.to_string(),
                }],
            }),
            RepeatChoice::Always {
                verdict: LoopVerdict::Accept,
                scope: Scope::Session,
            }
        );
        assert_eq!(
            response_to_repeat_choice(&ResolveResponse::Cancel),
            RepeatChoice::RejectOnce
        );
        assert_eq!(
            response_to_repeat_choice(&ResolveResponse::Single {
                selected_id: "unknown".to_string(),
            }),
            RepeatChoice::RejectOnce
        );
    }

    /// Spawn a background resolver that answers a sequence of prompts in
    /// order: for each `id` in `ids`, it waits for the next not-yet-seen open
    /// interrupt and resolves it with `Single { selected_id: id }`.
    fn resolve_sequence(approver: &Approver, ids: &[&'static str]) -> tokio::task::JoinHandle<()> {
        let db = approver.db.clone();
        let session_id = approver.session_id;
        let hub = approver.interrupts.clone();
        let ids: Vec<&'static str> = ids.to_vec();
        tokio::spawn(async move {
            let mut seen: Vec<uuid::Uuid> = Vec::new();
            for id in ids {
                let iid = loop {
                    let open = db.list_open_interrupts(session_id).unwrap();
                    if let Some(row) = open.iter().find(|r| !seen.contains(&r.interrupt_id)) {
                        break row.interrupt_id;
                    }
                    tokio::task::yield_now().await;
                };
                seen.push(iid);
                assert!(hub.resolve(
                    iid,
                    ResolveResponse::Single {
                        selected_id: id.to_string(),
                    }
                ));
            }
        })
    }

    fn resolve_sequence_collecting_prompts(
        approver: &Approver,
        ids: &[&'static str],
    ) -> tokio::task::JoinHandle<Vec<String>> {
        let db = approver.db.clone();
        let session_id = approver.session_id;
        let hub = approver.interrupts.clone();
        let ids: Vec<&'static str> = ids.to_vec();
        tokio::spawn(async move {
            let mut seen: Vec<uuid::Uuid> = Vec::new();
            let mut prompts = Vec::new();
            for id in ids {
                let (iid, prompt) = loop {
                    let open = db.list_open_interrupts(session_id).unwrap();
                    if let Some(row) = open.iter().find(|r| !seen.contains(&r.interrupt_id)) {
                        let prompt = row
                            .questions
                            .as_ref()
                            .and_then(|set| set.questions.first())
                            .and_then(|question| match question {
                                InterruptQuestion::Single { prompt, .. } => Some(prompt.clone()),
                                _ => None,
                            })
                            .unwrap_or_default();
                        break (row.interrupt_id, prompt);
                    }
                    tokio::task::yield_now().await;
                };
                seen.push(iid);
                prompts.push(prompt);
                assert!(hub.resolve(
                    iid,
                    ResolveResponse::Single {
                        selected_id: id.to_string(),
                    }
                ));
            }
            prompts
        })
    }

    fn resolve_sequence_collecting_questions(
        approver: &Approver,
        ids: &[&'static str],
    ) -> tokio::task::JoinHandle<Vec<InterruptQuestion>> {
        let db = approver.db.clone();
        let session_id = approver.session_id;
        let hub = approver.interrupts.clone();
        let ids: Vec<&'static str> = ids.to_vec();
        tokio::spawn(async move {
            let mut seen: Vec<uuid::Uuid> = Vec::new();
            let mut questions = Vec::new();
            for id in ids {
                let (iid, question) = loop {
                    let open = db.list_open_interrupts(session_id).unwrap();
                    if let Some(row) = open.iter().find(|r| !seen.contains(&r.interrupt_id)) {
                        let question = row
                            .questions
                            .as_ref()
                            .and_then(|set| set.questions.first())
                            .cloned()
                            .expect("question recorded");
                        break (row.interrupt_id, question);
                    }
                    tokio::task::yield_now().await;
                };
                seen.push(iid);
                questions.push(question);
                assert!(hub.resolve(
                    iid,
                    ResolveResponse::Single {
                        selected_id: id.to_string(),
                    }
                ));
            }
            questions
        })
    }

    #[tokio::test]
    async fn sandbox_escalation_grant_prompt_records_path_and_retries_confined_choice() {
        let tmp = tempfile::tempdir().unwrap();
        let (approver, _) = approver(tmp.path());
        let path = tmp.path().join("cache");
        let offer = SandboxEscalationGrantOffer {
            paths: vec![path.clone()],
            access: crate::tools::shell_sandbox::SandboxPathAccess::Read,
        };
        let resolver =
            resolve_sequence_collecting_questions(&approver, &[ID_ESCALATE_GRANT_SESSION]);

        let decision = approver
            .approve_sandbox_escalation(
                "cat cache/data",
                13,
                "cat: Permission denied".into(),
                Some(&offer),
                None,
            )
            .await
            .unwrap();
        assert_eq!(
            decision,
            SandboxEscalationApproval::GrantAndRetryConfined {
                scope: Scope::Session
            }
        );
        let questions = resolver.await.unwrap();
        let InterruptQuestion::Single {
            options,
            sandbox_escalation,
            ..
        } = &questions[0]
        else {
            panic!("expected single question");
        };
        let ids: Vec<_> = options.iter().map(|option| option.id.as_str()).collect();
        assert!(ids.starts_with(&[ID_ESCALATE_GRANT_SESSION]));
        assert!(ids.contains(&ID_ESCALATE_RUN_UNCONFINED_ONCE));
        assert!(ids.contains(&ID_REJECT));
        let esc = sandbox_escalation.as_ref().expect("escalation detail");
        assert_eq!(esc.suggested_paths, vec![path.display().to_string()]);
        assert_eq!(esc.suggested_access.as_deref(), Some("read"));
        assert!(
            approver
                .store
                .is_path_granted_for(&path, crate::tools::shell_sandbox::SandboxPathAccess::Read),
            "session path grant recorded"
        );
        assert!(
            !approver.store.is_path_granted_for(
                &path,
                crate::tools::shell_sandbox::SandboxPathAccess::ReadWrite
            ),
            "read grant must not imply write"
        );
    }

    #[tokio::test]
    async fn sandbox_escalation_run_once_records_no_path_grant() {
        let tmp = tempfile::tempdir().unwrap();
        let (approver, _) = approver(tmp.path());
        let path = tmp.path().join("cache");
        let offer = SandboxEscalationGrantOffer {
            paths: vec![path.clone()],
            access: crate::tools::shell_sandbox::SandboxPathAccess::ReadWrite,
        };
        let resolver =
            resolve_sequence_collecting_questions(&approver, &[ID_ESCALATE_RUN_UNCONFINED_ONCE]);

        let decision = approver
            .approve_sandbox_escalation("cat cache/data", 13, "denied".into(), Some(&offer), None)
            .await
            .unwrap();
        assert_eq!(decision, SandboxEscalationApproval::RunUnconfinedOnce);
        resolver.await.unwrap();
        assert!(
            !approver.store.is_path_granted_for(
                &path,
                crate::tools::shell_sandbox::SandboxPathAccess::ReadWrite
            ),
            "run-once must not record durable path grants"
        );
    }

    #[tokio::test]
    async fn shell_heredoc_write_approval_names_concrete_path() {
        let tmp = tempfile::tempdir().unwrap();
        let (approver, _) = approver(tmp.path());
        let resolver = resolve_sequence_collecting_prompts(&approver, &[ID_APPROVE_ONCE]);
        let command = "cat > scratch/staged/x.md <<EOF\nbody\nEOF";

        let decision = approver.approve_command(command).await.unwrap();
        let prompts = resolver.await.unwrap();
        assert_eq!(decision, Decision::Allow { scope: Scope::Once });

        let target = tmp.path().join("scratch/staged/x.md").display().to_string();
        assert_eq!(prompts.len(), 1);
        assert!(prompts[0].contains(&target), "{prompts:?}");
        assert!(!prompts[0].contains("Run `/`"), "{prompts:?}");

        let events = permission_events(&approver);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["tool"], "path");
        assert_eq!(events[0]["target"], target);
    }

    #[tokio::test]
    async fn shell_redirection_and_tee_approvals_use_path_targets() {
        let tmp = tempfile::tempdir().unwrap();
        let (approver, _) = approver(tmp.path());
        let resolver =
            resolve_sequence_collecting_prompts(&approver, &[ID_APPROVE_ONCE, ID_APPROVE_ONCE]);

        let decision = approver
            .approve_command("printf x > nested/x.txt && tee scratch/staged/x.md")
            .await
            .unwrap();
        let prompts = resolver.await.unwrap();
        assert_eq!(decision, Decision::Allow { scope: Scope::Once });

        let nested = tmp.path().join("nested/x.txt").display().to_string();
        let tee = tmp.path().join("scratch/staged/x.md").display().to_string();
        assert_eq!(prompts.len(), 2);
        assert!(prompts[0].contains(&nested), "{prompts:?}");
        assert!(prompts[1].contains(&tee), "{prompts:?}");
        assert!(prompts.iter().all(|prompt| !prompt.contains("Run `/`")));

        let targets: Vec<_> = permission_events(&approver)
            .into_iter()
            .map(|event| event["target"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(targets, vec![nested, tee]);
        assert!(targets.iter().all(|target| target != "/"));
    }

    #[tokio::test]
    async fn safe_compound_batch_approval_is_once_only_and_records_no_grants() {
        let tmp = tempfile::tempdir().unwrap();
        let (approver, _) = approver(tmp.path());
        let resolver = resolve_sequence(&approver, &[ID_APPROVE_ALL_ONCE]);

        let decision = approver
            .approve_command("mkdir logs && touch logs/ready")
            .await
            .unwrap();
        resolver.await.unwrap();
        assert_eq!(decision, Decision::Allow { scope: Scope::Once });

        for key in [
            ApprovalKey {
                program: "mkdir".into(),
                subcommand: None,
            },
            ApprovalKey {
                program: "touch".into(),
                subcommand: None,
            },
        ] {
            assert!(!approver.store.is_command_granted(&key));
        }
    }

    #[tokio::test]
    async fn destructive_command_audit_records_risk_and_policy_fields() {
        let tmp = tempfile::tempdir().unwrap();
        let (approver, _) = approver(tmp.path());
        let resolver = resolve_sequence(&approver, &[ID_APPROVE_ONCE]);

        let decision = approver.approve_command("rm foo").await.unwrap();
        resolver.await.unwrap();

        assert_eq!(decision, Decision::Allow { scope: Scope::Once });
        let events = permission_events(&approver);
        assert_eq!(events.len(), 1);
        let ev = &events[0];
        assert_eq!(ev["tool"], "bash");
        assert_eq!(ev["offered_scopes"], serde_json::json!(["once"]));
        assert_eq!(ev["approval_risk"]["tier"], "destructive");
        assert_eq!(
            ev["approval_risk"]["affected_targets"],
            serde_json::json!(["foo"])
        );
        assert_eq!(ev["approval_policy"]["policy_cap"], "once");
    }

    #[tokio::test]
    async fn broad_existing_grant_above_policy_cap_does_not_skip_prompt() {
        let tmp = tempfile::tempdir().unwrap();
        let (approver, _) = approver(tmp.path());
        let info = classify::classify("rm foo").simple_commands()[0].clone();
        approver
            .store
            .record_command(&info, Scope::Session)
            .unwrap();
        assert_eq!(
            approver.store.command_grant_scope(&info.key),
            Some(Scope::Session)
        );

        let resolver = resolve_sequence(&approver, &[ID_APPROVE_ONCE]);
        let decision = approver.approve_command("rm foo").await.unwrap();
        resolver.await.unwrap();

        assert_eq!(decision, Decision::Allow { scope: Scope::Once });
        let events = permission_events(&approver);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["source"], "user_prompt");
        assert_eq!(events[0]["approval_policy"]["policy_cap"], "once");
    }

    #[tokio::test]
    async fn dynamic_shell_redirection_falls_back_to_command_approval() {
        let tmp = tempfile::tempdir().unwrap();
        let (approver, _) = approver(tmp.path());
        let resolver = resolve_sequence_collecting_prompts(&approver, &[ID_APPROVE_ONCE]);
        let command = r#"cat > "$OUT""#;

        let decision = approver.approve_command(command).await.unwrap();
        let prompts = resolver.await.unwrap();
        assert_eq!(decision, Decision::Allow { scope: Scope::Once });

        assert_eq!(prompts, vec!["Run `cat`?".to_string()]);
        let events = permission_events(&approver);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["tool"], "bash");
        assert_eq!(events[0]["target"], command);
    }

    #[tokio::test]
    async fn already_granted_command_skips_prompt() {
        let tmp = tempfile::tempdir().unwrap();
        let (approver, _) = approver(tmp.path());
        let info = SimpleCommandInfo {
            program: "cargo".into(),
            normalized_program: "cargo".into(),
            subcommand: Some("build".into()),
            key: ApprovalKey {
                program: "cargo".into(),
                subcommand: Some("build".into()),
            },
            wrapper: false,
            risk: Default::default(),
            span: None,
        };
        approver
            .store
            .record_command(&info, Scope::Session)
            .unwrap();
        // No client is attached; if this prompted it would block forever.
        // It returns immediately because the grant short-circuits.
        let decision = approver
            .approve_command("cargo build --release")
            .await
            .unwrap();
        assert!(decision.is_allowed());
    }

    // ---- permission_decision events (item #5) ----------------------------

    /// An already-granted command short-circuits with no prompt and records
    /// a `permission_decision` event with source `already_granted` — the
    /// `command_granted_broad`-equivalent path that fires on the next call
    /// after a session-scope approval.
    #[tokio::test]
    async fn already_granted_records_permission_decision() {
        let tmp = tempfile::tempdir().unwrap();
        let (approver, _) = approver(tmp.path());
        let info = SimpleCommandInfo {
            program: "cargo".into(),
            normalized_program: "cargo".into(),
            subcommand: Some("build".into()),
            key: ApprovalKey {
                program: "cargo".into(),
                subcommand: Some("build".into()),
            },
            wrapper: false,
            risk: Default::default(),
            span: None,
        };
        approver
            .store
            .record_command(&info, Scope::Session)
            .unwrap();
        let decision = approver
            .approve_command("cargo build --release")
            .await
            .unwrap();
        assert!(decision.is_allowed());

        let events = permission_events(&approver);
        assert_eq!(events.len(), 1, "one decision recorded");
        let ev = &events[0];
        assert_eq!(ev["tool"], "bash");
        assert_eq!(ev["target"], "cargo build --release");
        assert_eq!(ev["decision"], "allow");
        assert_eq!(ev["source"], "already_granted");
        // No prompt was raised → no scopes were offered.
        assert_eq!(ev["offered_scopes"], serde_json::json!([]));
        assert!(ev["tool_call_id"].is_null());
    }

    // ---- standing reject short-circuits (item #4) ------------------------

    /// A command rejected at a persisted scope is auto-denied on the next
    /// attempt with NO prompt (a detached hub would block forever if it
    /// prompted), recording a `permission_decision` with the new
    /// `standing_reject` source and an empty offered-scope set.
    #[tokio::test]
    async fn standing_command_reject_short_circuits_to_deny() {
        let tmp = tempfile::tempdir().unwrap();
        let (approver, _) = approver(tmp.path());
        let info = SimpleCommandInfo {
            program: "gh".into(),
            normalized_program: "gh".into(),
            subcommand: Some("pr".into()),
            key: ApprovalKey {
                program: "gh".into(),
                subcommand: Some("pr".into()),
            },
            wrapper: false,
            risk: Default::default(),
            span: None,
        };
        approver
            .store
            .record_command_reject(&info, Scope::Session)
            .unwrap();
        // No client attached: this returns immediately because the standing
        // reject short-circuits (it never raises a prompt).
        let decision = approver.approve_command("gh pr create").await.unwrap();
        assert_eq!(decision, Decision::Deny);

        let events = permission_events(&approver);
        assert_eq!(events.len(), 1, "one decision recorded");
        let ev = &events[0];
        assert_eq!(ev["tool"], "bash");
        assert_eq!(ev["target"], "gh pr create");
        assert_eq!(ev["decision"], "deny");
        assert_eq!(ev["source"], "standing_reject");
        assert!(ev["scope"].is_null(), "a deny carries no scope");
        // No prompt was raised → no scopes were offered.
        assert_eq!(ev["offered_scopes"], serde_json::json!([]));
    }

    /// The escalation path (`approve_command_escalated`) honors a standing
    /// reject: it returns `Deny` with no prompt — the caller keeps the
    /// confined failure rather than offering to broaden.
    #[tokio::test]
    async fn standing_reject_escalation_returns_deny_without_prompt() {
        let tmp = tempfile::tempdir().unwrap();
        let (approver, _) = approver(tmp.path());
        let info = SimpleCommandInfo {
            program: "cat".into(),
            normalized_program: "cat".into(),
            subcommand: None,
            key: ApprovalKey {
                program: "cat".into(),
                subcommand: None,
            },
            wrapper: false,
            risk: Default::default(),
            span: None,
        };
        approver
            .store
            .record_command_reject(&info, Scope::Session)
            .unwrap();
        let decision = approver
            .approve_command_escalated("cat /etc/secret", 13, "denied".into())
            .await
            .unwrap();
        assert_eq!(decision, Decision::Deny);
        let events = permission_events(&approver);
        assert_eq!(events.last().unwrap()["source"], "standing_reject");
    }

    /// A path rejected at a persisted scope auto-denies the out-of-cwd access
    /// with no prompt, recording `standing_reject`.
    #[tokio::test]
    async fn standing_path_reject_short_circuits_to_deny() {
        let tmp = tempfile::tempdir().unwrap();
        let (approver, _) = approver(tmp.path());
        let outside = tmp.path().join("outside.txt");
        approver
            .store
            .record_path_reject(&outside, Scope::Session)
            .unwrap();
        let decision = approver
            .approve_path(
                &outside,
                crate::tools::shell_sandbox::SandboxPathAccess::ReadWrite,
            )
            .await
            .unwrap();
        assert_eq!(decision, Decision::Deny);
        let events = permission_events(&approver);
        assert_eq!(events.len(), 1);
        let ev = &events[0];
        assert_eq!(ev["tool"], "path");
        assert_eq!(ev["decision"], "deny");
        assert_eq!(ev["source"], "standing_reject");
    }

    /// Interactively choosing Reject at a persistable scope records a standing
    /// command reject (verdict polarity preserved) and denies this invocation;
    /// a later attempt then short-circuits with no prompt.
    #[tokio::test]
    async fn interactive_reject_session_records_standing_reject() {
        let tmp = tempfile::tempdir().unwrap();
        let (approver, _) = approver(tmp.path());
        let resolver = resolve_sequence(&approver, &[ID_REJECT_SESSION]);
        let decision = approver.approve_command("gh pr create").await.unwrap();
        resolver.await.unwrap();
        assert_eq!(decision, Decision::Deny);

        // The standing reject persisted.
        let key = ApprovalKey {
            program: "gh".into(),
            subcommand: Some("pr".into()),
        };
        assert!(approver.store.is_command_rejected(&key));
        assert!(!approver.store.is_command_granted(&key));

        // A later attempt short-circuits with no prompt (detached hub).
        let again = approver.approve_command("gh pr create").await.unwrap();
        assert_eq!(again, Decision::Deny);
        let last = permission_events(&approver);
        assert_eq!(last.last().unwrap()["source"], "standing_reject");
    }

    /// Interactively choosing Deny persists nothing and denies this invocation only.
    #[tokio::test]
    async fn interactive_reject_once_persists_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let (approver, _) = approver(tmp.path());
        let resolver = resolve_sequence(&approver, &[ID_REJECT]);
        let decision = approver.approve_command("gh pr create").await.unwrap();
        resolver.await.unwrap();
        assert_eq!(decision, Decision::Deny);
        let key = ApprovalKey {
            program: "gh".into(),
            subcommand: Some("pr".into()),
        };
        assert!(
            !approver.store.is_command_rejected(&key),
            "once persists nothing"
        );
    }

    /// A dismissed command prompt records a `permission_decision` event whose
    /// `decision` is `deny`, with source `user_prompt` and the offered scope
    /// set the prompt presented.
    #[tokio::test]
    async fn denied_prompt_records_deny_permission_decision() {
        let tmp = tempfile::tempdir().unwrap();
        let (approver, _) = approver(tmp.path());
        let db = approver.db.clone();
        let session_id = approver.session_id;
        let hub = approver.interrupts.clone();
        let resolver = tokio::spawn(async move {
            let iid = loop {
                let open = db.list_open_interrupts(session_id).unwrap();
                if let Some(row) = open.first() {
                    break row.interrupt_id;
                }
                tokio::task::yield_now().await;
            };
            assert!(hub.resolve(iid, ResolveResponse::Cancel));
        });
        let decision = approver.approve_command("rm file").await.unwrap();
        resolver.await.unwrap();
        assert_eq!(decision, Decision::Deny);

        let events = permission_events(&approver);
        assert_eq!(events.len(), 1, "one decision recorded");
        let ev = &events[0];
        assert_eq!(ev["tool"], "bash");
        assert_eq!(ev["target"], "rm file");
        assert_eq!(ev["decision"], "deny");
        assert!(ev["scope"].is_null(), "a deny carries no scope");
        assert_eq!(ev["source"], "user_prompt");
        // A destructive command is capped to the once-only policy scope.
        assert_eq!(ev["offered_scopes"], serde_json::json!(["once"]));
    }

    /// Approving the package-add gate returns `Allow { Once }` and records a
    /// once-only `permission_decision` whose target is the exact clone URL.
    #[tokio::test]
    async fn package_add_approval_allows_once() {
        let tmp = tempfile::tempdir().unwrap();
        let (approver, _) = approver(tmp.path());
        let db = approver.db.clone();
        let session_id = approver.session_id;
        let hub = approver.interrupts.clone();
        let resolver = tokio::spawn(async move {
            let iid = loop {
                let open = db.list_open_interrupts(session_id).unwrap();
                if let Some(row) = open.first() {
                    break row.interrupt_id;
                }
                tokio::task::yield_now().await;
            };
            assert!(hub.resolve(
                iid,
                ResolveResponse::Single {
                    selected_id: ID_ONCE.to_string()
                }
            ));
        });
        let decision = approver
            .approve_package_add(
                "cargo:tokio",
                "https://github.com/tokio-rs/tokio",
                "`tokio`'s official crates.io registry declares this repository.",
            )
            .await
            .unwrap();
        resolver.await.unwrap();
        assert_eq!(decision, Decision::Allow { scope: Scope::Once });

        let events = permission_events(&approver);
        assert_eq!(events.len(), 1, "one decision recorded");
        let ev = &events[0];
        assert_eq!(ev["tool"], "add-package");
        assert_eq!(ev["target"], "https://github.com/tokio-rs/tokio");
        assert_eq!(ev["decision"], "allow");
        assert_eq!(ev["scope"], "once");
        assert_eq!(ev["source"], "user_prompt");
        assert_eq!(ev["offered_scopes"], serde_json::json!(["once"]));
    }

    /// Dismissing the package-add gate denies the clone (no loop, no guess)
    /// and records a `deny` decision.
    #[tokio::test]
    async fn package_add_dismissal_denies() {
        let tmp = tempfile::tempdir().unwrap();
        let (approver, _) = approver(tmp.path());
        let db = approver.db.clone();
        let session_id = approver.session_id;
        let hub = approver.interrupts.clone();
        let resolver = tokio::spawn(async move {
            let iid = loop {
                let open = db.list_open_interrupts(session_id).unwrap();
                if let Some(row) = open.first() {
                    break row.interrupt_id;
                }
                tokio::task::yield_now().await;
            };
            assert!(hub.resolve(iid, ResolveResponse::Cancel));
        });
        let decision = approver
            .approve_package_add("cargo:tokio", "https://example.invalid/x", "grounded")
            .await
            .unwrap();
        resolver.await.unwrap();
        assert_eq!(decision, Decision::Deny);

        let events = permission_events(&approver);
        assert_eq!(events.len(), 1, "one decision recorded");
        let ev = &events[0];
        assert_eq!(ev["tool"], "add-package");
        assert_eq!(ev["decision"], "deny");
        assert!(ev["scope"].is_null(), "a deny carries no scope");
    }

    /// A headless loop-guard repeat (no interactive client, no standing rule)
    /// auto-rejects without blocking and records a `permission_decision`
    /// event with source `headless_auto_reject` and a `deny` decision.
    #[tokio::test]
    async fn headless_repeat_records_headless_auto_reject() {
        let tmp = tempfile::tempdir().unwrap();
        let (approver, _) = approver(tmp.path());
        let input = serde_json::json!({"path": "x"});
        let decision = approver
            .approve_repeat("read", &input, false)
            .await
            .unwrap();
        assert_eq!(decision, RepeatDecision::Reject);

        let events = permission_events(&approver);
        assert_eq!(events.len(), 1, "one decision recorded");
        let ev = &events[0];
        assert_eq!(ev["tool"], "read");
        assert_eq!(ev["target"], input.to_string());
        assert_eq!(ev["decision"], "deny");
        assert_eq!(ev["source"], "headless_auto_reject");
        assert_eq!(
            ev["offered_scopes"],
            serde_json::json!(["once", "session", "project"])
        );
    }

    /// A standing loop-guard rule resolves the repeat without prompting and
    /// records source `loop_guard_rule` with the rule's verdict.
    #[tokio::test]
    async fn loop_rule_records_loop_guard_rule_source() {
        let tmp = tempfile::tempdir().unwrap();
        let (approver, _) = approver(tmp.path());
        let input = serde_json::json!({"path": "y"});
        let sig = GrantStore::loop_signature("read", &input);
        approver
            .store
            .record_loop_rule(&sig, LoopVerdict::Accept, Scope::Session)
            .unwrap();
        let decision = approver
            .approve_repeat("read", &input, false)
            .await
            .unwrap();
        assert_eq!(decision, RepeatDecision::Accept);

        let events = permission_events(&approver);
        assert_eq!(events.len(), 1);
        let ev = &events[0];
        assert_eq!(ev["source"], "loop_guard_rule");
        assert_eq!(ev["decision"], "allow");
    }

    /// Pull the command-detail off the open interrupt with `iid`.
    fn open_command_detail(
        db: &crate::db::Db,
        sid: uuid::Uuid,
        iid: uuid::Uuid,
    ) -> Option<CommandDetail> {
        let open = db.list_open_interrupts(sid).unwrap();
        let row = open.iter().find(|r| r.interrupt_id == iid)?;
        let set = row.questions.as_ref()?;
        match set.questions.first()? {
            InterruptQuestion::Single { command_detail, .. } => command_detail
                .as_ref()
                .map(|detail| detail.as_ref().clone()),
            _ => None,
        }
    }

    #[tokio::test]
    async fn compound_prompts_carry_step_count_and_full_command() {
        // Neither constituent granted: two prompts, each with the full
        // command verbatim, `step 1 of 2` / `step 2 of 2`, and the active
        // constituent's highlight span. A "session" grant on the second
        // records the KEY (`cargo build`), not the full command.
        let tmp = tempfile::tempdir().unwrap();
        let (approver, _) = approver(tmp.path());
        let db = approver.db.clone();
        let sid = approver.session_id;
        let hub = approver.interrupts.clone();
        let cmd = "git push origin main && cargo build";

        let resolver = tokio::spawn(async move {
            // Each constituent now prompts in two stages: a VERDICT prompt
            // (which carries the command-detail step/highlight) then a SCOPE
            // prompt. `seen` tracks resolved interrupts so we always grab the
            // next new one.
            let mut seen: Vec<uuid::Uuid> = Vec::new();
            let next_new = |db: &crate::db::Db, seen: &[uuid::Uuid]| -> Option<uuid::Uuid> {
                let open = db.list_open_interrupts(sid).unwrap();
                open.iter()
                    .find(|r| !seen.contains(&r.interrupt_id))
                    .map(|r| r.interrupt_id)
            };

            // Constituent 1 — approval prompt: step 1 of 2, highlight over
            // "git push origin main".
            let iid = loop {
                if let Some(i) = next_new(&db, &seen) {
                    break i;
                }
                tokio::task::yield_now().await;
            };
            seen.push(iid);
            let cd =
                open_command_detail(&db, sid, iid).expect("approval prompt has command_detail");
            assert_eq!(cd.full_command, cmd);
            assert_eq!((cd.step, cd.step_count), (1, 2));
            let h = cd.highlight.expect("step 1 highlighted");
            let slice: String = cmd
                .chars()
                .skip(h.start as usize)
                .take((h.end - h.start) as usize)
                .collect();
            assert_eq!(slice, "git push origin main");
            assert!(hub.resolve(
                iid,
                ResolveResponse::Single {
                    selected_id: ID_APPROVE_ONCE.into(),
                }
            ));

            // Constituent 2 — approval prompt: step 2 of 2, highlight over
            // "cargo build".
            let iid2 = loop {
                if let Some(i) = next_new(&db, &seen) {
                    break i;
                }
                tokio::task::yield_now().await;
            };
            seen.push(iid2);
            let cd2 =
                open_command_detail(&db, sid, iid2).expect("approval prompt has command_detail");
            assert_eq!(cd2.full_command, cmd);
            assert_eq!((cd2.step, cd2.step_count), (2, 2));
            let h2 = cd2.highlight.expect("step 2 highlighted");
            let slice2: String = cmd
                .chars()
                .skip(h2.start as usize)
                .take((h2.end - h2.start) as usize)
                .collect();
            assert_eq!(slice2, "cargo build");
            assert!(hub.resolve(
                iid2,
                ResolveResponse::Single {
                    selected_id: ID_APPROVE_SESSION.into(),
                }
            ));
        });

        let decision = approver.approve_command(cmd).await.unwrap();
        resolver.await.unwrap();
        assert!(decision.is_allowed());

        // The grant recorded the KEY for the remembered constituent only.
        let cargo_key = ApprovalKey {
            program: "cargo".into(),
            subcommand: Some("build".into()),
        };
        assert!(
            approver.store.is_command_granted(&cargo_key),
            "remembered `cargo build` key"
        );
        // The once-approved git push was NOT remembered.
        let git_key = ApprovalKey {
            program: "git".into(),
            subcommand: Some("push".into()),
        };
        assert!(
            !approver.store.is_command_granted(&git_key),
            "`git push` was once-only, not stored"
        );
    }

    #[tokio::test]
    async fn granted_first_half_prompts_once_as_step_1_of_1() {
        // `git push origin main && cargo build` with `git push` already
        // granted: exactly one prompt, labelled step 1 of 1 (M counts only
        // prompting constituents), full command shown, no highlight.
        let tmp = tempfile::tempdir().unwrap();
        let (approver, _) = approver(tmp.path());
        // Pre-grant `git push`.
        let git_info = SimpleCommandInfo {
            program: "git".into(),
            normalized_program: "git".into(),
            subcommand: Some("push".into()),
            key: ApprovalKey {
                program: "git".into(),
                subcommand: Some("push".into()),
            },
            wrapper: false,
            risk: Default::default(),
            span: None,
        };
        approver
            .store
            .record_command(&git_info, Scope::Session)
            .unwrap();

        let db = approver.db.clone();
        let sid = approver.session_id;
        let hub = approver.interrupts.clone();
        let cmd = "git push origin main && cargo build";
        let resolver = tokio::spawn(async move {
            // Approval prompt carries the command-detail and resolves directly.
            let iid = loop {
                let open = db.list_open_interrupts(sid).unwrap();
                if let Some(row) = open.first() {
                    break row.interrupt_id;
                }
                tokio::task::yield_now().await;
            };
            let cd = open_command_detail(&db, sid, iid).expect("command_detail present");
            assert_eq!(cd.full_command, cmd);
            assert_eq!(
                (cd.step, cd.step_count),
                (1, 1),
                "M counts only prompting steps"
            );
            // Single prompting step → no highlight.
            assert!(cd.highlight.is_none(), "lone prompt is not highlighted");
            assert!(hub.resolve(
                iid,
                ResolveResponse::Single {
                    selected_id: ID_APPROVE_ONCE.into(),
                }
            ));
        });
        let decision = approver.approve_command(cmd).await.unwrap();
        resolver.await.unwrap();
        assert!(decision.is_allowed());
    }

    #[tokio::test]
    async fn wrapper_prompt_shows_full_command_once_only() {
        // A wrapper (`bash -c …`) offers only the once verdict forms (Approve
        // once / Reject once) on a single page, and still shows the full
        // command in the detail block.
        let tmp = tempfile::tempdir().unwrap();
        let (approver, _) = approver(tmp.path());
        let db = approver.db.clone();
        let sid = approver.session_id;
        let hub = approver.interrupts.clone();
        let cmd = "bash -c 'echo hi'";
        let resolver = tokio::spawn(async move {
            let iid = loop {
                let open = db.list_open_interrupts(sid).unwrap();
                if let Some(row) = open.first() {
                    break row.interrupt_id;
                }
                tokio::task::yield_now().await;
            };
            // Wrapper → two once-only verdict options, full command in detail.
            let open = db.list_open_interrupts(sid).unwrap();
            let set = open[0].questions.as_ref().unwrap();
            match set.questions.first().unwrap() {
                InterruptQuestion::Single {
                    options,
                    command_detail,
                    ..
                } => {
                    assert_eq!(
                        options.len(),
                        2,
                        "wrapper offers `Approve once` / `Reject once`"
                    );
                    assert_eq!(
                        command_detail.as_ref().unwrap().full_command,
                        cmd,
                        "wrapper shows the full command"
                    );
                }
                _ => panic!("expected Single"),
            }
            // Approve once: a wrapper resolves from this single prompt.
            assert!(hub.resolve(
                iid,
                ResolveResponse::Single {
                    selected_id: ID_APPROVE.into(),
                }
            ));
        });
        let decision = approver.approve_command(cmd).await.unwrap();
        resolver.await.unwrap();
        assert_eq!(decision, Decision::Allow { scope: Scope::Once });
    }

    #[test]
    fn prompt_description_includes_full_command() {
        // The persisted/headless description carries the full command + step.
        let detail = CommandDetail {
            full_command: "git push && cargo build".into(),
            highlight: None,
            step: 2,
            step_count: 2,
            cwd: None,
            remembered_key: None,
            write_content: None,
            risk_tier: None,
            risk_reasons: Vec::new(),
            affected_targets: Vec::new(),
            native_tool_hints: Vec::new(),
            offered_scopes: Vec::new(),
            policy_cap: None,
        };
        let desc = prompt_description("cargo build", false, Some(&detail), None);
        assert!(
            desc.contains("git push && cargo build"),
            "full command in desc"
        );
        assert!(desc.contains("step 2 of 2"), "step indicator in desc");
        // Single-step: no step indicator, but still the full command.
        let lone = CommandDetail {
            full_command: "cd /tmp".into(),
            highlight: None,
            step: 1,
            step_count: 1,
            cwd: None,
            remembered_key: None,
            write_content: None,
            risk_tier: None,
            risk_reasons: Vec::new(),
            affected_targets: Vec::new(),
            native_tool_hints: Vec::new(),
            offered_scopes: Vec::new(),
            policy_cap: None,
        };
        let desc = prompt_description("cd", false, Some(&lone), None);
        assert!(desc.contains("cd /tmp"));
        assert!(!desc.contains("step "));
    }

    #[test]
    fn escalation_description_is_honest_and_carries_confined_detail() {
        // The headless/log description for an escalation states it failed
        // WHILE sandboxed (never "blocked by the sandbox") and carries the
        // confined exit + stderr so non-TUI surfaces aren't worse off.
        let esc = SandboxEscalation {
            confined_exit: 101,
            confined_stderr: "cat: /etc/secret: Permission denied".into(),
            suggested_paths: Vec::new(),
            suggested_access: None,
        };
        let desc = prompt_description("cat", false, None, Some(&esc));
        assert!(
            desc.contains("failed while sandboxed"),
            "honest framing: {desc}"
        );
        assert!(
            !desc.to_lowercase().contains("blocked by the sandbox"),
            "must never assert the sandbox blocked it: {desc}"
        );
        assert!(desc.contains("exit 101"), "confined exit in desc: {desc}");
        assert!(
            desc.contains("Permission denied"),
            "confined stderr in desc: {desc}"
        );
        assert!(
            desc.contains("without the sandbox"),
            "the ask is the unconfined re-run: {desc}"
        );
    }

    #[test]
    fn command_detail_drops_out_of_range_span() {
        // A span beyond the command length is dropped, never used to slice
        // (defensive: no wrong highlight).
        let info = SimpleCommandInfo {
            program: "x".into(),
            normalized_program: "x".into(),
            subcommand: None,
            key: ApprovalKey {
                program: "x".into(),
                subcommand: None,
            },
            wrapper: false,
            risk: Default::default(),
            span: Some(crate::approval::classify::CharSpan { start: 2, end: 999 }),
        };
        let policy = ApprovalPromptPolicy::new(Scope::Global);
        let cd = command_detail(
            &info,
            &policy,
            "x && y",
            std::path::Path::new("."),
            None,
            2,
            2,
        )
        .unwrap();
        assert!(cd.highlight.is_none(), "out-of-range span dropped");
        assert_eq!((cd.step, cd.step_count), (2, 2));
    }

    #[tokio::test]
    async fn empty_command_is_denied_without_prompting() {
        let tmp = tempfile::tempdir().unwrap();
        let (approver, _) = approver(tmp.path());
        assert_eq!(approver.approve_command("").await.unwrap(), Decision::Deny);
        assert_eq!(
            approver.approve_command("   ").await.unwrap(),
            Decision::Deny
        );
    }

    #[tokio::test]
    async fn prompt_then_record_at_project_scope() {
        let tmp = tempfile::tempdir().unwrap();
        let (approver, _) = approver(tmp.path());
        // Point the store's scopes at the temp dir deterministically.
        // (The store resolves project root from cwd; tmp may not be a git
        // repo, so a Project record would error. Use Session here, which
        // needs no project root, and assert the prompt→record flow.)
        let resolver = resolve_sequence(&approver, &[ID_APPROVE_SESSION]);

        let decision = approver.approve_command("gh pr create").await.unwrap();
        resolver.await.unwrap();
        assert_eq!(
            decision,
            Decision::Allow {
                scope: Scope::Session
            }
        );
        // And it's now remembered.
        let key = ApprovalKey {
            program: "gh".into(),
            subcommand: Some("pr".into()),
        };
        assert!(approver.store.is_command_granted(&key));
    }

    #[tokio::test]
    async fn dismissed_prompt_denies() {
        let tmp = tempfile::tempdir().unwrap();
        let (approver, _) = approver(tmp.path());
        let db = approver.db.clone();
        let session_id = approver.session_id;
        let hub = approver.interrupts.clone();
        let resolver = tokio::spawn(async move {
            let iid = loop {
                let open = db.list_open_interrupts(session_id).unwrap();
                if let Some(row) = open.first() {
                    break row.interrupt_id;
                }
                tokio::task::yield_now().await;
            };
            assert!(hub.resolve(iid, ResolveResponse::Cancel));
        });
        let decision = approver.approve_command("rm file").await.unwrap();
        resolver.await.unwrap();
        assert_eq!(decision, Decision::Deny);
    }

    #[tokio::test]
    async fn wrapper_chain_command_prompts_and_is_not_remembered() {
        let tmp = tempfile::tempdir().unwrap();
        let (approver, _) = approver(tmp.path());
        // The user picks `Approve once`; a wrapper is never persistable.
        let resolver = resolve_sequence(&approver, &[ID_APPROVE]);
        let decision = approver.approve_command("bash -c 'echo hi'").await.unwrap();
        resolver.await.unwrap();
        assert_eq!(decision, Decision::Allow { scope: Scope::Once });
        // Wrapper key was NOT stored.
        let key = ApprovalKey {
            program: "bash".into(),
            subcommand: None,
        };
        assert!(!approver.store.is_command_granted(&key));
    }

    #[test]
    fn approval_response_mapping_round_trips_scoped_actions() {
        for (id, choice) in [
            (ID_APPROVE_ONCE, ApprovalChoice::Approve(Scope::Once)),
            (ID_APPROVE_SESSION, ApprovalChoice::Approve(Scope::Session)),
            (ID_APPROVE_PROJECT, ApprovalChoice::Approve(Scope::Project)),
            (ID_APPROVE_GLOBAL, ApprovalChoice::Approve(Scope::Global)),
            (ID_REJECT, ApprovalChoice::Deny),
            (ID_REJECT_SESSION, ApprovalChoice::Reject(Scope::Session)),
            (ID_REJECT_PROJECT, ApprovalChoice::Reject(Scope::Project)),
            (ID_REJECT_GLOBAL, ApprovalChoice::Reject(Scope::Global)),
        ] {
            let resp = ResolveResponse::Single {
                selected_id: id.into(),
            };
            assert_eq!(response_to_approval_choice(&resp, false), choice);
        }
        assert_eq!(
            response_to_approval_choice(&ResolveResponse::Cancel, false),
            ApprovalChoice::Deny
        );
    }

    #[test]
    fn wrapper_response_mapping_remains_once_only() {
        assert_eq!(
            response_to_approval_choice(
                &ResolveResponse::Single {
                    selected_id: ID_APPROVE.into(),
                },
                true
            ),
            ApprovalChoice::Approve(Scope::Once)
        );
        assert_eq!(
            response_to_approval_choice(
                &ResolveResponse::Single {
                    selected_id: ID_REJECT.into(),
                },
                true
            ),
            ApprovalChoice::Deny
        );
        assert_eq!(
            response_to_approval_choice(&ResolveResponse::Cancel, true),
            ApprovalChoice::Deny
        );
    }

    // ---- loop guard ------------------------------------------------------

    #[test]
    fn repeat_response_mapping_round_trips() {
        use crate::approval::{
            ID_LOOP_ACCEPT_ONCE, ID_LOOP_ACCEPT_PROJECT, ID_LOOP_ACCEPT_SESSION,
            ID_LOOP_REJECT_ONCE, ID_LOOP_REJECT_PROJECT, ID_LOOP_REJECT_SESSION,
        };
        let single = |id: &str| ResolveResponse::Single {
            selected_id: id.into(),
        };
        assert_eq!(
            response_to_repeat_choice(&single(ID_LOOP_ACCEPT_ONCE)),
            RepeatChoice::AcceptOnce
        );
        assert_eq!(
            response_to_repeat_choice(&single(ID_LOOP_REJECT_ONCE)),
            RepeatChoice::RejectOnce
        );
        assert_eq!(
            response_to_repeat_choice(&single(ID_LOOP_ACCEPT_SESSION)),
            RepeatChoice::Always {
                verdict: LoopVerdict::Accept,
                scope: Scope::Session
            }
        );
        assert_eq!(
            response_to_repeat_choice(&single(ID_LOOP_REJECT_SESSION)),
            RepeatChoice::Always {
                verdict: LoopVerdict::Reject,
                scope: Scope::Session
            }
        );
        assert_eq!(
            response_to_repeat_choice(&single(ID_LOOP_ACCEPT_PROJECT)),
            RepeatChoice::Always {
                verdict: LoopVerdict::Accept,
                scope: Scope::Project
            }
        );
        assert_eq!(
            response_to_repeat_choice(&single(ID_LOOP_REJECT_PROJECT)),
            RepeatChoice::Always {
                verdict: LoopVerdict::Reject,
                scope: Scope::Project
            }
        );
        // A dismissal reads as reject-once (safe default for a loop).
        assert_eq!(
            response_to_repeat_choice(&ResolveResponse::Cancel),
            RepeatChoice::RejectOnce
        );
    }

    #[tokio::test]
    async fn headless_repeat_with_no_rule_auto_rejects() {
        // No interactive client + no standing rule → reject without ever
        // raising a prompt (a detached hub would block forever if it did).
        let tmp = tempfile::tempdir().unwrap();
        let (approver, _) = approver(tmp.path());
        let decision = approver
            .approve_repeat("read", &serde_json::json!({"path": "x"}), false)
            .await
            .unwrap();
        assert_eq!(decision, RepeatDecision::Reject);
    }

    #[tokio::test]
    async fn headless_repeat_honors_always_accept_rule() {
        let tmp = tempfile::tempdir().unwrap();
        let (approver, _) = approver(tmp.path());
        let input = serde_json::json!({"path": "x"});
        let sig = GrantStore::loop_signature("read", &input);
        approver
            .store
            .record_loop_rule(&sig, LoopVerdict::Accept, Scope::Session)
            .unwrap();
        // Headless, but a session always-accept rule applies → accept.
        let decision = approver
            .approve_repeat("read", &input, false)
            .await
            .unwrap();
        assert_eq!(decision, RepeatDecision::Accept);
    }

    #[tokio::test]
    async fn headless_repeat_honors_always_reject_rule() {
        let tmp = tempfile::tempdir().unwrap();
        let (approver, _) = approver(tmp.path());
        let input = serde_json::json!({"path": "y"});
        let sig = GrantStore::loop_signature("bash", &input);
        approver
            .store
            .record_loop_rule(&sig, LoopVerdict::Reject, Scope::Session)
            .unwrap();
        let decision = approver
            .approve_repeat("bash", &input, false)
            .await
            .unwrap();
        assert_eq!(decision, RepeatDecision::Reject);
    }

    #[tokio::test]
    async fn interactive_repeat_accept_once_runs_but_records_no_rule() {
        let tmp = tempfile::tempdir().unwrap();
        let (approver, _) = approver(tmp.path());
        let db = approver.db.clone();
        let session_id = approver.session_id;
        let hub = approver.interrupts.clone();
        let resolver = tokio::spawn(async move {
            let iid = loop {
                let open = db.list_open_interrupts(session_id).unwrap();
                if let Some(row) = open.first() {
                    break row.interrupt_id;
                }
                tokio::task::yield_now().await;
            };
            assert!(hub.resolve(
                iid,
                ResolveResponse::Single {
                    selected_id: crate::approval::ID_LOOP_ACCEPT_ONCE.into(),
                }
            ));
        });
        let input = serde_json::json!({"path": "z"});
        let decision = approver.approve_repeat("read", &input, true).await.unwrap();
        resolver.await.unwrap();
        assert_eq!(decision, RepeatDecision::Accept);
        // Accept-once records no rule: a fresh query still has none.
        let sig = GrantStore::loop_signature("read", &input);
        assert!(approver.store.loop_rule(&sig).is_none());
    }

    #[tokio::test]
    async fn interactive_repeat_always_reject_session_records_rule() {
        let tmp = tempfile::tempdir().unwrap();
        let (approver, _) = approver(tmp.path());
        let db = approver.db.clone();
        let session_id = approver.session_id;
        let hub = approver.interrupts.clone();
        let resolver = tokio::spawn(async move {
            let iid = loop {
                let open = db.list_open_interrupts(session_id).unwrap();
                if let Some(row) = open.first() {
                    break row.interrupt_id;
                }
                tokio::task::yield_now().await;
            };
            assert!(hub.resolve(
                iid,
                ResolveResponse::Single {
                    selected_id: crate::approval::ID_LOOP_REJECT_SESSION.into(),
                }
            ));
        });
        let input = serde_json::json!({"command": "spin"});
        let decision = approver.approve_repeat("bash", &input, true).await.unwrap();
        resolver.await.unwrap();
        assert_eq!(decision, RepeatDecision::Reject);
        // The always-reject-session rule was persisted, so a later
        // (even headless) repeat of the exact signature auto-rejects with
        // no prompt.
        let sig = GrantStore::loop_signature("bash", &input);
        assert_eq!(approver.store.loop_rule(&sig), Some(LoopVerdict::Reject));
        let again = approver
            .approve_repeat("bash", &input, false)
            .await
            .unwrap();
        assert_eq!(again, RepeatDecision::Reject);
    }
}
