//! Descriptor-driven category settings pages — the reorganized `/settings`
//! body (implementation note).
//!
//! The old flat `UiPage` mixed display, behavior, privacy and translation
//! settings into one ~28-row list. It is split here into five cohesive
//! categories — **Interface**, **Behavior**, **Privacy & Safety**,
//! **Translation**, **Profile** — each rendered by one generic
//! [`CategoryPage`] driven by a list of [`Row`] descriptors. A descriptor
//! is either a section [`Row::Heading`] (used for the "Advanced" divider and
//! its blurb) or a [`Row::Setting`] naming a [`SettingId`]. The dialog reads
//! and writes `self.extended` by matching on the id, so there is exactly one
//! place per field that knows how to render and mutate it — no per-page
//! copy-paste, and adding a field is a one-line descriptor plus its arms.
//!
//! Each category carries a 1–3 sentence section intro and each setting a
//! plain-language description (`help`), shown in a side pane so the dialog
//! teaches the feature without external docs. The help text is decoupled
//! from layout: it lives on the [`SettingId`], not the row, so a future
//! on-focus help pane needs no copy rewrite.
//!
//! Validation lives with the mutation: numeric/text edits parse + clamp (or
//! reject with an inline reason) before anything is persisted. Enum cycles
//! drive their option set from the config enum's own `cycled()`, never a
//! hardcoded list, so roster changes are reflected automatically.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::PathBuf;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Wrap};

use crate::tui::dir_suggest::{DIR_SUGGEST_WINDOW, DirSuggestion, PathSuggestMode, suggest_paths};
use crate::tui::textfield::TextField;
use crate::tui::vim_editor::{VimEditor, VimEditorOutcome};
use cockpit_config::extended::{
    ApprovalMode, Concurrency, DefaultPrimaryAgent, DiffStyle, InjectionResultAction,
    InjectionThreshold, LlmMode, PredictNextMessage, ShellCompression, TextEmbeddedRecovery,
    ThinkingDisplay, TuiConfig, VimModeSetting,
};
use cockpit_core::tools::command_resource_profiles::{
    GO_TOOLCHAIN, JAVA_TOOLCHAIN, NODE_PACKAGE_MANAGER, PYTHON_TOOLCHAIN, RUST_TOOLCHAIN,
};

use super::descriptor::{FieldKind, SettingDescriptor, SettingHeading, SettingStore};
use super::reset::{ResetButton, ResetOutcome};
use super::secret_display;
use super::shell::{
    PointerOperationGate, PointerOperationId, SettingsPointerAction, SettingsPointerSurface,
    SettingsPointerTarget, TextColumnLayout, heading_style, muted_style, push_label_text_field_row,
    push_label_value_row, push_wrapped_text, selected_style, settings_text_columns, warning_style,
};
use super::ui_page::{InstructionsPage, RedactPatternsPage, UtilityModelPicker};
use cockpit_core::daemon::proto::Request;

use super::{Nav, SettingsCx, SettingsPage, save_status};

// ── Enum option labels + cycles ──────────────────────────────────────────
// One place per enum so the value-renderer and the cycle/toggle action stay
// in sync. Cycles delegate to the config enum's own `cycled()`/`toggled()`
// where one exists, so a grown option set is reflected without editing here.

fn cycle_vim(v: VimModeSetting) -> VimModeSetting {
    match v {
        VimModeSetting::Hint => VimModeSetting::Enabled,
        VimModeSetting::Enabled => VimModeSetting::Disabled,
        VimModeSetting::Disabled => VimModeSetting::Hint,
    }
}

fn vim_label(v: VimModeSetting) -> &'static str {
    match v {
        VimModeSetting::Hint => "hint (default — vim on, hint chip on Normal entry)",
        VimModeSetting::Enabled => "enabled (vim on, no hint chip)",
        VimModeSetting::Disabled => "disabled (vim off)",
    }
}

fn cycle_thinking(t: ThinkingDisplay) -> ThinkingDisplay {
    match t {
        ThinkingDisplay::Condensed => ThinkingDisplay::Hidden,
        ThinkingDisplay::Hidden => ThinkingDisplay::Verbose,
        ThinkingDisplay::Verbose => ThinkingDisplay::Condensed,
    }
}

fn thinking_label(t: ThinkingDisplay) -> &'static str {
    match t {
        ThinkingDisplay::Condensed => "condensed (default — chip, ctrl+t expands every block)",
        ThinkingDisplay::Hidden => "hidden (only `Thinking…` while in flight; nothing after)",
        ThinkingDisplay::Verbose => "verbose (always show reasoning inline)",
    }
}

fn cycle_diff_style(s: DiffStyle) -> DiffStyle {
    match s {
        DiffStyle::SideBySide => DiffStyle::Inline,
        DiffStyle::Inline => DiffStyle::Hidden,
        DiffStyle::Hidden => DiffStyle::SideBySide,
    }
}

fn diff_style_label(s: DiffStyle) -> &'static str {
    match s {
        DiffStyle::SideBySide => {
            "side-by-side (default — two columns; falls back to inline under 80 cols)"
        }
        DiffStyle::Inline => "inline (unified +/- diff)",
        DiffStyle::Hidden => "hidden (one-line `edited path (+N -M)` summary)",
    }
}

fn cycle_concurrency(c: Concurrency) -> Concurrency {
    match c {
        Concurrency::Subagents => Concurrency::Fork,
        Concurrency::Fork => Concurrency::Subagents,
    }
}

fn concurrency_label(c: Concurrency) -> &'static str {
    match c {
        Concurrency::Subagents => "subagents (default — in-process fan-out)",
        Concurrency::Fork => "fork (separate subprocess per sub-task)",
    }
}

fn default_primary_agent_label(a: DefaultPrimaryAgent) -> &'static str {
    match a {
        DefaultPrimaryAgent::Build => "build (start on the coding agent — make the change now)",
        DefaultPrimaryAgent::Plan => "plan (start on the planning agent — author a plan)",
    }
}

fn injection_threshold_label(t: InjectionThreshold) -> &'static str {
    match t {
        InjectionThreshold::Off => "off (default — no prompt-injection scanning)",
        InjectionThreshold::Low => "low (block prompts rated low or higher; needs a utility model)",
        InjectionThreshold::Medium => {
            "medium (block prompts rated medium or higher; needs a utility model)"
        }
        InjectionThreshold::High => "high (block only prompts rated high; needs a utility model)",
    }
}

fn injection_result_action_label(a: InjectionResultAction) -> &'static str {
    match a {
        InjectionResultAction::Block => "block (default — withhold behind override UX)",
        InjectionResultAction::Ask => "ask (prompt before delivering flagged tool results)",
    }
}

fn approval_mode_label(m: ApprovalMode) -> &'static str {
    match m {
        ApprovalMode::Manual => {
            "manual (default — sandboxed by default; you approve anything that needs to leave the sandbox)"
        }
        ApprovalMode::Auto => {
            "auto (sandboxed by default; utility model can approve anything that needs to leave the sandbox)"
        }
        ApprovalMode::Yolo => "yolo (run without approval prompts)",
    }
}

fn sandbox_mode_setting_value(
    mode: cockpit_core::tools::sandbox_mode::SandboxMode,
    caps: &cockpit_proto::HostCapabilitySnapshot,
) -> String {
    crate::tui::capability_gate::sandbox_mode_display(mode, caps)
}

fn predict_next_message_label(m: PredictNextMessage) -> &'static str {
    match m {
        PredictNextMessage::Off => "off (no next-message prediction; no utility call)",
        PredictNextMessage::Short => {
            "short (default — one-line next-message prediction; needs a utility model)"
        }
        PredictNextMessage::Long => {
            "long (full proposed message prediction; needs a utility model)"
        }
    }
}

fn shell_compression_label(c: ShellCompression) -> &'static str {
    match c {
        ShellCompression::Enabled => {
            "enabled (default — filter/compress bash output; errors/warnings always kept)"
        }
        ShellCompression::Disabled => "disabled (bash output returned verbatim)",
    }
}

fn text_embedded_recovery_label(m: TextEmbeddedRecovery) -> &'static str {
    match m {
        TextEmbeddedRecovery::Available => {
            "available (default — recover only when the named tool exists; else warn + nudge)"
        }
        TextEmbeddedRecovery::Strict => {
            "strict (always treat a tool-shaped block as a call; unknown tool fed back)"
        }
        TextEmbeddedRecovery::Off => "off (a text-form tool call stays plain assistant text)",
    }
}

/// Harness-steering labels only. Mode is orthogonal to model trust: no label
/// here implies data custody, and none of them changes redaction.
fn llm_mode_label(m: LlmMode) -> &'static str {
    match m {
        LlmMode::Defensive => {
            "defensive (default — explicit tool steering, more decomposition; weaker models; steering only)"
        }
        LlmMode::Normal => {
            "normal (terse tool descriptions, episode sequencing; strong models; steering only)"
        }
        LlmMode::Frontier => {
            "frontier (lean steering, high-autonomy; top-tier models; steering only)"
        }
    }
}

/// Which top-level category a [`CategoryPage`] renders. Drives the page
/// title, the section intro, the row descriptor list, the reset scope, and
/// the back-target cursor.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash)]
pub(super) enum Category {
    Interface,
    Behavior,
    Privacy,
    Translation,
    Profile,
}

impl Category {
    #[cfg(test)]
    pub(super) const ALL: [Self; 5] = [
        Self::Interface,
        Self::Behavior,
        Self::Privacy,
        Self::Translation,
        Self::Profile,
    ];

    #[cfg(test)]
    const fn fixture_ordinal(self) -> usize {
        match self {
            Self::Interface => 0,
            Self::Behavior => 1,
            Self::Privacy => 2,
            Self::Translation => 3,
            Self::Profile => 4,
        }
    }

    /// The page heading shown bold at the top of the body.
    pub(super) fn heading(self) -> &'static str {
        match self {
            Category::Interface => "Interface",
            Category::Behavior => "Behavior",
            Category::Privacy => "Privacy & Safety",
            Category::Translation => "Translation",
            Category::Profile => "Profile",
        }
    }

    /// The breadcrumb label for the dialog title bar.
    pub(super) fn crumb(self) -> &'static str {
        self.heading()
    }

    /// The 1–3 sentence section intro: what this category governs and how
    /// it fits into how cockpit works.
    pub(super) fn intro(self) -> &'static str {
        match self {
            Category::Interface => {
                "How the terminal UI looks and how you type into it. These are \
                 pure display and input preferences — nothing here changes what \
                 the agent does, only what you see."
            }
            Category::Behavior => {
                "How sessions and agents behave: which agent you start on, how \
                 strongly tools are steered, when commands need approval, and how \
                 plans run. The Advanced block holds tuning knobs most users \
                 never need to touch."
            }
            Category::Privacy => {
                "What leaves your machine and what gets scrubbed first. Redaction \
                 replaces secrets (env vars, .env files) with a placeholder before \
                 any prompt is sent; the injection guard screens untrusted text. \
                 The Advanced block holds the redaction internals and the \
                 remote-config opt-in."
            }
            Category::Translation => {
                "Round-trip translation through the utility model. When your \
                 language and the model's language are both set and differ, your \
                 prompts are translated into the model's language and its replies \
                 back into yours. Leave either blank to disable."
            }
            Category::Profile => {
                "Who cockpit greets. Your display name is shown on the startup \
                 banner. That's it — nothing here affects the agent."
            }
        }
    }

    /// The label on the page-level reset button, scoped to what it resets.
    /// `None` for categories with no meaningful "restore defaults" affordance
    /// (Translation/Profile are just free-text — clearing them is the reset).
    fn reset_label(self) -> Option<&'static str> {
        match self {
            Category::Interface => Some("reset display settings to defaults"),
            Category::Behavior => Some("reset behavior settings to defaults"),
            Category::Privacy => Some("reset privacy & safety settings to defaults"),
            Category::Translation | Category::Profile => None,
        }
    }
}

/// One displayed line in a category page: a section divider/heading or an
/// actual setting row.
pub(super) enum Row {
    /// A non-selectable section divider (e.g. the "Advanced" block) with a
    /// short blurb shown under it.
    Heading(SettingHeading),
    /// A selectable setting.
    Setting(SettingId),
}

/// Every individual setting across the five categories. The dialog matches
/// on this to render the value, describe it, and mutate `self.extended`.
/// One enum (rather than per-category enums) keeps the read/write/help
/// logic in a single exhaustive `match` per concern.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub(super) enum SettingId {
    // ── Interface ────────────────────────────────────────────────────
    VimMode,
    Thinking,
    RenderAgentMarkdown,
    RenderUserMarkdown,
    Mouse,
    RichTextCopy,
    Emojis,
    DiffStyle,
    Banner,
    ShowCwd,
    ShowBranch,
    CaffeinateDisplay,
    AttentionEnabled,
    AttentionTitle,
    AttentionBell,
    AttentionDesktop,
    ExitTailLines,

    // ── Behavior ─────────────────────────────────────────────────────
    DefaultPrimaryAgent,
    LlmMode,
    ApprovalMode,
    SandboxEscalationEnabled,
    PredictNextMessage,
    ShellCompression,
    CommandProfileRust,
    CommandProfileNode,
    CommandProfilePython,
    CommandProfileGo,
    CommandProfileJava,
    CommandProfileWrappers,
    CommandProfileCustomProfiles,
    InlineThink,
    HintToolCallCorrections,
    TextEmbeddedRecovery,
    UtilityModel,
    TranslationModel,
    CheapCodeModel,
    SmartCodeModel,
    ReasoningModel,
    AgentChoosesSubagentModel,
    DeepthinkEnabled,
    AutoTitleModel,
    SkillInjectionModel,
    PredictNextMessageModel,
    HarnessReportSummarizationModel,
    CompactModel,
    CompactPrompt,
    Instructions,
    // Advanced
    LoopGuardThreshold,
    MaxPrimaryRounds,
    Concurrency,
    ScheduleMaxConcurrent,
    ScheduleAllowUnboundedLoops,
    DelegationMaxParallel,
    GoalSupervisionEnabled,
    GoalSupervisionSkepticCount,
    GoalSupervisionModel,
    GoalSupervisionMaxRounds,
    DialogLockoutMs,
    TimeInjectionInterval,
    PackagesDir,
    AgentDirs,

    // ── Privacy & Safety ─────────────────────────────────────────────
    SandboxDefaultMode,
    SandboxDockerfile,
    SecretStore,
    RedactEnabled,
    RedactScanEnvironment,
    RedactScanDotenv,
    RedactScanSshKeys,
    RedactPatterns,
    InjectionThreshold,
    InjectionResultAction,
    InjectionCheckPrompt,
    InjectionModel,
    // Request preflight (implementation note)
    PreflightEnabled,
    PreflightModel,
    PreflightPrompt,
    // Advanced
    RedactExtraDotenvPaths,
    RedactMinSecretLength,
    RedactPlaceholder,
    RedactDenylist,
    RedactAllowlist,
    GitignoreAllow,
    AllowRemoteConfig,

    // ── Translation ──────────────────────────────────────────────────
    TranslationUserLanguage,
    TranslationModelLanguage,

    // ── Profile ──────────────────────────────────────────────────────
    Name,
}

pub(super) const ALL_SETTING_IDS: &[SettingId] = &[
    SettingId::VimMode,
    SettingId::Thinking,
    SettingId::RenderAgentMarkdown,
    SettingId::RenderUserMarkdown,
    SettingId::Mouse,
    SettingId::RichTextCopy,
    SettingId::Emojis,
    SettingId::DiffStyle,
    SettingId::Banner,
    SettingId::ShowCwd,
    SettingId::ShowBranch,
    SettingId::CaffeinateDisplay,
    SettingId::AttentionEnabled,
    SettingId::AttentionTitle,
    SettingId::AttentionBell,
    SettingId::AttentionDesktop,
    SettingId::ExitTailLines,
    SettingId::DefaultPrimaryAgent,
    SettingId::LlmMode,
    SettingId::ApprovalMode,
    SettingId::SandboxEscalationEnabled,
    SettingId::PredictNextMessage,
    SettingId::ShellCompression,
    SettingId::CommandProfileRust,
    SettingId::CommandProfileNode,
    SettingId::CommandProfilePython,
    SettingId::CommandProfileGo,
    SettingId::CommandProfileJava,
    SettingId::CommandProfileWrappers,
    SettingId::CommandProfileCustomProfiles,
    SettingId::InlineThink,
    SettingId::HintToolCallCorrections,
    SettingId::TextEmbeddedRecovery,
    SettingId::UtilityModel,
    SettingId::TranslationModel,
    SettingId::CheapCodeModel,
    SettingId::SmartCodeModel,
    SettingId::ReasoningModel,
    SettingId::AgentChoosesSubagentModel,
    SettingId::DeepthinkEnabled,
    SettingId::AutoTitleModel,
    SettingId::SkillInjectionModel,
    SettingId::PredictNextMessageModel,
    SettingId::HarnessReportSummarizationModel,
    SettingId::CompactModel,
    SettingId::CompactPrompt,
    SettingId::Instructions,
    SettingId::LoopGuardThreshold,
    SettingId::MaxPrimaryRounds,
    SettingId::Concurrency,
    SettingId::ScheduleMaxConcurrent,
    SettingId::ScheduleAllowUnboundedLoops,
    SettingId::DelegationMaxParallel,
    SettingId::GoalSupervisionEnabled,
    SettingId::GoalSupervisionSkepticCount,
    SettingId::GoalSupervisionModel,
    SettingId::GoalSupervisionMaxRounds,
    SettingId::DialogLockoutMs,
    SettingId::TimeInjectionInterval,
    SettingId::PackagesDir,
    SettingId::AgentDirs,
    SettingId::SandboxDefaultMode,
    SettingId::SandboxDockerfile,
    SettingId::SecretStore,
    SettingId::RedactEnabled,
    SettingId::RedactScanEnvironment,
    SettingId::RedactScanDotenv,
    SettingId::RedactScanSshKeys,
    SettingId::RedactPatterns,
    SettingId::InjectionThreshold,
    SettingId::InjectionResultAction,
    SettingId::InjectionCheckPrompt,
    SettingId::InjectionModel,
    SettingId::PreflightEnabled,
    SettingId::PreflightModel,
    SettingId::PreflightPrompt,
    SettingId::RedactExtraDotenvPaths,
    SettingId::RedactMinSecretLength,
    SettingId::RedactPlaceholder,
    SettingId::RedactDenylist,
    SettingId::RedactAllowlist,
    SettingId::GitignoreAllow,
    SettingId::AllowRemoteConfig,
    SettingId::TranslationUserLanguage,
    SettingId::TranslationModelLanguage,
    SettingId::Name,
];

impl SettingId {
    fn descriptor(self) -> SettingDescriptor {
        SettingDescriptor {
            label: self.label(),
            help: self.help_text(),
            kind: self.kind(),
        }
    }

    /// The short row label (left column).
    fn label(self) -> &'static str {
        match self {
            SettingId::VimMode => "vim mode",
            SettingId::Thinking => "thinking display",
            SettingId::RenderAgentMarkdown => "render agent markdown",
            SettingId::RenderUserMarkdown => "render user markdown",
            SettingId::Mouse => "mouse",
            SettingId::RichTextCopy => "rich-text copy",
            SettingId::Emojis => "emojis",
            SettingId::DiffStyle => "diff style",
            SettingId::Banner => "startup banner",
            SettingId::ShowCwd => "show cwd",
            SettingId::ShowBranch => "show branch",
            SettingId::CaffeinateDisplay => "caffeinate display",
            SettingId::AttentionEnabled => "attention notifications",
            SettingId::AttentionTitle => "attention title marker",
            SettingId::AttentionBell => "attention bell",
            SettingId::AttentionDesktop => "attention desktop",
            SettingId::ExitTailLines => "exit tail lines",
            SettingId::DefaultPrimaryAgent => "default agent",
            SettingId::LlmMode => "llm mode",
            SettingId::ApprovalMode => "approval mode",
            SettingId::SandboxEscalationEnabled => "sandbox escalation",
            SettingId::PredictNextMessage => "predict next message",
            SettingId::ShellCompression => "shell compression",
            SettingId::CommandProfileRust => "Rust resource profile",
            SettingId::CommandProfileNode => "Node resource profile",
            SettingId::CommandProfilePython => "Python resource profile",
            SettingId::CommandProfileGo => "Go resource profile",
            SettingId::CommandProfileJava => "Java resource profile",
            SettingId::CommandProfileWrappers => "resource profile wrappers",
            SettingId::CommandProfileCustomProfiles => "custom resource profiles",
            SettingId::InlineThink => "extract inline <think>",
            SettingId::HintToolCallCorrections => "hint tool-call corrections",
            SettingId::TextEmbeddedRecovery => "text-embedded recovery",
            SettingId::UtilityModel => "utility model",
            SettingId::TranslationModel => "translation model",
            SettingId::CheapCodeModel => "cheap code model",
            SettingId::SmartCodeModel => "smart code model",
            SettingId::ReasoningModel => "reasoning model",
            SettingId::AgentChoosesSubagentModel => "allow agent to determine subagent model",
            SettingId::DeepthinkEnabled => "deepthink subagent",
            SettingId::AutoTitleModel => "auto-title model",
            SettingId::SkillInjectionModel => "skill injection model",
            SettingId::PredictNextMessageModel => "prediction model",
            SettingId::HarnessReportSummarizationModel => "harness-report summarization model",
            SettingId::CompactModel => "compact model",
            SettingId::CompactPrompt => "compact prompt",
            SettingId::Instructions => "instructions files",
            SettingId::LoopGuardThreshold => "loop-guard threshold",
            SettingId::MaxPrimaryRounds => "max tool rounds per message",
            SettingId::Concurrency => "fan-out concurrency",
            SettingId::ScheduleMaxConcurrent => "max concurrent scheduled tasks",
            SettingId::ScheduleAllowUnboundedLoops => "allow unbounded schedule loops",
            SettingId::DelegationMaxParallel => "max parallel task delegations",
            SettingId::GoalSupervisionEnabled => "goal completion verification",
            SettingId::GoalSupervisionSkepticCount => "goal skeptic count",
            SettingId::GoalSupervisionModel => "goal skeptic model",
            SettingId::GoalSupervisionMaxRounds => "goal verification rounds",
            SettingId::DialogLockoutMs => "dialog lockout (ms)",
            SettingId::TimeInjectionInterval => "time-injection interval (min)",
            SettingId::PackagesDir => "packages dir",
            SettingId::AgentDirs => "agent dirs",
            SettingId::SandboxDefaultMode => "default sandbox mode",
            SettingId::SandboxDockerfile => "sandbox Dockerfile",
            SettingId::SecretStore => "secret storage",
            SettingId::RedactEnabled => "redaction",
            SettingId::RedactScanEnvironment => "environment variable redaction",
            SettingId::RedactScanDotenv => "environment file redaction",
            SettingId::RedactScanSshKeys => "private SSH key redaction",
            SettingId::RedactPatterns => "environment file patterns",
            SettingId::InjectionThreshold => "injection threshold",
            SettingId::InjectionResultAction => "injection result action",
            SettingId::InjectionCheckPrompt => "injection check-prompt",
            SettingId::InjectionModel => "injection guard model",
            SettingId::PreflightEnabled => "request preflight",
            SettingId::PreflightModel => "preflight model",
            SettingId::PreflightPrompt => "preflight prompt",
            SettingId::RedactExtraDotenvPaths => "extra env files",
            SettingId::RedactMinSecretLength => "min secret length",
            SettingId::RedactPlaceholder => "redaction placeholder",
            SettingId::RedactDenylist => "always-redact denylist",
            SettingId::RedactAllowlist => "env var allowlist",
            SettingId::GitignoreAllow => "gitignore read allowlist",
            SettingId::AllowRemoteConfig => "allow remote config",
            SettingId::TranslationUserLanguage => "your language",
            SettingId::TranslationModelLanguage => "model language",
            SettingId::Name => "name",
        }
    }

    /// The plain-language description: what the setting does and the effect
    /// of each value. Genuinely educational — written for someone who has
    /// never read the docs. Read the code that consumes each field to keep
    /// these accurate.
    fn help_text(self) -> &'static str {
        match self {
            SettingId::VimMode => {
                "Keystroke model for the message composer. `hint` (default) enables \
                 vim keybindings and shows a one-time hint chip when you enter \
                 Normal mode; `enabled` is vim with no hint; `disabled` is a plain \
                 text input with no modal editing."
            }
            SettingId::Thinking => {
                "How a model's reasoning is shown. `condensed` (default) collapses \
                 it to a clickable \"thought for Xs\" chip you can expand; `hidden` \
                 shows only a live \"Thinking…\" placeholder and drops the text once \
                 the turn ends; `verbose` always prints the full reasoning inline."
            }
            SettingId::RenderAgentMarkdown => {
                "Render the agent's replies as formatted markdown (code blocks, \
                 bullets, bold) instead of raw text. On by default — chat models \
                 routinely emit markdown. Turn off to see exactly the bytes the \
                 model produced."
            }
            SettingId::RenderUserMarkdown => {
                "Render your own messages as markdown too. Off by default, since \
                 most prompts are plain prose; turn on if you paste markdown into \
                 the composer and want it formatted in the transcript."
            }
            SettingId::Mouse => {
                "Capture mouse events. On (default) gives click-to-position in the \
                 composer, in-app drag-select, clickable chips, and click/wheel \
                 navigation and editing throughout Settings; hold \
                 Shift/Option/Fn for your terminal's native selection. Off hands \
                 selection and copy back to the terminal entirely."
            }
            SettingId::RichTextCopy => {
                "Allow Ctrl+Shift+Y to copy the focused agent message as rich text \
                 (HTML to the system clipboard, falling back to plain text over \
                 SSH). Off disables that shortcut."
            }
            SettingId::Emojis => {
                "Use emoji glyphs in tool-call boxes and the splash. Off by default \
                 because many terminals render emoji as tofu boxes; turn on only if \
                 yours displays them correctly."
            }
            SettingId::DiffStyle => {
                "How file edits are shown in the transcript. `side-by-side` \
                 (default) puts old and new in two columns (auto-falling back to \
                 inline under 80 columns); `inline` is a unified +/- diff; `hidden` \
                 shows only a one-line `edited path (+N -M)` summary."
            }
            SettingId::Banner => {
                "Show the pixel-art banner at TUI startup. On by default; it is \
                 suppressed anyway when output isn't a TTY, NO_COLOR is set, or the \
                 window is too narrow. Off skips it entirely."
            }
            SettingId::ShowCwd => {
                "Show the current working directory in the top chrome. The path \
                 orients you when you run cockpit across several projects."
            }
            SettingId::ShowBranch => {
                "Show the active git branch in the top chrome, so you always know \
                 which branch the agent's commands run against."
            }
            SettingId::CaffeinateDisplay => {
                "When /caffeinate is active, also keep the display awake. Off \
                 (default) keeps only the machine awake and prevents lid-close \
                 suspend while letting the screen sleep — saves wear/power on \
                 overnight runs. System-idle and lid-close are always suppressed \
                 while caffeinated regardless."
            }
            SettingId::AttentionEnabled => {
                "In-TUI attention notifications for events that want you back: a \
                 question or approval waiting, a turn finishing or failing, a job \
                 completing, or a plan step needing attention. On (default) shows a \
                 brief toast for each; off silences the whole subsystem (toast, \
                 title marker, bell, and desktop)."
            }
            SettingId::AttentionTitle => {
                "Show a terminal-title marker while a question or approval is waiting. \
                 On by default so another terminal tab/window shows action is needed; \
                 fixed strings only, never command text, paths, or prompt content."
            }
            SettingId::AttentionBell => {
                "Ring the terminal bell once for events that need you to act — a \
                 question, an approval, or a plan step needing attention. Off by \
                 default. Repeated identical events are debounced so a burst rings \
                 at most once. Requires attention notifications on."
            }
            SettingId::AttentionDesktop => {
                "Post a native desktop notification for action-required events and \
                 long-running turn completions when you haven't recently interacted. \
                 Off by default. Best-effort on two layers: terminal notification \
                 escapes (which supporting terminals like kitty, WezTerm, foot, or \
                 Ghostty turn into native popups, and which work over SSH) plus the \
                 OS notification service on local sessions. Repeated identical events \
                 are debounced. Requires attention notifications on."
            }
            SettingId::ExitTailLines => {
                "How many lines of the conversation tail are dumped back into your \
                 terminal scrollback when the TUI exits, so the last exchange stays \
                 visible. Default 100; `0` dumps nothing; `-1` dumps the whole \
                 session."
            }
            SettingId::DefaultPrimaryAgent => {
                "Which agent a brand-new session starts on. `build` starts on the \
                 coding agent; `plan` starts on the planning agent. You can still \
                 switch any time with /build or /plan."
            }
            SettingId::LlmMode => {
                "How hard tools and prompts steer the model. `defensive` (default) \
                 uses explicit, spelled-out tool descriptions and more task \
                 decomposition — tuned for weaker ~120k-context models; `normal` \
                 uses terse descriptions and episode-sequencing delegation for \
                 strong models; `frontier` uses the leanest steering and \
                 high-autonomy prompts for top-tier models. This global default is \
                 not auto-detected — a provider or model Mode override wins over \
                 it (known frontier models on standard providers are pinned to \
                 `frontier` at discovery). Steering only: mode never changes \
                 provider eligibility, data custody, or redaction. Model trust \
                 alone decides whether inference requests are sent raw, and no \
                 mode or locality implies trust."
            }
            SettingId::ApprovalMode => {
                "When a command needs approval to leave the sandbox. `manual` \
                 (default) asks you — you are the gate; `auto` lets the \
                 utility-model safety gate approve when possible and asks when \
                 unsafe or unavailable; `yolo` runs without approval prompts. \
                 Distinct from the `auto` *agent*."
            }
            SettingId::SandboxEscalationEnabled => {
                "Allow the agent to offer an explicit unsandboxed retry after a \
                 sandboxed command fails. On by default; approval mode still \
                 decides whether an allowed escalation asks first. This setting \
                 persists the default and updates the current session."
            }
            SettingId::PredictNextMessage => {
                "After each agent turn, have the utility model predict your likely \
                 next message and offer it as grey ghost text in an empty composer \
                 (Tab accepts). `off` makes no prediction; `short` (default) is one \
                 line; `long` allows a fuller proposed message. Needs a utility \
                 model."
            }
            SettingId::ShellCompression => {
                "Filter and compress bash output before it enters the model's \
                 context to save tokens. `enabled` (default) strips noise with a \
                 per-command strategy — errors, warnings, failures and diagnostics \
                 are always kept; `disabled` returns bash output verbatim."
            }
            SettingId::CommandProfileRust => {
                "Allow sandboxed Rust commands to reach Cargo/Rustup homes, binary \
                 directories, and Cargo config files without a broad approval. On by \
                 default; wrappers can also opt commands into this profile."
            }
            SettingId::CommandProfileNode => {
                "Allow sandboxed Node package-manager commands to reach package-manager \
                 caches such as npm, pnpm, yarn, bun, and corepack. On by default."
            }
            SettingId::CommandProfilePython => {
                "Allow sandboxed Python tooling to reach pip/uv/poetry/mypy caches and \
                 an external active virtualenv when present. On by default."
            }
            SettingId::CommandProfileGo => {
                "Allow sandboxed Go tooling to reach GOPATH, module cache, and build \
                 cache roots. On by default; Go cache discovery may run a trusted \
                 `go env` introspection."
            }
            SettingId::CommandProfileJava => {
                "Allow sandboxed Java tooling to reach Maven and Gradle user caches. \
                 On by default."
            }
            SettingId::CommandProfileWrappers => {
                "JSON object mapping wrapper approval keys to profile ids. For example, \
                 `just ci` can map to `rust_toolchain` and `node_package_manager` so a \
                 wrapper command gets the same scoped cache access as the tools it runs."
            }
            SettingId::CommandProfileCustomProfiles => {
                "JSON object defining additional command resource profiles. Each key is \
                 a profile id; each value declares `commands` and `roots` so sandboxed \
                 commands can expose only the required external caches or tool state."
            }
            SettingId::InlineThink => {
                "Classify a leading inline `<think>…</think>` block. On (default) \
                 treats it as thinking — shown as the reasoning chip and dropped \
                 from later turns so it never replays. Off treats it as response \
                 body — left inline as ordinary text (no chip) and carried \
                 forward. A provider or model override wins over this default."
            }
            SettingId::HintToolCallCorrections => {
                "When a tool call is auto-repaired, also tell the model what was \
                 corrected via a terse `<repair_note>` on the result, so a weak \
                 model learns (e.g. that the field is `path`, not `file_path`) \
                 instead of repeating the mistake. Off (default) repairs silently. \
                 A provider or model override wins over this global default."
            }
            SettingId::TextEmbeddedRecovery => {
                "Recover a tool call a weak model emitted as text (a fenced block \
                 or bare JSON) instead of the structured tool-call field. \
                 `available` (default) recovers only when the named tool exists — \
                 an unknown tool is surfaced with a warning and the model is \
                 nudged to retry; `strict` always treats a tool-shaped block as a \
                 call and feeds an `unknown tool` result back; `off` leaves it as \
                 plain text. A provider or model override wins over this default."
            }
            SettingId::TranslationModel => {
                "Model role for translation work and translation-class subagents. \
                 Unset falls back to the shared utility model for translation."
            }
            SettingId::CheapCodeModel => {
                "Default model for cheap read-only delegated coding work such as \
                 explore/docs/scout. Unset falls through to the session model."
            }
            SettingId::SmartCodeModel => {
                "Default model for write-capable delegated coding work such as \
                 builder/coder/bee. Unset falls through to the session model."
            }
            SettingId::ReasoningModel => {
                "Default model for reasoning-heavy delegated work such as plan-author \
                 and deepthink. Unset falls through to the session model."
            }
            SettingId::AgentChoosesSubagentModel => {
                "When on, a delegating agent's `task.model` / `spawn.model` \
                 policy selector (exact provider:model, or category) is \
                 honored; when off (default), role defaults apply. A selector \
                 cannot choose data custody: that is host policy, so \
                 model-directed delegation always routes to a redacted \
                 untrusted child."
            }
            SettingId::DeepthinkEnabled => {
                "When on, Build may delegate to `deepthink`, a tool-free \
                 reasoning leaf that receives only its brief and explicit seeds. \
                 It is off by default because it is meant for strong reasoning \
                 models and may route prompts to remote providers."
            }
            SettingId::UtilityModel => {
                "The cheap background model (`provider:model-id`) used for work that \
                 doesn't need the primary model: session auto-titling, the \
                 prompt-injection guard, next-message prediction, and \
                 safety-gated approval. Unset disables every feature that depends \
                 on it."
            }
            SettingId::AutoTitleModel => {
                "Model used specifically for session auto-titling. Unset falls back \
                 to the shared utility model."
            }
            SettingId::SkillInjectionModel => {
                "Model used to rank skills for automatic injection. Unset falls \
                 back to the shared utility model."
            }
            SettingId::PredictNextMessageModel => {
                "Model used for next-message prediction. Unset falls back to the \
                 shared utility model."
            }
            SettingId::HarnessReportSummarizationModel => {
                "Model used to summarize over-budget external harness reports. \
                 Unset falls back to the shared utility model."
            }
            SettingId::CompactModel => {
                "Dedicated model (`provider:model-id`) for drafting the `/compact` \
                 handoff brief. Unset falls back to the shared utility model, then \
                 the active agent's own model."
            }
            SettingId::CompactPrompt => {
                "Full override for the `/compact` handoff-brief instruction. When \
                 set it replaces the default brief prompt entirely; the \
                 deterministic file/command appendix is unaffected. Blank restores \
                 the built-in default."
            }
            SettingId::Instructions => {
                "Ordered list of agent-guidance filenames (e.g. AGENTS.md, \
                 project guidance). The first one that exists, walking up from the cwd to \
                 the git root, is injected into the system prompt. Drill in to add, \
                 rename, reorder, or remove entries."
            }
            SettingId::LoopGuardThreshold => {
                "How many back-to-back identical tool calls trigger an approval \
                 prompt — a stuck-in-a-loop guard. `2` (default and minimum) fires \
                 on the first exact repeat; higher values tolerate more repeats \
                 before pausing."
            }
            SettingId::MaxPrimaryRounds => {
                "Maximum number of primary-agent tool round-trips allowed for one \
                 user message. `0` (default) is unlimited; positive values pause \
                 for approval in the TUI and stop headless runs at the ceiling."
            }
            SettingId::Concurrency => {
                "How an agent fans out sub-tasks. `subagents` (default) runs them \
                 in-process; `fork` runs a separate cockpit/other-harness \
                 subprocess per sub-task."
            }
            SettingId::ScheduleMaxConcurrent => {
                "Cap on simultaneously-running scheduled tasks (loops, timers, \
                 background tasks) per session — a guard against accidental \
                 fan-out. Must be at least 1."
            }
            SettingId::ScheduleAllowUnboundedLoops => {
                "Allow scheduled loops to run without a fixed iteration limit. Off by default; leave it off unless the schedule has its own clear stop condition."
            }
            SettingId::DelegationMaxParallel => {
                "Cap on entries accepted in one inline `task(intent=\"batch\", batch=[...])` \
                 call. Larger batches are refused before any child starts. Must \
                 be at least 1."
            }
            SettingId::GoalSupervisionEnabled => {
                "Operator kill switch for host-supervised `/goal` runs. On (default) \
                 enables planning, evaluation, and verification; off rejects new goals \
                 and pauses open goals without restoring worker lifecycle authority."
            }
            SettingId::GoalSupervisionSkepticCount => {
                "How many refute-framed skeptic scouts run in parallel for each \
                 completion verification round. A majority decides. Default 3."
            }
            SettingId::GoalSupervisionModel => {
                "Optional model selector (`provider:model-id`) for completion skeptics. \
                 Blank falls back to the same model as the active session."
            }
            SettingId::GoalSupervisionMaxRounds => {
                "Maximum verification attempts before the host pauses the goal for \
                 explicit user action. Default 4."
            }
            SettingId::DialogLockoutMs => {
                "How long (milliseconds) an answer dialog ignores input after it \
                 appears, so a keystroke you were mid-typing can't accidentally \
                 answer it. The border is grey during the lockout and white once \
                 it elapses. Default 1500."
            }
            SettingId::TimeInjectionInterval => {
                "Minimum minutes between `[time: …]` preludes added to your \
                 messages. The first message always carries one; later messages get \
                 one only after this many minutes have passed. Lets a long-running \
                 model keep a rough sense of elapsed time. Default 5."
            }
            SettingId::PackagesDir => {
                "Where the docs agent stores cloned dependency snapshots. Leave \
                 unset to let the agent pick its own default location."
            }
            SettingId::AgentDirs => {
                "Extra directories searched for agent-definition files, on top of \
                 the built-in locations. Paths are tilde-expanded. Drill in to add, \
                 edit, reorder, or remove entries."
            }
            SettingId::SandboxDefaultMode => {
                "Which sandbox mode new sessions start in. `on` is the default host filesystem sandbox; `off` disables sandboxing; container modes run bash inside docker/podman when available. The --no-sandbox flag still forces off. Host sandbox and container modes stay visible when unavailable and show the snapshot install/fix command; they are not persisted until the capability is present."
            }
            SettingId::SandboxDockerfile => {
                "Optional Dockerfile path for container sandboxes. Blank uses the global default at ~/.config/cockpit/sandbox/Dockerfile. Project values only take effect for trusted workspaces."
            }
            SettingId::SecretStore => crate::tui::capability_gate::SECRET_STORE_HELP,
            SettingId::RedactEnabled => {
                "The master redaction switch. On (default) routes every outbound \
                 prompt through the scrubber so secrets are replaced with the \
                 placeholder before sending. Off disables scrubbing entirely — only \
                 turn this off if you fully trust everything in context, since \
                 secrets would then reach the provider verbatim."
            }
            SettingId::RedactScanEnvironment => {
                "Add your OS environment-variable values to the redaction table so \
                 they're scrubbed out of prompts. On by default. (A built-in \
                 allowlist already exempts non-secret vars like PATH.)"
            }
            SettingId::RedactScanDotenv => {
                "Scan matched env files (see the patterns below) and add their \
                 secret values to the redaction table. On by default."
            }
            SettingId::RedactScanSshKeys => {
                "Scan your `~/.ssh` directory and add every private key's contents \
                 to the redaction table so a key echoed into a tool result is \
                 scrubbed. Public keys (`*.pub`) are never added. On by default."
            }
            SettingId::RedactPatterns => {
                "Gitignore-style globs naming which env files to scan, matched from \
                 the cwd downward. Default `.env` and `.env.local`. Drill in to \
                 add, edit, reorder, or remove patterns."
            }
            SettingId::InjectionThreshold => {
                "Block user prompts the injection guard rates at or above this \
                 level. `off` (default) disables scanning; `low`/`medium`/`high` \
                 each block prompts rated that level or higher (a flagged \
                 below-threshold prompt still proceeds with a warning). Needs a \
                 utility model."
            }
            SettingId::InjectionResultAction => {
                "What to do when an untrusted tool or subagent result is rated at \
                 or above the injection threshold. `block` withholds behind the \
                 override flow; `ask` prompts before delivery. Yolo mode skips \
                 result scanning."
            }
            SettingId::InjectionCheckPrompt => {
                "The template handed to the utility model when screening untrusted \
                 input. Blank uses the built-in default. The runtime always wraps a \
                 fresh nonce around the untrusted text, so an edited template that \
                 drops the `<KEY>` / `<untrusted content>` markers still gets a \
                 correctly fenced payload."
            }
            SettingId::InjectionModel => {
                "Model used specifically for the injection-guard classification \
                 call (`provider:model-id`). Unset falls back to the shared utility \
                 model; if both are unset the guard fails open (the prompt proceeds \
                 unscanned with a one-time warning)."
            }
            SettingId::PreflightEnabled => {
                "Rewrite each user prompt through the utility model before sending \
                 it to the coding model — clearer, more concise, same intent. Off \
                 by default. Per-session flippable via `/preflight`. Needs a utility \
                 model; fails open to the original on any error."
            }
            SettingId::PreflightModel => {
                "Model used for the preflight rewrite (`provider:model-id`). Unset \
                 falls back to the shared utility model; if both are unset preflight \
                 is skipped (the original prompt is sent)."
            }
            SettingId::PreflightPrompt => {
                "The instruction handed to the utility model for the rewrite. Blank \
                 uses the built-in default (rewrite for clarity, preserve intent, \
                 don't answer or invent, return only the rewritten prompt)."
            }
            SettingId::RedactExtraDotenvPaths => {
                "Explicit extra env-file paths to scan in addition to whatever the \
                 glob patterns match. Drill in to add, edit, reorder, or remove \
                 paths."
            }
            SettingId::RedactMinSecretLength => {
                "Shortest value length that may be auto-added to the redaction \
                 table. Values shorter than this are skipped to avoid scrubbing \
                 common short strings. Default 8. The table never registers values shorter than four bytes."
            }
            SettingId::RedactPlaceholder => {
                "The string each redacted secret is replaced with in outbound \
                 prompts. Make it unmistakable so the model never mistakes it for \
                 real data or tries to work around it."
            }
            SettingId::RedactDenylist => {
                "Literal values redacted when at least four bytes long, even if shorter than \
                 the configured minimum length or sourced from an allowlisted variable. \
                 Base64, hex, and URL-encoded forms are also scrubbed. \
                 Security-sensitive: entries below four bytes are rejected; accepted entries are scrubbed everywhere. \
                 Drill in to manage the list."
            }
            SettingId::RedactAllowlist => {
                "Environment-variable names to exclude from the redaction table on \
                 top of the built-in allowlist — for non-secret vars you don't want \
                 scrubbed. Security-sensitive: an allowlisted var's value will \
                 reach the provider unredacted. Drill in to manage the list."
            }
            SettingId::GitignoreAllow => {
                "Gitignore-style globs that re-permit otherwise-gitignored paths for \
                 the agent's read tools — allow `target/` while `.env` stays blocked. \
                 An allowed path also reappears in file search and the @-tag popup \
                 (dimmed). Saved to this project's config; the approval prompt and \
                 /gitignore-allow add to it too. Drill in to manage the list."
            }
            SettingId::AllowRemoteConfig => {
                "Opt in to fetching remote `.well-known/cockpit` configuration. \
                 Security-sensitive: enabling this lets a remote endpoint \
                 contribute settings, so leave it off unless you specifically trust \
                 the source. Off by default."
            }
            SettingId::TranslationUserLanguage => {
                "Your language as a plain name (e.g. `English`, `Spanish`, \
                 `日本語`). When set and different from the model language, your \
                 prompts are translated into the model's language and its replies \
                 translated back into this. Blank disables translation."
            }
            SettingId::TranslationModelLanguage => {
                "The language to translate prompts into for the model, as a plain \
                 name. When set and different from your language, the round-trip \
                 translation runs. Blank disables translation. Needs a utility \
                 model."
            }
            SettingId::Name => {
                "Your display name. When set, the startup banner greets you with \
                 \"Welcome, {name}\". Purely cosmetic."
            }
        }
    }

    /// The activation kind for Enter handling.
    fn kind(self) -> FieldKind {
        let kind = match self {
            // Drill-in sub-pages.
            SettingId::UtilityModel
            | SettingId::TranslationModel
            | SettingId::CheapCodeModel
            | SettingId::SmartCodeModel
            | SettingId::ReasoningModel
            | SettingId::AutoTitleModel
            | SettingId::SkillInjectionModel
            | SettingId::PredictNextMessageModel
            | SettingId::HarnessReportSummarizationModel
            | SettingId::GoalSupervisionModel
            | SettingId::CompactModel
            | SettingId::Instructions
            | SettingId::RedactPatterns
            | SettingId::AgentDirs
            | SettingId::RedactExtraDotenvPaths
            | SettingId::RedactDenylist
            | SettingId::RedactAllowlist
            | SettingId::GitignoreAllow => FieldKind::Drill,
            // Inline text/number edits.
            SettingId::ExitTailLines
            | SettingId::CommandProfileWrappers
            | SettingId::CommandProfileCustomProfiles
            | SettingId::LoopGuardThreshold
            | SettingId::MaxPrimaryRounds
            | SettingId::ScheduleMaxConcurrent
            | SettingId::DelegationMaxParallel
            | SettingId::GoalSupervisionSkepticCount
            | SettingId::GoalSupervisionMaxRounds
            | SettingId::DialogLockoutMs
            | SettingId::TimeInjectionInterval
            | SettingId::CompactPrompt
            | SettingId::PackagesDir
            | SettingId::SandboxDockerfile
            | SettingId::InjectionCheckPrompt
            | SettingId::InjectionModel
            | SettingId::PreflightModel
            | SettingId::PreflightPrompt
            | SettingId::RedactMinSecretLength
            | SettingId::RedactPlaceholder
            | SettingId::TranslationUserLanguage
            | SettingId::TranslationModelLanguage
            | SettingId::Name => FieldKind::EditText,
            // Everything else cycles/toggles in place.
            _ => FieldKind::Cycle,
        };
        if matches!(kind, FieldKind::EditText) && numeric_text_setting(self) {
            FieldKind::Numeric
        } else {
            kind
        }
    }
}

/// A generic category settings page. Holds the descriptor list (built fresh
/// on entry from [`category_rows`]), the cursor over selectable rows, the
/// inline edit buffer, and a scoped reset button.
pub(super) struct CategoryPage {
    pub(super) category: Category,
    /// Descriptor list including headings. `cursor` indexes only the
    /// selectable rows (settings + the trailing reset button).
    pub(super) rows: Vec<Row>,
    pub(super) cursor: usize,
    /// `Some(id)` while a short text/number field is being edited inline.
    pub(super) editing: Option<SettingId>,
    pub(super) buf: TextField,
    /// Shared full-area editor for long text and JSON settings.
    pub(super) text_editor: Option<CategoryTextEditor>,
    pub(super) path_editor: Option<CategoryPathEditor>,
    pub(super) pending_external_edit: Option<CategoryExternalEdit>,
    external_edit_ops: PointerOperationGate,
    pub(super) status: Option<String>,
    pub(super) reset: ResetButton,
    /// Drained by the App on close to reconcile crossterm mouse capture
    /// after a Mouse-row toggle or a reset. `None` = untouched.
    pub(crate) pending_mouse_capture: Option<bool>,
    /// `Some` while the utility-model picker overlay is open (Behavior only).
    pub(super) utility_picker: Option<Box<UtilityModelPicker>>,
    pub(super) utility_picker_target: Option<SettingId>,
    pub(super) shadowed_global: Option<ShadowedGlobalPrompt>,
    pub(super) secret_store_confirm: Option<crate::tui::dialog::DialogState>,
}

pub(super) struct CategorySettingStore<'a, 'b> {
    pub(super) dialog: &'a mut SettingsCx,
    pub(super) page: &'b mut CategoryPage,
}

impl SettingStore for CategorySettingStore<'_, '_> {
    type Id = SettingId;

    fn descriptor(&self, id: Self::Id) -> SettingDescriptor {
        id.descriptor()
    }

    fn value(&self, id: Self::Id) -> String {
        self.dialog.category_value(id)
    }

    fn cycle(&mut self, id: Self::Id) {
        self.dialog.cycle_category_setting(id, self.page);
    }

    fn commit_text(&mut self, id: Self::Id, raw: &str) -> Result<(), String> {
        self.dialog.commit_category_text(id, raw)
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(super) enum CategoryExternalSource {
    Cursor,
    Inline,
    PathEditor,
    TextEditor,
}

pub(super) struct CategoryExternalEdit {
    pub(super) operation_id: PointerOperationId,
    pub(super) id: SettingId,
    pub(super) path: tempfile::TempPath,
    source: CategoryExternalSource,
    servicing: bool,
}

impl CategoryExternalEdit {
    #[cfg(test)]
    pub(super) fn source(&self) -> CategoryExternalSource {
        self.source
    }

    fn new(
        operation_id: PointerOperationId,
        id: SettingId,
        text: &str,
        source: CategoryExternalSource,
    ) -> Result<Self, String> {
        if std::env::var_os("EDITOR").is_none() {
            return Err("No $EDITOR environment variable".into());
        }
        let mut temp = tempfile::Builder::new()
            .prefix("cockpit-settings-")
            .suffix(".txt")
            .tempfile()
            .map_err(|e| format!("editor: failed to create temp file: {e}"))?;
        temp.write_all(text.as_bytes())
            .map_err(|e| format!("editor: failed to write temp file: {e}"))?;
        temp.flush()
            .map_err(|e| format!("editor: failed to flush temp file: {e}"))?;
        Ok(Self {
            operation_id,
            id,
            path: temp.into_temp_path(),
            source,
            servicing: false,
        })
    }

    pub(super) fn service_path(&mut self) -> Option<PathBuf> {
        if self.servicing {
            return None;
        }
        self.servicing = true;
        Some(self.path.to_path_buf())
    }
}

pub(super) struct CategoryPathEditor {
    pub(super) id: SettingId,
    buf: TextField,
    pub(super) suggest: DirSuggestState,
    mode: PathSuggestMode,
}

impl CategoryPathEditor {
    fn new(id: SettingId, text: String, mode: PathSuggestMode, cwd: &std::path::Path) -> Self {
        let mut editor = Self {
            id,
            buf: TextField::new(text),
            suggest: DirSuggestState::default(),
            mode,
        };
        editor.refresh(cwd);
        editor
    }

    fn text(&self) -> &str {
        self.buf.text()
    }

    #[cfg(test)]
    pub(super) fn set_text_for_test(&mut self, text: String, cwd: &std::path::Path) {
        self.buf.set(text);
        self.refresh(cwd);
    }

    fn cursor(&self) -> usize {
        self.buf.cursor()
    }

    pub(super) fn paste(&mut self, text: &str, cwd: &std::path::Path) {
        self.buf.paste(text);
        self.refresh(cwd);
    }

    fn refresh(&mut self, cwd: &std::path::Path) {
        self.suggest.entries = suggest_paths(cwd, self.buf.text(), self.mode);
        self.suggest.selected = 0;
        self.suggest.scroll = 0;
    }

    fn accept(&mut self, replacement: String, cwd: &std::path::Path) {
        self.buf.set(replacement);
        self.refresh(cwd);
    }

    fn render(&self, frame: &mut Frame, area: Rect, surface: &SettingsPointerSurface) {
        let mut lines = vec![
            Line::from(Span::styled(
                format!("editing {}", self.id.descriptor().label),
                heading_style(),
            )),
            Line::default(),
        ];
        let field_line = lines.len();
        super::shell::push_text_field_at_cursor(
            &mut lines,
            area.width,
            self.id.descriptor().label,
            self.text(),
            self.cursor(),
            true,
            None,
        );
        let field_x = self.id.descriptor().label.chars().count().saturating_add(2);
        surface.register(SettingsPointerTarget {
            rect: Rect::new(
                area.x.saturating_add(field_x.min(u16::MAX as usize) as u16),
                area.y.saturating_add(field_line as u16),
                area.width
                    .saturating_sub(field_x.min(u16::MAX as usize) as u16),
                1,
            ),
            action: SettingsPointerAction::Page(
                super::pointer_actions::SettingsPointerAction::Category(
                    super::pointer_actions::CategoryAction::PathEditBegin(category_pointer_id(
                        self.id,
                    )),
                ),
            ),
            enabled: true,
            disabled_reason: None,
        });
        if let Some(ghost) = self.suggest.ghost_for(self.text())
            && let Some(last) = lines.last_mut()
        {
            last.spans.push(Span::styled(
                ghost.to_string(),
                muted_style().add_modifier(Modifier::DIM),
            ));
        }
        if !self.suggest.entries.is_empty() {
            for (i, entry) in self
                .suggest
                .entries
                .iter()
                .enumerate()
                .skip(self.suggest.scroll)
                .take(DIR_SUGGEST_WINDOW)
            {
                let suggestion_line = lines.len();
                let active = i == self.suggest.selected;
                let suffix = if entry.is_dir { "/" } else { "" };
                lines.push(Line::from(vec![
                    Span::raw(format!("  {}", super::shell::marker(active))),
                    Span::styled(
                        format!("{}{}", entry.name, suffix),
                        if active {
                            selected_style()
                        } else {
                            Style::default()
                        },
                    ),
                ]));
                surface.register(SettingsPointerTarget {
                    rect: Rect::new(
                        area.x,
                        area.y.saturating_add(suggestion_line as u16),
                        area.width,
                        1,
                    ),
                    action: SettingsPointerAction::Page(
                        super::pointer_actions::SettingsPointerAction::Category(
                            super::pointer_actions::CategoryAction::SuggestionSelect(
                                category_pointer_id(self.id),
                                super::pointer_actions::SuggestionId(entry.replacement.clone()),
                            ),
                        ),
                    ),
                    enabled: true,
                    disabled_reason: None,
                });
            }
            if self.suggest.entries.len() > DIR_SUGGEST_WINDOW {
                lines.push(Line::from(Span::styled(
                    format!(
                        "  ... {} more (up/down to scroll)",
                        self.suggest.entries.len() - DIR_SUGGEST_WINDOW
                    ),
                    muted_style(),
                )));
            }
        }
        lines.push(Line::default());
        let action_line = lines.len();
        lines.push(Line::from(vec![
            Span::styled("[Save]", selected_style()),
            Span::raw("  "),
            Span::styled("[Cancel]", selected_style()),
            Span::raw("  "),
            Span::styled("[Open in $EDITOR]", selected_style()),
            Span::styled("  tab: accept  right: complete", muted_style()),
        ]));
        for (action, x, width) in [
            (
                super::pointer_actions::CategoryAction::PathEditCommit(category_pointer_id(
                    self.id,
                )),
                0u16,
                6u16,
            ),
            (
                super::pointer_actions::CategoryAction::PathEditCancel(category_pointer_id(
                    self.id,
                )),
                8u16,
                8u16,
            ),
            (
                super::pointer_actions::CategoryAction::ExternalEditBegin(
                    category_pointer_id(self.id),
                    super::pointer_actions::CategoryExternalSource::PathEditor,
                ),
                18u16,
                17u16,
            ),
        ] {
            if x.saturating_add(width) > area.width {
                continue;
            }
            surface.register(SettingsPointerTarget {
                rect: Rect::new(
                    area.x + x,
                    area.y.saturating_add(action_line as u16),
                    width,
                    1,
                ),
                action: SettingsPointerAction::Page(
                    super::pointer_actions::SettingsPointerAction::Category(action),
                ),
                enabled: true,
                disabled_reason: None,
            });
        }
        frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), area);
    }
}

fn path_setting_mode(id: SettingId) -> Option<PathSuggestMode> {
    match id {
        SettingId::PackagesDir => Some(PathSuggestMode::Directories),
        SettingId::SandboxDockerfile => Some(PathSuggestMode::FilesAndDirectories),
        _ => None,
    }
}

fn category_pointer_id(id: SettingId) -> super::pointer_actions::SettingId {
    id
}

fn category_setting_from_pointer(id: super::pointer_actions::SettingId) -> Option<SettingId> {
    Some(id)
}

/// Full-area editor for long text and JSON category settings.
pub(super) struct CategoryTextEditor {
    pub(super) id: SettingId,
    editor: VimEditor,
    pub(super) error: Option<String>,
}

impl CategoryTextEditor {
    fn new(id: SettingId, text: String, vim_enabled: bool) -> Self {
        Self {
            id,
            editor: VimEditor::new(&text, vim_enabled),
            error: None,
        }
    }

    fn text(&self) -> &str {
        self.editor.text()
    }

    #[cfg(test)]
    pub(super) fn set_text_for_test(&mut self, text: String) {
        self.editor = VimEditor::new(&text, false);
    }

    pub(super) fn paste(&mut self, text: &str) {
        self.editor.paste(text);
    }

    fn handle_key(&mut self, key: KeyEvent) -> VimEditorOutcome {
        self.editor.handle_key(key)
    }

    fn render(&self, frame: &mut Frame, area: Rect) {
        let title = match &self.error {
            Some(error) => format!("editing {} - {error}", self.id.descriptor().label),
            None => format!("editing {}", self.id.descriptor().label),
        };
        self.editor.render(
            frame,
            area,
            title,
            "ctrl+s: save  ctrl+g: editor  enter: newline  esc: cancel",
        );
    }
}

fn long_text_setting(id: SettingId) -> bool {
    matches!(
        id,
        SettingId::CompactPrompt
            | SettingId::InjectionCheckPrompt
            | SettingId::PreflightPrompt
            | SettingId::CommandProfileWrappers
            | SettingId::CommandProfileCustomProfiles
    )
}

#[derive(Debug, Clone)]
pub(super) struct ShadowedGlobalPrompt {
    setting: SettingId,
    project_config: std::path::PathBuf,
    path: &'static [&'static str],
}

/// Directory autosuggest for the packages-dir field: the ranked candidate
/// list (`entries[0]` drives both the dropdown highlight and the inline
/// ghost), the highlighted row, and the scroll window. Recomputed on every
/// buffer change while editing; cleared when editing ends.
#[derive(Default)]
pub(super) struct DirSuggestState {
    pub(super) entries: Vec<DirSuggestion>,
    pub(super) selected: usize,
    pub(super) scroll: usize,
}

impl DirSuggestState {
    fn clear(&mut self) {
        self.entries.clear();
        self.selected = 0;
        self.scroll = 0;
    }

    /// The inline ghost: the part of the top-ranked replacement past what the
    /// user has typed, or `None` when the best match isn't a prefix
    /// completion.
    fn ghost_for(&self, typed: &str) -> Option<&str> {
        let top = self.entries.first()?;
        top.replacement
            .strip_prefix(typed)
            .filter(|g| !g.is_empty())
    }
}

impl CategoryPage {
    pub(super) fn new(category: Category) -> Self {
        Self {
            category,
            rows: category_rows(category),
            cursor: 0,
            editing: None,
            buf: TextField::default(),
            text_editor: None,
            path_editor: None,
            pending_external_edit: None,
            external_edit_ops: PointerOperationGate::default(),
            status: None,
            reset: ResetButton::default(),
            pending_mouse_capture: None,
            utility_picker: None,
            utility_picker_target: None,
            shadowed_global: None,
            secret_store_confirm: None,
        }
    }

    #[cfg(test)]
    pub(super) fn pointer_surface_fixture(
        mode: CategoryPointerFixtureMode,
        cwd: &std::path::Path,
    ) -> Self {
        use super::ui_page::PickerMode;

        let mut page = Self::new(Category::Interface);
        match mode {
            CategoryPointerFixtureMode::Browse => {}
            CategoryPointerFixtureMode::InlineEdit => {
                page.editing = Some(SettingId::ExitTailLines);
                page.buf = TextField::new("7");
            }
            CategoryPointerFixtureMode::PathEdit => {
                page.path_editor = Some(CategoryPathEditor::new(
                    SettingId::PackagesDir,
                    cwd.display().to_string(),
                    PathSuggestMode::Directories,
                    cwd,
                ));
            }
            CategoryPointerFixtureMode::TextEdit => {
                page.text_editor = Some(CategoryTextEditor::new(
                    SettingId::CompactPrompt,
                    "echo fixture".into(),
                    false,
                ));
            }
            CategoryPointerFixtureMode::ExternalEdit => {
                page.pending_external_edit = Some(CategoryExternalEdit {
                    operation_id: PointerOperationId(1),
                    id: SettingId::CompactPrompt,
                    path: tempfile::NamedTempFile::new()
                        .expect("category external-edit fixture")
                        .into_temp_path(),
                    source: CategoryExternalSource::TextEditor,
                    servicing: false,
                });
            }
            CategoryPointerFixtureMode::PickerList => {
                page.utility_picker = Some(Box::new(UtilityModelPicker {
                    entries: Vec::new(),
                    current: None,
                    mode: PickerMode::List {
                        cursor: 0,
                        scroll: 0,
                    },
                }));
                page.utility_picker_target = Some(SettingId::UtilityModel);
            }
            CategoryPointerFixtureMode::PickerCustom => {
                page.utility_picker = Some(Box::new(UtilityModelPicker {
                    entries: Vec::new(),
                    current: None,
                    mode: PickerMode::Custom {
                        buf: TextField::new("p:model"),
                    },
                }));
                page.utility_picker_target = Some(SettingId::UtilityModel);
            }
        }
        page
    }

    pub(super) fn is_path_editing(&self) -> bool {
        self.path_editor.is_some()
    }

    pub(super) fn is_editing(&self) -> bool {
        self.editing.is_some() || self.text_editor.is_some() || self.path_editor.is_some()
    }

    /// The setting ids in display order (headings filtered out). Index `i`
    /// here is the same as selectable-cursor `i`.
    fn setting_ids(&self) -> Vec<SettingId> {
        self.rows
            .iter()
            .filter_map(|r| match r {
                Row::Setting(id) => Some(*id),
                Row::Heading(_) => None,
            })
            .collect()
    }

    /// Number of selectable rows: every setting plus the trailing reset
    /// button when the category has one.
    fn nav_len(&self) -> usize {
        let settings = self.setting_ids().len();
        settings + usize::from(self.category.reset_label().is_some())
    }

    /// Cursor index of the reset button, if this category has one (the last
    /// selectable row).
    fn reset_cursor(&self) -> Option<usize> {
        self.category
            .reset_label()
            .map(|_| self.setting_ids().len())
    }
}

#[cfg(test)]
#[derive(Debug, Clone, Copy)]
pub(super) enum CategoryPointerFixtureMode {
    Browse,
    InlineEdit,
    PathEdit,
    TextEdit,
    ExternalEdit,
    PickerList,
    PickerCustom,
}

#[cfg(test)]
impl CategoryPointerFixtureMode {
    pub(super) const ALL: [Self; 7] = [
        Self::Browse,
        Self::InlineEdit,
        Self::PathEdit,
        Self::TextEdit,
        Self::ExternalEdit,
        Self::PickerList,
        Self::PickerCustom,
    ];
}

/// Build the descriptor list for a category. Common, foundational settings
/// first; the "Advanced" heading separates rarely-touched tuning and
/// security-sensitive knobs from the common path.
fn category_rows(category: Category) -> Vec<Row> {
    use Row::{Heading, Setting};
    use SettingId as S;
    match category {
        Category::Interface => vec![
            Setting(S::VimMode),
            Setting(S::Thinking),
            Setting(S::RenderAgentMarkdown),
            Setting(S::RenderUserMarkdown),
            Setting(S::Mouse),
            Setting(S::RichTextCopy),
            Setting(S::Emojis),
            Setting(S::DiffStyle),
            Setting(S::Banner),
            Setting(S::ShowCwd),
            Setting(S::ShowBranch),
            Setting(S::CaffeinateDisplay),
            Setting(S::AttentionEnabled),
            Setting(S::AttentionTitle),
            Setting(S::AttentionBell),
            Setting(S::AttentionDesktop),
            Setting(S::ExitTailLines),
        ],
        Category::Behavior => vec![
            Setting(S::DefaultPrimaryAgent),
            Setting(S::LlmMode),
            Setting(S::ApprovalMode),
            Setting(S::SandboxEscalationEnabled),
            Setting(S::PredictNextMessage),
            Setting(S::ShellCompression),
            Heading(SettingHeading {
                title: "Command resource profiles",
                blurb: "Scoped cache/toolchain access for sandboxed developer commands.",
            }),
            Setting(S::CommandProfileRust),
            Setting(S::CommandProfileNode),
            Setting(S::CommandProfilePython),
            Setting(S::CommandProfileGo),
            Setting(S::CommandProfileJava),
            Setting(S::CommandProfileWrappers),
            Setting(S::CommandProfileCustomProfiles),
            Setting(S::InlineThink),
            Setting(S::HintToolCallCorrections),
            Setting(S::TextEmbeddedRecovery),
            Heading(SettingHeading {
                title: "Coding tiers",
                blurb: "Default models for delegated subagents; explicit agent config wins.",
            }),
            Setting(S::CheapCodeModel),
            Setting(S::SmartCodeModel),
            Setting(S::ReasoningModel),
            Setting(S::TranslationModel),
            Setting(S::AgentChoosesSubagentModel),
            Setting(S::DeepthinkEnabled),
            Heading(SettingHeading {
                title: "Utility",
                blurb: "Background models; extra utility rows fall back to utility if \
                        unset. The injection-guard and preflight models live under \
                        Privacy & Safety.",
            }),
            Setting(S::UtilityModel),
            Setting(S::AutoTitleModel),
            Setting(S::SkillInjectionModel),
            Setting(S::PredictNextMessageModel),
            Setting(S::HarnessReportSummarizationModel),
            Setting(S::CompactModel),
            Setting(S::CompactPrompt),
            Setting(S::Instructions),
            Heading(SettingHeading {
                title: "Advanced",
                blurb: "Tuning knobs most users never need. Defaults are sensible; \
                        change these only with a specific reason.",
            }),
            Setting(S::LoopGuardThreshold),
            Setting(S::MaxPrimaryRounds),
            Setting(S::Concurrency),
            Setting(S::ScheduleMaxConcurrent),
            Setting(S::ScheduleAllowUnboundedLoops),
            Setting(S::DelegationMaxParallel),
            Setting(S::GoalSupervisionEnabled),
            Setting(S::GoalSupervisionSkepticCount),
            Setting(S::GoalSupervisionModel),
            Setting(S::GoalSupervisionMaxRounds),
            Setting(S::DialogLockoutMs),
            Setting(S::TimeInjectionInterval),
            Setting(S::PackagesDir),
            Setting(S::AgentDirs),
        ],
        Category::Privacy => vec![
            Setting(S::SandboxDefaultMode),
            Setting(S::SandboxDockerfile),
            Setting(S::SecretStore),
            Setting(S::RedactEnabled),
            Setting(S::RedactScanEnvironment),
            Setting(S::RedactScanDotenv),
            Setting(S::RedactScanSshKeys),
            Setting(S::RedactPatterns),
            Setting(S::InjectionThreshold),
            Setting(S::InjectionResultAction),
            Setting(S::InjectionCheckPrompt),
            Setting(S::InjectionModel),
            Heading(SettingHeading {
                title: "Request preflight",
                blurb: "Rewrite each prompt through the utility model before \
                        sending it (clearer + more concise, same intent). Off by \
                        default; per-session flippable via `/preflight`.",
            }),
            Setting(S::PreflightEnabled),
            Setting(S::PreflightModel),
            Setting(S::PreflightPrompt),
            Heading(SettingHeading {
                title: "Advanced",
                blurb: "Redaction internals and the remote-config opt-in. The \
                        denylist/allowlist and remote-config are \
                        security-sensitive — read each description before changing \
                        it.",
            }),
            Setting(S::RedactExtraDotenvPaths),
            Setting(S::RedactMinSecretLength),
            Setting(S::RedactPlaceholder),
            Setting(S::RedactDenylist),
            Setting(S::RedactAllowlist),
            Setting(S::GitignoreAllow),
            Setting(S::AllowRemoteConfig),
        ],
        Category::Translation => vec![
            Setting(S::TranslationUserLanguage),
            Setting(S::TranslationModelLanguage),
        ],
        Category::Profile => vec![Setting(S::Name)],
    }
}

// ── Value formatting ─────────────────────────────────────────────────────

impl SettingsCx {
    /// The right-column display value for a setting, reflecting the current
    /// `self.extended` (or `self.config`) state. Enum rows show the active
    /// option spelled out; bool rows show on/off with the default noted.
    pub(super) fn category_value(&self, id: SettingId) -> String {
        use SettingId as S;
        let e = &self.extended;
        match id {
            S::VimMode => vim_label(e.tui.vim_mode).to_string(),
            S::Thinking => thinking_label(e.tui.thinking).to_string(),
            S::RenderAgentMarkdown => on_off(e.tui.render_agent_markdown, "on (default)", "off"),
            S::RenderUserMarkdown => on_off(e.tui.render_user_markdown, "on", "off (default)"),
            S::Mouse => on_off(
                e.tui.mouse_capture,
                "on (default — click + drag-select)",
                "off (native terminal select)",
            ),
            S::RichTextCopy => on_off(
                e.tui.rich_text_copy,
                "on (default — Ctrl+Shift+Y copies as rich text)",
                "off",
            ),
            S::Emojis => on_off(
                e.tui.use_emojis,
                "enabled (emoji glyphs)",
                "disabled (default — text-only)",
            ),
            S::DiffStyle => diff_style_label(e.tui.diff_style).to_string(),
            S::Banner => on_off(
                e.tui.banner.enabled,
                "on (default — show startup banner)",
                "off",
            ),
            S::ShowCwd => on_off(e.tui.show_cwd, "on (default — cwd in chrome)", "off"),
            S::ShowBranch => on_off(e.tui.show_branch, "on (default — branch in chrome)", "off"),
            S::CaffeinateDisplay => on_off(
                e.tui.caffeinate_display_awake,
                "keep display on too",
                "system only (default)",
            ),
            S::AttentionEnabled => on_off(
                e.tui.attention.enabled,
                "on (default — toast for attention events)",
                "off (no attention notifications)",
            ),
            S::AttentionTitle => on_off(
                e.tui.attention.title,
                "on (default — title marker for waiting questions)",
                "off (no title marker)",
            ),
            S::AttentionBell => on_off(
                e.tui.attention.bell,
                "on (bell on action-required events)",
                "off (default — no bell)",
            ),
            S::AttentionDesktop => on_off(
                e.tui.attention.desktop,
                "on (desktop notification on attention events)",
                "off (default — no desktop notifications)",
            ),
            S::ExitTailLines => format!(
                "{} (lines of tail dumped to scrollback on exit; 0 none, -1 all)",
                e.tui.exit_tail_lines
            ),
            S::DefaultPrimaryAgent => {
                default_primary_agent_label(e.default_primary_agent).to_string()
            }
            S::LlmMode => llm_mode_label(e.llm_mode).to_string(),
            S::ApprovalMode => approval_mode_label(e.default_approval_mode).to_string(),
            S::SandboxEscalationEnabled => on_off(
                e.sandbox_escalation_enabled,
                "on (default — escalation can be offered)",
                "off (no escalation offers)",
            ),
            S::PredictNextMessage => predict_next_message_label(e.predict_next_message).to_string(),
            S::ShellCompression => shell_compression_label(e.shell_compression).to_string(),
            S::CommandProfileRust => command_profile_enabled_value(
                e.command_resource_profiles.profile_enabled(RUST_TOOLCHAIN),
            ),
            S::CommandProfileNode => command_profile_enabled_value(
                e.command_resource_profiles
                    .profile_enabled(NODE_PACKAGE_MANAGER),
            ),
            S::CommandProfilePython => command_profile_enabled_value(
                e.command_resource_profiles
                    .profile_enabled(PYTHON_TOOLCHAIN),
            ),
            S::CommandProfileGo => command_profile_enabled_value(
                e.command_resource_profiles.profile_enabled(GO_TOOLCHAIN),
            ),
            S::CommandProfileJava => command_profile_enabled_value(
                e.command_resource_profiles.profile_enabled(JAVA_TOOLCHAIN),
            ),
            S::CommandProfileWrappers => map_summary(
                e.command_resource_profiles.wrappers.len(),
                "wrapper mapping",
            ),
            S::CommandProfileCustomProfiles => {
                map_summary(e.command_resource_profiles.profiles.len(), "custom profile")
            }
            S::InlineThink => on_off(
                e.inline_think,
                "on (default — <think> is thinking: chip, dropped later)",
                "off (<think> is response body: kept inline, no chip)",
            ),
            S::HintToolCallCorrections => on_off(
                e.hint_tool_call_corrections,
                "on (tell the model what was corrected)",
                "off (default — repair silently)",
            ),
            S::TextEmbeddedRecovery => {
                text_embedded_recovery_label(e.text_embedded_recovery).to_string()
            }
            S::UtilityModel => e
                .utility_model
                .clone()
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "(unset — provider:model-id)".to_string()),
            S::TranslationModel => model_role_value(e.translation_model.as_deref()),
            S::CheapCodeModel => model_role_value(e.cheap_code.as_deref()),
            S::SmartCodeModel => model_role_value(e.smart_code.as_deref()),
            S::ReasoningModel => model_role_value(e.reasoning.as_deref()),
            S::AgentChoosesSubagentModel => on_off(
                e.agent_chooses_subagent_model,
                "on (honor task/spawn model)",
                "off (role defaults only)",
            ),
            S::DeepthinkEnabled => on_off(
                e.deepthink.enabled,
                "on (advertise deepthink)",
                "off (hidden)",
            ),
            S::AutoTitleModel => model_role_value(e.auto_title.as_deref()),
            S::SkillInjectionModel => model_role_value(e.skill_injection.as_deref()),
            S::PredictNextMessageModel => model_role_value(e.predict_next_message_model.as_deref()),
            S::HarnessReportSummarizationModel => {
                model_role_value(e.harness_report_summarization.as_deref())
            }
            S::CompactModel => e
                .compact_model
                .clone()
                .filter(|s| !s.trim().is_empty())
                .unwrap_or_else(|| "(unset — provider:model-id)".to_string()),
            S::CompactPrompt => e
                .compact_prompt
                .clone()
                .filter(|s| !s.trim().is_empty())
                .unwrap_or_else(|| "(unset — using default brief prompt)".to_string()),
            S::Instructions => list_summary(&e.agent_guidance_files),
            S::LoopGuardThreshold => format!(
                "{} (consecutive identical tool calls before approval; 2 = first repeat)",
                e.loop_guard.effective_threshold()
            ),
            S::MaxPrimaryRounds => format!(
                "{} (primary tool round cap per message; 0 = unlimited)",
                e.max_primary_rounds
            ),
            S::Concurrency => concurrency_label(e.concurrency).to_string(),
            S::ScheduleMaxConcurrent => format!(
                "{} (cap on running scheduled tasks; >= 1)",
                e.schedule.max_concurrent
            ),
            S::ScheduleAllowUnboundedLoops => on_off(
                e.schedule.allow_unbounded_loops,
                "on (requires per-session approval)",
                "off (default)",
            ),
            S::DelegationMaxParallel => format!(
                "{} (cap on inline task parallel entries; >= 1)",
                e.delegation.max_parallel
            ),
            S::GoalSupervisionEnabled => on_off(
                e.goal_supervision.enabled,
                "on (default — budgeted goals verify completion)",
                "off (complete immediately)",
            ),
            S::GoalSupervisionSkepticCount => format!(
                "{} (parallel skeptic scouts; default {})",
                e.goal_supervision.effective_cold_skeptic_count(),
                cockpit_config::extended::DEFAULT_GOAL_SUPERVISION_COLD_SKEPTIC_COUNT
            ),
            S::GoalSupervisionModel => e
                .goal_supervision
                .cold_skeptic_model
                .clone()
                .filter(|s| !s.trim().is_empty())
                .unwrap_or_else(|| "(session model fallback)".to_string()),
            S::GoalSupervisionMaxRounds => format!(
                "{} (failed/inconclusive rounds before intervention; default {})",
                e.goal_supervision.effective_max_verification_attempts(),
                cockpit_config::extended::DEFAULT_GOAL_SUPERVISION_MAX_VERIFICATION_ATTEMPTS
            ),
            S::DialogLockoutMs => format!(
                "{} (answer-dialog input lockout; default 1500)",
                e.dialog.lockout_ms
            ),
            S::TimeInjectionInterval => format!(
                "{} (minutes between [time:] preludes; default 5)",
                e.system_prompt.time_injection_interval_minutes
            ),
            S::PackagesDir => e
                .packages_directory
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "(unset — agent picks default)".to_string()),
            S::AgentDirs => {
                if e.agent_dirs.is_empty() {
                    "(none)".to_string()
                } else {
                    e.agent_dirs
                        .iter()
                        .map(|p| p.display().to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                }
            }
            S::SandboxDefaultMode => {
                sandbox_mode_setting_value(e.sandbox.default_mode, &self.host_capabilities)
            }
            S::SecretStore => {
                crate::tui::capability_gate::secret_store_row_value(&self.host_capabilities)
            }
            S::SandboxDockerfile => e
                .sandbox
                .dockerfile
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "(unset - global default Dockerfile)".to_string()),
            S::RedactEnabled => on_off(
                e.redact.enabled,
                "on (default — scrub every outbound prompt)",
                "off (NO scrubbing — secrets sent verbatim)",
            ),
            S::RedactScanEnvironment => on_off(
                e.redact.scan_environment,
                "on (default — scrub OS env-var values)",
                "off",
            ),
            S::RedactScanDotenv => on_off(
                e.redact.scan_dotenv,
                "on (default — scrub matched env-file values)",
                "off",
            ),
            S::RedactScanSshKeys => on_off(
                e.redact.scan_ssh_keys,
                "on (default — scrub private SSH keys under ~/.ssh)",
                "off",
            ),
            S::RedactPatterns => list_summary(&e.redact.dotenv_patterns),
            S::InjectionThreshold => {
                injection_threshold_label(e.prompt_injection_guard.threshold).to_string()
            }
            S::InjectionResultAction => {
                injection_result_action_label(e.prompt_injection_guard.result_action).to_string()
            }
            S::InjectionCheckPrompt => {
                if e.prompt_injection_guard.check_prompt.is_some() {
                    "(custom template)".to_string()
                } else {
                    "(default template)".to_string()
                }
            }
            S::InjectionModel => e
                .prompt_injection_guard
                .model
                .clone()
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "(unset — falls back to utility model)".to_string()),
            S::PreflightEnabled => on_off(
                e.preflight.enabled,
                "on (rewrite prompts before sending)",
                "off (default)",
            ),
            S::PreflightModel => e
                .preflight
                .model
                .clone()
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "(utility model)".to_string()),
            S::PreflightPrompt => {
                if e.preflight.preflight_prompt.is_some() {
                    "(custom template)".to_string()
                } else {
                    "(default template)".to_string()
                }
            }
            S::RedactExtraDotenvPaths => {
                if e.redact.extra_dotenv_paths.is_empty() {
                    "(none)".to_string()
                } else {
                    e.redact
                        .extra_dotenv_paths
                        .iter()
                        .map(|p| p.display().to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                }
            }
            S::RedactMinSecretLength => format!(
                "{} (shortest value auto-added to the redaction table)",
                e.redact.min_secret_length
            ),
            S::RedactPlaceholder => e.redact.placeholder.clone(),
            S::RedactDenylist => secret_display::masked_list_summary(&e.redact.denylist),
            S::RedactAllowlist => list_summary(&e.redact.allowlist),
            S::GitignoreAllow => list_summary(&e.gitignore_allow),
            S::AllowRemoteConfig => on_off(
                e.allow_remote_config,
                "on (fetch remote .well-known/cockpit config)",
                "off (default — no remote config)",
            ),
            S::TranslationUserLanguage => lang_value(&e.translation.user_language),
            S::TranslationModelLanguage => lang_value(&e.translation.model_language),
            S::Name => e
                .name
                .clone()
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "(unset)".to_string()),
        }
    }
}

fn on_off(v: bool, on: &str, off: &str) -> String {
    if v { on.to_string() } else { off.to_string() }
}

fn model_role_value(value: Option<&str>) -> String {
    value
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| "(unset -> utility/session fallback)".to_string())
}

fn list_summary(v: &[String]) -> String {
    if v.is_empty() {
        "(none)".to_string()
    } else {
        v.join(", ")
    }
}

fn lang_value(s: &str) -> String {
    if s.trim().is_empty() {
        "(unset — disables translation)".to_string()
    } else {
        s.to_string()
    }
}

fn command_profile_enabled_value(enabled: bool) -> String {
    on_off(enabled, "on (default — scoped cache access)", "off")
}

fn map_summary(len: usize, singular: &str) -> String {
    match len {
        0 => "(none)".to_string(),
        1 => format!("1 {singular}"),
        n => format!("{n} {singular}s"),
    }
}

fn pretty_json<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_string_pretty(value).unwrap_or_else(|_| "{}".to_string())
}

fn parse_json_map<T>(raw: &str, label: &str) -> Result<BTreeMap<String, T>, String>
where
    T: serde::de::DeserializeOwned,
{
    if raw.trim().is_empty() {
        return Ok(BTreeMap::new());
    }
    serde_json::from_str(raw).map_err(|e| format!("invalid JSON for {label}: {e}"))
}

fn toggle_command_profile(e: &mut cockpit_config::extended::ExtendedConfig, id: &str) {
    let next = !e.command_resource_profiles.profile_enabled(id);
    e.command_resource_profiles
        .enabled
        .insert(id.to_string(), next);
}

// ── Key handling ─────────────────────────────────────────────────────────

impl SettingsCx {
    pub(super) fn finish_category_page_external_edit(
        &mut self,
        p: &mut CategoryPage,
        operation_id: PointerOperationId,
        outcome: super::pointer_actions::ExternalEditOutcome,
        detail: Option<String>,
    ) {
        let Some(setting) = p
            .pending_external_edit
            .as_ref()
            .filter(|pending| pending.operation_id == operation_id)
            .map(|pending| pending.id)
        else {
            return;
        };
        self.reduce_category_external_edit_result(
            p,
            operation_id,
            super::pointer_actions::CategoryAction::ExternalEditResult(setting, outcome),
            detail,
        );
    }

    fn reduce_category_external_edit_result(
        &mut self,
        p: &mut CategoryPage,
        operation_id: PointerOperationId,
        action: super::pointer_actions::CategoryAction,
        detail: Option<String>,
    ) {
        let super::pointer_actions::CategoryAction::ExternalEditResult(setting, outcome) = action
        else {
            return;
        };
        if !p
            .pending_external_edit
            .as_ref()
            .is_some_and(|pending| pending.operation_id == operation_id && pending.id == setting)
        {
            return;
        }
        if p.pending_external_edit
            .as_ref()
            .map(|pending| pending.operation_id)
            != Some(operation_id)
            || !p.external_edit_ops.complete(operation_id)
        {
            return;
        }
        let Some(pending) = p.pending_external_edit.take() else {
            return;
        };
        match outcome {
            super::pointer_actions::ExternalEditOutcome::Cancelled => {
                p.status = Some(detail.unwrap_or_else(|| "external edit cancelled".into()));
                return;
            }
            super::pointer_actions::ExternalEditOutcome::Failed => {
                let error = detail.unwrap_or_else(|| "external edit failed".into());
                match pending.source {
                    CategoryExternalSource::TextEditor => {
                        if let Some(editor) = p.text_editor.as_mut() {
                            editor.error = Some(error);
                        } else {
                            p.status = Some(error);
                        }
                    }
                    CategoryExternalSource::PathEditor
                    | CategoryExternalSource::Inline
                    | CategoryExternalSource::Cursor => {
                        p.status = Some(error);
                    }
                }
                return;
            }
            super::pointer_actions::ExternalEditOutcome::Saved => {}
        }

        let raw = match std::fs::read_to_string(pending.path.as_ref() as &std::path::Path) {
            Ok(text) => text,
            Err(e) => {
                p.status = Some(format!("editor: failed to read temp file back: {e}"));
                return;
            }
        };
        let without_lf = raw.strip_suffix('\n').unwrap_or(&raw);
        let text = without_lf
            .strip_suffix('\r')
            .unwrap_or(without_lf)
            .to_string();
        let id = pending.id;
        match self.commit_category_text(id, &text) {
            Ok(()) => {
                p.editing = None;
                p.text_editor = None;
                p.path_editor = None;
                p.status = None;
                self.finish_category_save(id, p);
                if let Some(detail) = detail {
                    p.status = Some(format!("saved; {detail}"));
                }
            }
            Err(reason) => {
                self.restore_category_external_edit(p, id, text, pending.source, reason);
            }
        }
    }

    fn restore_category_external_edit(
        &mut self,
        p: &mut CategoryPage,
        id: SettingId,
        text: String,
        source: CategoryExternalSource,
        reason: String,
    ) {
        if matches!(source, CategoryExternalSource::TextEditor)
            || matches!(source, CategoryExternalSource::Cursor) && long_text_setting(id)
        {
            let mut editor =
                CategoryTextEditor::new(id, text, self.extended.tui.vim_mode.vim_enabled());
            editor.error = Some(reason);
            p.text_editor = Some(editor);
            p.path_editor = None;
            p.editing = None;
            p.status = None;
            return;
        }

        if matches!(source, CategoryExternalSource::PathEditor)
            || matches!(source, CategoryExternalSource::Cursor) && path_setting_mode(id).is_some()
        {
            let cwd = self.agents_cwd();
            if let Some(mode) = path_setting_mode(id) {
                p.path_editor = Some(CategoryPathEditor::new(id, text, mode, &cwd));
                p.text_editor = None;
                p.editing = None;
                p.status = Some(reason);
                return;
            }
        }

        p.buf = TextField::new(text);
        p.editing = Some(id);
        p.text_editor = None;
        p.path_editor = None;
        p.status = Some(reason);
    }

    fn handle_category_page_key(&mut self, key: KeyEvent, p: &mut CategoryPage) -> Nav {
        if p.pending_external_edit.is_some() {
            return Nav::Stay;
        }

        if p.secret_store_confirm.is_some() {
            let outcome = p
                .secret_store_confirm
                .as_mut()
                .expect("secret store confirm present")
                .handle_key(key);
            match outcome {
                crate::tui::dialog::DialogOutcome::Continue => {}
                crate::tui::dialog::DialogOutcome::Cancel => {
                    self.finish_secret_store_confirm(p, false);
                }
                crate::tui::dialog::DialogOutcome::Submit(answers) => {
                    let confirm = answers.first().is_some_and(|answer| match answer {
                        crate::tui::dialog::Answer::Single { id } => {
                            id == crate::tui::capability_gate::SECRET_STORE_CONFIRM_ID
                        }
                        _ => false,
                    });
                    self.finish_secret_store_confirm(p, confirm);
                }
            }
            return Nav::Stay;
        }

        if let Some(prompt) = p.shadowed_global.clone() {
            match key.code {
                KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Enter => {
                    p.status = Some(
                        match remove_project_shadow_path(&prompt.project_config, prompt.path) {
                            Ok(true) => format!(
                                "saved; removed project override for {}",
                                prompt.setting.descriptor().label
                            ),
                            Ok(false) => "saved; project override was already absent".to_string(),
                            Err(e) => format!("saved; removing project override failed: {e}"),
                        },
                    );
                    p.shadowed_global = None;
                }
                KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                    p.status = Some("saved; project override kept".to_string());
                    p.shadowed_global = None;
                }
                _ => {}
            }
            return Nav::Stay;
        }

        // Path editor owns input until save/cancel.
        if let Some(mut editor) = p.path_editor.take() {
            let cwd = self.agents_cwd();
            match key.code {
                KeyCode::Char('g') if is_ctrl_g(key) => {
                    match CategoryExternalEdit::new(
                        p.external_edit_ops.begin(),
                        editor.id,
                        editor.text(),
                        CategoryExternalSource::PathEditor,
                    ) {
                        Ok(request) => {
                            p.pending_external_edit = Some(request);
                            p.status = Some("opening $EDITOR...".into());
                        }
                        Err(reason) => {
                            p.external_edit_ops.cancel();
                            p.status = Some(reason);
                        }
                    }
                    p.path_editor = Some(editor);
                }
                KeyCode::Esc => {}
                KeyCode::Enter => {
                    let id = editor.id;
                    let raw = editor.text().to_string();
                    match self.commit_category_text(id, &raw) {
                        Ok(()) => {
                            p.status = None;
                            self.finish_category_save(id, p);
                        }
                        Err(reason) => {
                            p.status = Some(reason);
                            p.path_editor = Some(editor);
                        }
                    }
                }
                KeyCode::Up | KeyCode::Char('k') if !editor.suggest.entries.is_empty() => {
                    let n = editor.suggest.entries.len();
                    editor.suggest.selected =
                        crate::tui::nav::wrap_prev(editor.suggest.selected, n);
                    editor.suggest.scroll = crate::tui::nav::windowed_scroll(
                        editor.suggest.selected,
                        editor.suggest.scroll,
                        n,
                        DIR_SUGGEST_WINDOW,
                    );
                    p.path_editor = Some(editor);
                }
                KeyCode::Down | KeyCode::Char('j') if !editor.suggest.entries.is_empty() => {
                    let n = editor.suggest.entries.len();
                    editor.suggest.selected =
                        crate::tui::nav::wrap_next(editor.suggest.selected, n);
                    editor.suggest.scroll = crate::tui::nav::windowed_scroll(
                        editor.suggest.selected,
                        editor.suggest.scroll,
                        n,
                        DIR_SUGGEST_WINDOW,
                    );
                    p.path_editor = Some(editor);
                }
                KeyCode::Tab => {
                    if let Some(entry) = editor.suggest.entries.get(editor.suggest.selected) {
                        editor.accept(entry.replacement.clone(), &cwd);
                    }
                    p.path_editor = Some(editor);
                }
                KeyCode::Right if editor.suggest.ghost_for(editor.text()).is_some() => {
                    if let Some(top) = editor.suggest.entries.first() {
                        editor.accept(top.replacement.clone(), &cwd);
                    }
                    p.path_editor = Some(editor);
                }
                _ => {
                    editor.buf.handle_key(key);
                    editor.refresh(&cwd);
                    p.path_editor = Some(editor);
                }
            }
            return Nav::Stay;
        }

        // Full-area long text / JSON editor owns input until save/cancel.
        if let Some(mut editor) = p.text_editor.take() {
            match editor.handle_key(key) {
                VimEditorOutcome::Stay => {
                    p.text_editor = Some(editor);
                }
                VimEditorOutcome::Save => {
                    let id = editor.id;
                    let raw = editor.text().to_string();
                    match self.commit_category_text(id, &raw) {
                        Ok(()) => {
                            p.status = None;
                            self.finish_category_save(id, p);
                        }
                        Err(reason) => {
                            editor.error = Some(reason);
                            p.text_editor = Some(editor);
                        }
                    }
                }
                VimEditorOutcome::Cancel => {
                    p.status = None;
                }
                VimEditorOutcome::ExternalEdit => {
                    match CategoryExternalEdit::new(
                        p.external_edit_ops.begin(),
                        editor.id,
                        editor.text(),
                        CategoryExternalSource::TextEditor,
                    ) {
                        Ok(request) => {
                            p.pending_external_edit = Some(request);
                            p.status = Some("opening $EDITOR...".into());
                            editor.error = None;
                        }
                        Err(reason) => {
                            p.external_edit_ops.cancel();
                            editor.error = Some(reason);
                        }
                    }
                    p.text_editor = Some(editor);
                }
            }
            return Nav::Stay;
        }

        // Utility-model picker overlay owns input while open.
        if p.utility_picker.is_some() {
            self.handle_category_utility_picker_key(key, p);
            return Nav::Stay;
        }

        // Inline text/number edit owns input until Enter/Esc.
        if let Some(id) = p.editing {
            match key.code {
                // Every active inline text field publishes this explicit
                // action, including validated numeric fields. The external
                // round trip feeds the same commit validator and restores the
                // inline draft on invalid content, so do not apply the
                // cursor-only long-text/path eligibility filter here.
                KeyCode::Char('g') if is_ctrl_g(key) => {
                    match CategoryExternalEdit::new(
                        p.external_edit_ops.begin(),
                        id,
                        p.buf.text(),
                        CategoryExternalSource::Inline,
                    ) {
                        Ok(request) => {
                            p.pending_external_edit = Some(request);
                            p.status = Some("opening $EDITOR...".into());
                        }
                        Err(reason) => {
                            p.external_edit_ops.cancel();
                            p.status = Some(reason);
                        }
                    }
                }
                KeyCode::Enter => {
                    let raw = p.buf.text().to_string();
                    match self.commit_category_text(id, &raw) {
                        Ok(()) => {
                            p.editing = None;
                            self.finish_category_save(id, p);
                        }
                        Err(reason) => {
                            // Invalid: stay open, show why, persist nothing.
                            p.status = Some(reason);
                        }
                    }
                }
                KeyCode::Esc => {
                    p.editing = None;
                    p.status = None;
                }
                _ => {
                    p.buf.handle_key(key);
                }
            }
            return Nav::Stay;
        }

        let nav_len = p.nav_len();
        match key.code {
            KeyCode::Char('g') if is_ctrl_g(key) => {
                if let Some(id) = p.setting_ids().get(p.cursor).copied()
                    && category_external_editable(id)
                {
                    let seed = self.category_edit_seed(id);
                    match CategoryExternalEdit::new(
                        p.external_edit_ops.begin(),
                        id,
                        &seed,
                        CategoryExternalSource::Cursor,
                    ) {
                        Ok(request) => {
                            p.pending_external_edit = Some(request);
                            p.status = Some("opening $EDITOR...".into());
                        }
                        Err(reason) => {
                            p.external_edit_ops.cancel();
                            p.status = Some(reason);
                        }
                    }
                }
            }
            KeyCode::Char('q') => return Nav::Close,
            KeyCode::Esc | KeyCode::Left | KeyCode::Backspace | KeyCode::Char('h') => {
                return Nav::Back;
            }
            KeyCode::Up | KeyCode::Char('k') => {
                p.reset.disarm();
                p.cursor = crate::tui::nav::wrap_prev(p.cursor, nav_len);
                p.status = None;
            }
            KeyCode::Down | KeyCode::Char('j') => {
                p.reset.disarm();
                p.cursor = crate::tui::nav::wrap_next(p.cursor, nav_len);
                p.status = None;
            }
            KeyCode::Enter | KeyCode::Right | KeyCode::Char('l') => {
                // Reset button is the last selectable row when present.
                if Some(p.cursor) == p.reset_cursor() {
                    if p.reset.activate() == ResetOutcome::Apply {
                        self.reset_category(p);
                        p.status = save_status(self.save_extended());
                    } else {
                        p.status = None;
                    }
                    return Nav::Stay;
                }
                let ids = p.setting_ids();
                let Some(&id) = ids.get(p.cursor) else {
                    return Nav::Stay;
                };
                match id.descriptor().kind {
                    FieldKind::Cycle => {
                        if self.cycle_category_setting(id, p) {
                            self.finish_category_save(id, p);
                        }
                    }
                    FieldKind::EditText | FieldKind::Numeric => {
                        let seed = self.category_edit_seed(id);
                        if let Some(mode) = path_setting_mode(id) {
                            let cwd = self.agents_cwd();
                            p.path_editor = Some(CategoryPathEditor::new(id, seed, mode, &cwd));
                            p.text_editor = None;
                            p.editing = None;
                        } else if long_text_setting(id) {
                            p.text_editor = Some(CategoryTextEditor::new(
                                id,
                                seed,
                                self.extended.tui.vim_mode.vim_enabled(),
                            ));
                            p.path_editor = None;
                            p.editing = None;
                        } else {
                            p.buf = TextField::new(seed);
                            p.editing = Some(id);
                        }
                        p.status = None;
                    }
                    FieldKind::Drill => {
                        return self.drill_category_setting(id, p);
                    }
                }
            }
            _ => {}
        }
        Nav::Stay
    }

    /// Cycle/toggle an in-place setting. Returns whether layered config
    /// should be persisted. Secret-store placement is not a config key.
    fn cycle_category_setting(&mut self, id: SettingId, p: &mut CategoryPage) -> bool {
        use SettingId as S;
        if id == S::SandboxDefaultMode {
            return self.cycle_sandbox_setting(p);
        }
        if id == S::SecretStore {
            self.cycle_secret_store_setting(p);
            return false;
        }
        let e = &mut self.extended;
        match id {
            S::VimMode => e.tui.vim_mode = cycle_vim(e.tui.vim_mode),
            S::Thinking => e.tui.thinking = cycle_thinking(e.tui.thinking),
            S::RenderAgentMarkdown => e.tui.render_agent_markdown = !e.tui.render_agent_markdown,
            S::RenderUserMarkdown => e.tui.render_user_markdown = !e.tui.render_user_markdown,
            S::Mouse => {
                e.tui.mouse_capture = !e.tui.mouse_capture;
                p.pending_mouse_capture = Some(e.tui.mouse_capture);
            }
            S::RichTextCopy => e.tui.rich_text_copy = !e.tui.rich_text_copy,
            S::Emojis => e.tui.use_emojis = !e.tui.use_emojis,
            S::DiffStyle => e.tui.diff_style = cycle_diff_style(e.tui.diff_style),
            S::Banner => e.tui.banner.enabled = !e.tui.banner.enabled,
            S::ShowCwd => e.tui.show_cwd = !e.tui.show_cwd,
            S::ShowBranch => e.tui.show_branch = !e.tui.show_branch,
            S::CaffeinateDisplay => {
                e.tui.caffeinate_display_awake = !e.tui.caffeinate_display_awake
            }
            S::AttentionEnabled => e.tui.attention.enabled = !e.tui.attention.enabled,
            S::AttentionTitle => e.tui.attention.title = !e.tui.attention.title,
            S::AttentionBell => e.tui.attention.bell = !e.tui.attention.bell,
            S::AttentionDesktop => e.tui.attention.desktop = !e.tui.attention.desktop,
            S::DefaultPrimaryAgent => {
                e.default_primary_agent = e.default_primary_agent.cycled();
            }
            S::LlmMode => e.llm_mode = e.llm_mode.cycled(),
            S::ApprovalMode => e.default_approval_mode = e.default_approval_mode.cycled(),
            S::SandboxEscalationEnabled => {
                e.sandbox_escalation_enabled = !e.sandbox_escalation_enabled
            }
            S::PredictNextMessage => e.predict_next_message = e.predict_next_message.cycled(),
            S::ShellCompression => e.shell_compression = e.shell_compression.toggled(),
            S::CommandProfileRust => toggle_command_profile(e, RUST_TOOLCHAIN),
            S::CommandProfileNode => toggle_command_profile(e, NODE_PACKAGE_MANAGER),
            S::CommandProfilePython => toggle_command_profile(e, PYTHON_TOOLCHAIN),
            S::CommandProfileGo => toggle_command_profile(e, GO_TOOLCHAIN),
            S::CommandProfileJava => toggle_command_profile(e, JAVA_TOOLCHAIN),
            S::InlineThink => e.inline_think = !e.inline_think,
            S::HintToolCallCorrections => {
                e.hint_tool_call_corrections = !e.hint_tool_call_corrections
            }
            S::TextEmbeddedRecovery => e.text_embedded_recovery = e.text_embedded_recovery.cycled(),
            S::AgentChoosesSubagentModel => {
                e.agent_chooses_subagent_model = !e.agent_chooses_subagent_model
            }
            S::DeepthinkEnabled => e.deepthink.enabled = !e.deepthink.enabled,
            S::Concurrency => e.concurrency = cycle_concurrency(e.concurrency),
            S::ScheduleAllowUnboundedLoops => {
                e.schedule.allow_unbounded_loops = !e.schedule.allow_unbounded_loops
            }
            S::GoalSupervisionEnabled => e.goal_supervision.enabled = !e.goal_supervision.enabled,
            S::RedactEnabled => e.redact.enabled = !e.redact.enabled,
            S::RedactScanEnvironment => e.redact.scan_environment = !e.redact.scan_environment,
            S::RedactScanDotenv => e.redact.scan_dotenv = !e.redact.scan_dotenv,
            S::RedactScanSshKeys => e.redact.scan_ssh_keys = !e.redact.scan_ssh_keys,
            S::InjectionThreshold => {
                e.prompt_injection_guard.threshold = e.prompt_injection_guard.threshold.cycled()
            }
            S::InjectionResultAction => {
                e.prompt_injection_guard.result_action =
                    e.prompt_injection_guard.result_action.cycled()
            }
            S::PreflightEnabled => e.preflight.enabled = !e.preflight.enabled,
            S::AllowRemoteConfig => e.allow_remote_config = !e.allow_remote_config,
            // Non-cycle ids never reach here.
            _ => {}
        }
        true
    }

    fn cycle_sandbox_setting(&mut self, p: &mut CategoryPage) -> bool {
        use crate::tui::capability_gate::{
            RecheckApply, apply_sandbox_choice, next_settings_sandbox_mode,
        };
        let current = self.extended.sandbox.default_mode;
        let requested = next_settings_sandbox_mode(current, &self.host_capabilities);
        if requested == current {
            p.status = Some("no other sandbox mode is available".into());
            return false;
        }
        let snapshot = self.host_capabilities.clone();
        let outcome =
            apply_sandbox_choice(requested, &snapshot, || self.refresh_host_capabilities());
        match outcome {
            RecheckApply::Applied(mode) => {
                self.extended.sandbox.default_mode = mode;
                true
            }
            RecheckApply::Instruct(instruct) => {
                p.status = Some(instruct.display());
                false
            }
        }
    }

    fn cycle_secret_store_setting(&mut self, p: &mut CategoryPage) {
        use crate::tui::capability_gate::{
            RecheckApply, apply_keyring_choice, displayed_secret_store_placement,
            next_secret_store_placement, secret_store_downgrade_dialog,
            secret_store_switcher_enabled,
        };
        use cockpit_proto::SecretStorePlacement;

        if !secret_store_switcher_enabled(&self.host_capabilities) {
            p.status = Some("secret store is not configured yet".into());
            return;
        }
        let current = displayed_secret_store_placement(&self.host_capabilities);
        let requested = next_secret_store_placement(current);
        match requested {
            SecretStorePlacement::Keyring => {
                let snapshot = self.host_capabilities.clone();
                match apply_keyring_choice(&snapshot, || self.refresh_host_capabilities()) {
                    RecheckApply::Applied(_) => {
                        p.status =
                            Some(self.commit_secret_store_migrate(SecretStorePlacement::Keyring));
                    }
                    RecheckApply::Instruct(instruct) => {
                        p.status = Some(instruct.display());
                    }
                }
            }
            SecretStorePlacement::Database => {
                let keyring_available = self
                    .host_capabilities
                    .feature(cockpit_core::host_capabilities::FEATURE_SECRET_STORE_KEYRING)
                    .is_some_and(|row| row.state.is_available());
                if keyring_available {
                    p.status = Some(
                        crate::tui::capability_gate::SECRET_STORE_DATABASE_REJECTED.to_string(),
                    );
                    return;
                }
                p.secret_store_confirm = Some(secret_store_downgrade_dialog());
                p.status = Some("confirm moving the wrapping key off the OS keyring".into());
            }
            SecretStorePlacement::Unavailable => {}
        }
    }

    fn commit_secret_store_migrate(&mut self, dest: cockpit_proto::SecretStorePlacement) -> String {
        self.secret_store_migrate_calls = self.secret_store_migrate_calls.saturating_add(1);
        if let Some(migrate) = self.secret_store_migrate.clone() {
            return match migrate(dest) {
                Ok(snapshot) => {
                    self.host_capabilities.secret_store = snapshot;
                    "saved".into()
                }
                Err(error) => format!("migrate failed: {error}"),
            };
        }
        self.pending_daemon_request = Some(Request::MigrateKekPlacement { dest });
        "migrating secret storage…".into()
    }

    fn finish_secret_store_confirm(&mut self, p: &mut CategoryPage, confirm: bool) {
        p.secret_store_confirm = None;
        if !confirm {
            p.status = Some("kept OS keyring".into());
            return;
        }
        p.status =
            Some(self.commit_secret_store_migrate(cockpit_proto::SecretStorePlacement::Database));
    }

    /// The edit-buffer seed text for a text/number field.
    fn category_edit_seed(&self, id: SettingId) -> String {
        use SettingId as S;
        let e = &self.extended;
        match id {
            S::ExitTailLines => e.tui.exit_tail_lines.to_string(),
            S::LoopGuardThreshold => e.loop_guard.effective_threshold().to_string(),
            S::MaxPrimaryRounds => e.max_primary_rounds.to_string(),
            S::ScheduleMaxConcurrent => e.schedule.max_concurrent.to_string(),
            S::DelegationMaxParallel => e.delegation.max_parallel.to_string(),
            S::GoalSupervisionSkepticCount => e
                .goal_supervision
                .effective_cold_skeptic_count()
                .to_string(),
            S::GoalSupervisionMaxRounds => e
                .goal_supervision
                .effective_max_verification_attempts()
                .to_string(),
            S::DialogLockoutMs => e.dialog.lockout_ms.to_string(),
            S::TimeInjectionInterval => e.system_prompt.time_injection_interval_minutes.to_string(),
            S::CommandProfileWrappers => pretty_json(&e.command_resource_profiles.wrappers),
            S::CommandProfileCustomProfiles => pretty_json(&e.command_resource_profiles.profiles),
            S::PackagesDir => e
                .packages_directory
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_default(),
            S::SandboxDockerfile => e
                .sandbox
                .dockerfile
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_default(),
            S::InjectionCheckPrompt => e
                .prompt_injection_guard
                .check_prompt
                .clone()
                .unwrap_or_default(),
            S::InjectionModel => e.prompt_injection_guard.model.clone().unwrap_or_default(),
            S::PreflightModel => e.preflight.model.clone().unwrap_or_default(),
            S::PreflightPrompt => e.preflight.preflight_prompt.clone().unwrap_or_default(),
            S::CompactModel => e.compact_model.clone().unwrap_or_default(),
            S::GoalSupervisionModel => e
                .goal_supervision
                .cold_skeptic_model
                .clone()
                .unwrap_or_default(),
            S::CompactPrompt => e.compact_prompt.clone().unwrap_or_default(),
            S::RedactMinSecretLength => e.redact.min_secret_length.to_string(),
            S::RedactPlaceholder => e.redact.placeholder.clone(),
            S::TranslationUserLanguage => e.translation.user_language.clone(),
            S::TranslationModelLanguage => e.translation.model_language.clone(),
            S::Name => e.name.clone().unwrap_or_default(),
            _ => String::new(),
        }
    }

    /// Validate + commit a text/number field. Returns `Err(reason)` to keep
    /// the field open with an inline message (nothing persisted).
    fn commit_category_text(&mut self, id: SettingId, raw: &str) -> Result<(), String> {
        use SettingId as S;
        let trimmed = raw.trim();
        match id {
            S::ExitTailLines => {
                // Accepts any i32: 0 disables, -1 dumps all, positive is a
                // line count. Reject non-integers.
                let v: i32 = trimmed
                    .parse()
                    .map_err(|_| "must be a whole number (-1, 0, or a line count)".to_string())?;
                if v < -1 {
                    return Err("must be -1 (all), 0 (none), or a positive line count".into());
                }
                self.extended.tui.exit_tail_lines = v;
            }
            S::LoopGuardThreshold => {
                let v = parse_min_u32(trimmed, cockpit_config::extended::MIN_LOOP_GUARD_THRESHOLD)?;
                self.extended.loop_guard.repeat_threshold = v;
            }
            S::MaxPrimaryRounds => {
                let v = parse_min_u32(trimmed, 0)?;
                self.extended.max_primary_rounds = v;
            }
            S::ScheduleMaxConcurrent => {
                let v = parse_min_usize(trimmed, 1)?;
                self.extended.schedule.max_concurrent = v;
            }
            S::DelegationMaxParallel => {
                let v = parse_min_usize(trimmed, 1)?;
                self.extended.delegation.max_parallel = v;
            }
            S::GoalSupervisionSkepticCount => {
                let v = parse_min_usize(trimmed, 1)?;
                if v > 5 {
                    return Err("must be between 1 and 5".to_string());
                }
                self.extended.goal_supervision.cold_skeptic_count = v;
            }
            S::GoalSupervisionMaxRounds => {
                let v = parse_min_u32(trimmed, 1)?;
                self.extended.goal_supervision.max_verification_attempts = v;
            }
            S::DialogLockoutMs => {
                let v: u64 = trimmed
                    .parse()
                    .map_err(|_| "must be a whole number of milliseconds (>= 0)".to_string())?;
                self.extended.dialog.lockout_ms = v;
            }
            S::TimeInjectionInterval => {
                let v = parse_min_u32(trimmed, 0)?;
                self.extended.system_prompt.time_injection_interval_minutes = v;
            }
            S::CommandProfileWrappers => {
                self.extended.command_resource_profiles.wrappers =
                    parse_json_map(trimmed, "wrappers")?;
            }
            S::CommandProfileCustomProfiles => {
                self.extended.command_resource_profiles.profiles =
                    parse_json_map(trimmed, "profiles")?;
            }
            S::PackagesDir => {
                self.extended.packages_directory = if trimmed.is_empty() {
                    None
                } else {
                    Some(std::path::PathBuf::from(trimmed))
                };
            }
            S::SandboxDockerfile => {
                self.extended.sandbox.dockerfile = if trimmed.is_empty() {
                    None
                } else {
                    Some(std::path::PathBuf::from(trimmed))
                };
            }
            S::InjectionCheckPrompt => {
                // Blank resets to the built-in default (None).
                self.extended.prompt_injection_guard.check_prompt = if trimmed.is_empty() {
                    None
                } else {
                    Some(trimmed.to_string())
                };
            }
            S::InjectionModel => {
                self.extended.prompt_injection_guard.model = if trimmed.is_empty() {
                    None
                } else {
                    Some(trimmed.to_string())
                };
            }
            S::PreflightModel => {
                // Blank → unset (falls back to the utility model).
                self.extended.preflight.model = if trimmed.is_empty() {
                    None
                } else {
                    Some(trimmed.to_string())
                };
            }
            S::PreflightPrompt => {
                // Blank resets to the built-in default (None).
                self.extended.preflight.preflight_prompt = if trimmed.is_empty() {
                    None
                } else {
                    Some(trimmed.to_string())
                };
            }
            S::CompactModel => {
                // Blank → unset (drafts the brief with the active agent's model).
                self.extended.compact_model = if trimmed.is_empty() {
                    None
                } else {
                    Some(trimmed.to_string())
                };
            }
            S::GoalSupervisionModel => {
                self.extended.goal_supervision.cold_skeptic_model = if trimmed.is_empty() {
                    None
                } else {
                    Some(trimmed.to_string())
                };
            }
            S::CompactPrompt => {
                // Blank resets to the built-in default (None). Keep the raw
                // text otherwise so a multi-line override retains its internal
                // formatting — only leading/trailing whitespace decides
                // unset-vs-set.
                self.extended.compact_prompt = if trimmed.is_empty() {
                    None
                } else {
                    Some(raw.to_string())
                };
            }
            S::RedactMinSecretLength => {
                // The table has a hard four-byte floor; keep the editor aligned with it.
                let v = parse_min_usize(trimmed, 4)?;
                self.extended.redact.min_secret_length = v;
            }
            S::RedactPlaceholder => {
                if trimmed.is_empty() {
                    return Err("placeholder must not be empty".into());
                }
                // Keep the raw (un-trimmed) text — a placeholder may carry
                // meaningful trailing spaces, but reject whitespace-only.
                self.extended.redact.placeholder = raw.to_string();
            }
            S::TranslationUserLanguage => {
                self.extended.translation.user_language = trimmed.to_string();
            }
            S::TranslationModelLanguage => {
                self.extended.translation.model_language = trimmed.to_string();
            }
            S::Name => {
                self.extended.name = if trimmed.is_empty() {
                    None
                } else {
                    Some(trimmed.to_string())
                };
            }
            _ => {}
        }
        Ok(())
    }

    fn finish_category_save(&mut self, id: SettingId, p: &mut CategoryPage) {
        match self.save_extended() {
            Ok(()) => {
                if id == SettingId::SandboxEscalationEnabled {
                    self.pending_daemon_request =
                        Some(cockpit_core::daemon::proto::Request::SetSandboxEscalation {
                            enabled: self.extended.sandbox_escalation_enabled,
                        });
                }
                if let Some(prompt) = self.shadowed_global_prompt(id) {
                    p.status = Some(format!(
                        "saved; project config overrides {} here. Remove that project value? y/n",
                        id.descriptor().label
                    ));
                    p.shadowed_global = Some(prompt);
                } else {
                    p.status = Some("saved".into());
                }
            }
            Err(e) => p.status = Some(format!("save failed: {e}")),
        }
    }

    fn shadowed_global_prompt(&self, id: SettingId) -> Option<ShadowedGlobalPrompt> {
        let path = setting_json_path(id)?;
        let project_root = self.active_project_root.as_ref()?;
        let project_config = super::nearest_project_config_path(project_root);
        if self.config_path == project_config {
            return None;
        }
        let doc = cockpit_config::extended::ExtendedConfigDoc::load(&project_config).ok()?;
        if !doc.raw_has_path(path) {
            return None;
        }
        Some(ShadowedGlobalPrompt {
            setting: id,
            project_config,
            path,
        })
    }

    /// Navigate into a setting's dedicated sub-page.
    fn drill_category_setting(&mut self, id: SettingId, p: &mut CategoryPage) -> Nav {
        use SettingId as S;
        match id {
            S::UtilityModel
            | S::TranslationModel
            | S::CheapCodeModel
            | S::SmartCodeModel
            | S::ReasoningModel
            | S::AutoTitleModel
            | S::SkillInjectionModel
            | S::PredictNextMessageModel
            | S::HarnessReportSummarizationModel
            | S::GoalSupervisionModel
            | S::CompactModel => {
                p.utility_picker = Some(Box::new(UtilityModelPicker::new(
                    &self.config,
                    self.model_setting_value(id),
                )));
                p.utility_picker_target = Some(id);
                p.status = None;
                Nav::Stay
            }
            S::Instructions => Nav::Push(super::instructions_page(InstructionsPage::new())),
            S::RedactPatterns => Nav::Push(super::redact_patterns_page(RedactPatternsPage::new())),
            S::AgentDirs => Nav::Push(super::string_list_page(
                super::string_list::StringListPage::agent_dirs(),
            )),
            S::RedactExtraDotenvPaths => Nav::Push(super::string_list_page(
                super::string_list::StringListPage::extra_dotenv_paths(),
            )),
            S::RedactDenylist => Nav::Push(super::string_list_page(
                super::string_list::StringListPage::redact_denylist(),
            )),
            S::RedactAllowlist => Nav::Push(super::string_list_page(
                super::string_list::StringListPage::redact_allowlist(),
            )),
            S::GitignoreAllow => Nav::Push(super::string_list_page(
                super::string_list::StringListPage::gitignore_allow(),
            )),
            _ => Nav::Stay,
        }
    }

    fn model_setting_value(&self, id: SettingId) -> Option<String> {
        use SettingId as S;
        let e = &self.extended;
        match id {
            S::UtilityModel => e.utility_model.clone(),
            S::TranslationModel => e.translation_model.clone(),
            S::CheapCodeModel => e.cheap_code.clone(),
            S::SmartCodeModel => e.smart_code.clone(),
            S::ReasoningModel => e.reasoning.clone(),
            S::AutoTitleModel => e.auto_title.clone(),
            S::SkillInjectionModel => e.skill_injection.clone(),
            S::PredictNextMessageModel => e.predict_next_message_model.clone(),
            S::HarnessReportSummarizationModel => e.harness_report_summarization.clone(),
            S::GoalSupervisionModel => e.goal_supervision.cold_skeptic_model.clone(),
            S::CompactModel => e.compact_model.clone(),
            _ => None,
        }
        .filter(|s| !s.trim().is_empty())
    }

    fn set_model_setting_value(&mut self, id: SettingId, value: Option<String>) {
        use SettingId as S;
        let e = &mut self.extended;
        match id {
            S::UtilityModel => e.utility_model = value,
            S::TranslationModel => e.translation_model = value,
            S::CheapCodeModel => e.cheap_code = value,
            S::SmartCodeModel => e.smart_code = value,
            S::ReasoningModel => e.reasoning = value,
            S::AutoTitleModel => e.auto_title = value,
            S::SkillInjectionModel => e.skill_injection = value,
            S::PredictNextMessageModel => e.predict_next_message_model = value,
            S::HarnessReportSummarizationModel => e.harness_report_summarization = value,
            S::GoalSupervisionModel => e.goal_supervision.cold_skeptic_model = value,
            S::CompactModel => e.compact_model = value,
            _ => {}
        }
    }

    /// Reset a category's settings to their defaults. Scoped per category so
    /// the affordance is honest (Interface resets only display toggles; it
    /// leaves behavior/privacy alone, and vice versa).
    fn reset_category(&mut self, p: &mut CategoryPage) {
        match p.category {
            Category::Interface => {
                // The whole TuiConfig block back to defaults; non-display
                // fields are untouched.
                self.extended.tui = TuiConfig::default();
                p.pending_mouse_capture = Some(self.extended.tui.mouse_capture);
            }
            Category::Behavior => {
                let d = cockpit_config::extended::ExtendedConfig::default();
                let e = &mut self.extended;
                e.default_primary_agent = d.default_primary_agent;
                e.llm_mode = d.llm_mode;
                e.default_approval_mode = d.default_approval_mode;
                e.sandbox_escalation_enabled = d.sandbox_escalation_enabled;
                e.predict_next_message = d.predict_next_message;
                e.shell_compression = d.shell_compression;
                e.inline_think = d.inline_think;
                e.hint_tool_call_corrections = d.hint_tool_call_corrections;
                e.text_embedded_recovery = d.text_embedded_recovery;
                e.command_resource_profiles = d.command_resource_profiles;
                e.deepthink = d.deepthink;
                e.loop_guard = d.loop_guard;
                e.max_primary_rounds = d.max_primary_rounds;
                e.concurrency = d.concurrency;
                e.schedule = d.schedule;
                e.goal_supervision = d.goal_supervision;
                e.dialog = d.dialog;
                e.system_prompt = d.system_prompt;
                // Utility model, instructions, packages dir, and agent dirs
                // are user content, not "defaults" — preserved.
            }
            Category::Privacy => {
                reset_privacy_category(&mut self.extended);
            }
            Category::Translation | Category::Profile => {}
        }
    }

    /// Key handling for the utility-model picker overlay opened from the
    /// Behavior page. Mirrors the original UI-page picker semantics.
    fn handle_category_utility_picker_key(&mut self, key: KeyEvent, p: &mut CategoryPage) {
        use super::ui_page::{
            PICKER_ACTION_ROWS, PICKER_CLEAR_ROW, PICKER_CUSTOM_ROW, PickerMode,
            picker_window_scroll,
        };
        let Some(picker) = p.utility_picker.as_mut() else {
            return;
        };
        let target = p.utility_picker_target.unwrap_or(SettingId::UtilityModel);
        let entries_len = picker.entries.len();
        match &mut picker.mode {
            PickerMode::Custom { buf } => match key.code {
                KeyCode::Enter => {
                    let new = buf.text().trim().to_string();
                    let value = if new.is_empty() { None } else { Some(new) };
                    self.set_model_setting_value(target, value);
                    p.utility_picker = None;
                    p.utility_picker_target = None;
                    p.status = save_status(self.save_extended());
                }
                KeyCode::Esc => {
                    if picker.entries.is_empty() {
                        p.utility_picker = None;
                        p.utility_picker_target = None;
                    } else {
                        picker.back_to_list();
                    }
                }
                _ => {
                    buf.handle_key(key);
                }
            },
            PickerMode::List { cursor, scroll } => {
                let nav_len = PICKER_ACTION_ROWS + picker.entries.len();
                match key.code {
                    KeyCode::Esc => {
                        p.utility_picker = None;
                        p.utility_picker_target = None;
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        *cursor = crate::tui::nav::wrap_prev(*cursor, nav_len);
                        *scroll = picker_window_scroll(*cursor, *scroll, entries_len);
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        *cursor = crate::tui::nav::wrap_next(*cursor, nav_len);
                        *scroll = picker_window_scroll(*cursor, *scroll, entries_len);
                    }
                    KeyCode::Enter | KeyCode::Right | KeyCode::Char('l') => match *cursor {
                        PICKER_CLEAR_ROW => {
                            self.set_model_setting_value(target, None);
                            p.utility_picker = None;
                            p.utility_picker_target = None;
                            p.status = save_status(self.save_extended());
                        }
                        PICKER_CUSTOM_ROW => {
                            let prefill = picker.current.clone().unwrap_or_default();
                            picker.mode = PickerMode::Custom {
                                buf: TextField::new(prefill),
                            };
                        }
                        idx => {
                            let value = picker
                                .entries
                                .get(idx - PICKER_ACTION_ROWS)
                                .map(|en| en.value());
                            if let Some(value) = value {
                                self.set_model_setting_value(target, Some(value));
                                p.utility_picker = None;
                                p.utility_picker_target = None;
                                p.status = save_status(self.save_extended());
                            }
                        }
                    },
                    _ => {}
                }
            }
        }
    }
}

fn is_ctrl_g(key: KeyEvent) -> bool {
    matches!(key.code, KeyCode::Char('g')) && key.modifiers.contains(KeyModifiers::CONTROL)
}

fn numeric_text_setting(id: SettingId) -> bool {
    matches!(
        id,
        SettingId::ExitTailLines
            | SettingId::LoopGuardThreshold
            | SettingId::MaxPrimaryRounds
            | SettingId::ScheduleMaxConcurrent
            | SettingId::DelegationMaxParallel
            | SettingId::GoalSupervisionSkepticCount
            | SettingId::GoalSupervisionMaxRounds
            | SettingId::DialogLockoutMs
            | SettingId::TimeInjectionInterval
            | SettingId::RedactMinSecretLength
    )
}

fn category_external_editable(id: SettingId) -> bool {
    matches!(id.descriptor().kind, FieldKind::EditText) && !numeric_text_setting(id)
}

#[cfg(test)]
pub(super) fn pointer_inline_editor_sources() -> Vec<(Category, SettingId)> {
    pointer_setting_sources(|id| {
        matches!(
            id.descriptor().kind,
            FieldKind::EditText | FieldKind::Numeric
        ) && path_setting_mode(id).is_none()
            && !long_text_setting(id)
    })
}

#[cfg(test)]
pub(super) fn pointer_text_editor_sources() -> Vec<(Category, SettingId)> {
    pointer_setting_sources(long_text_setting)
}

#[cfg(test)]
pub(super) fn pointer_cursor_external_sources() -> Vec<(Category, SettingId)> {
    pointer_setting_sources(category_external_editable)
}

#[cfg(test)]
pub(super) fn pointer_descriptor_sources() -> Vec<(Category, SettingId)> {
    pointer_setting_sources(|_| true)
}

#[cfg(test)]
fn pointer_setting_sources(predicate: impl Fn(SettingId) -> bool) -> Vec<(Category, SettingId)> {
    let predicate = &predicate;
    Category::ALL
        .into_iter()
        .enumerate()
        .inspect(|(index, category)| {
            assert_eq!(
                *index,
                category.fixture_ordinal(),
                "sealed category inventory"
            );
        })
        .map(|(_, category)| category)
        .flat_map(|category| {
            category_rows(category)
                .into_iter()
                .filter_map(move |row| match row {
                    Row::Setting(id) if predicate(id) => Some((category, id)),
                    _ => None,
                })
        })
        .collect()
}

/// Parse a `>= min` `u32`, rejecting blank/non-numeric/below-floor input.
fn parse_min_u32(raw: &str, min: u32) -> Result<u32, String> {
    if raw.is_empty() {
        return Err("must not be empty".into());
    }
    match raw.parse::<u32>() {
        Ok(v) if v >= min => Ok(v),
        Ok(_) => Err(format!("must be >= {min}")),
        Err(_) => Err(format!("must be a whole number >= {min}")),
    }
}

/// Parse a `>= min` `usize`, rejecting blank/non-numeric/below-floor input.
fn parse_min_usize(raw: &str, min: usize) -> Result<usize, String> {
    if raw.is_empty() {
        return Err("must not be empty".into());
    }
    match raw.parse::<usize>() {
        Ok(v) if v >= min => Ok(v),
        Ok(_) => Err(format!("must be >= {min}")),
        Err(_) => Err(format!("must be a whole number >= {min}")),
    }
}

fn remove_project_shadow_path(
    project_config: &std::path::Path,
    path: &[&str],
) -> Result<bool, String> {
    let mut doc = cockpit_config::extended::ExtendedConfigDoc::load(project_config)
        .map_err(|e| e.to_string())?;
    #[cfg(test)]
    {
        doc.remove_raw_path_and_save(path)
            .map_err(|e| e.to_string())
    }
    #[cfg(not(test))]
    {
        let (removed, rendered) = doc
            .remove_raw_path_rendered(path)
            .map_err(|e| e.to_string())?;
        if removed {
            super::write_settings_text_via_daemon(project_config, None, rendered)?;
        }
        Ok(removed)
    }
}

fn setting_json_path(id: SettingId) -> Option<&'static [&'static str]> {
    use SettingId as S;
    if id == S::SecretStore {
        return None;
    }
    Some(match id {
        S::SecretStore => return None,
        S::VimMode => &["tui", "vim_mode"],
        S::Thinking => &["tui", "thinking"],
        S::RenderAgentMarkdown => &["tui", "render_agent_markdown"],
        S::RenderUserMarkdown => &["tui", "render_user_markdown"],
        S::Mouse => &["tui", "mouse_capture"],
        S::RichTextCopy => &["tui", "rich_text_copy"],
        S::Emojis => &["tui", "use_emojis"],
        S::DiffStyle => &["tui", "diff_style"],
        S::Banner => &["tui", "banner", "enabled"],
        S::ShowCwd => &["tui", "show_cwd"],
        S::ShowBranch => &["tui", "show_branch"],
        S::CaffeinateDisplay => &["tui", "caffeinate_display_awake"],
        S::AttentionEnabled => &["tui", "attention", "enabled"],
        S::AttentionTitle => &["tui", "attention", "title"],
        S::AttentionBell => &["tui", "attention", "bell"],
        S::AttentionDesktop => &["tui", "attention", "desktop"],
        S::LlmMode => &["llm_mode"],
        S::ApprovalMode => &["defaultApprovalMode"],
        S::SandboxEscalationEnabled => &["sandbox_escalation_enabled"],
        S::SandboxDefaultMode => &["sandbox", "defaultMode"],
        S::SandboxDockerfile => &["sandbox", "dockerfile"],
        S::DefaultPrimaryAgent => &["defaultPrimaryAgent"],
        S::PredictNextMessage => &["predictNextMessage"],
        S::ShellCompression => &["shellCompression"],
        S::CommandProfileRust => &["commandResourceProfiles", "enabled", "rust_toolchain"],
        S::CommandProfileNode => &["commandResourceProfiles", "enabled", "node_package_manager"],
        S::CommandProfilePython => &["commandResourceProfiles", "enabled", "python_toolchain"],
        S::CommandProfileGo => &["commandResourceProfiles", "enabled", "go_toolchain"],
        S::CommandProfileJava => &["commandResourceProfiles", "enabled", "java_toolchain"],
        S::CommandProfileWrappers => &["commandResourceProfiles", "wrappers"],
        S::CommandProfileCustomProfiles => &["commandResourceProfiles", "profiles"],
        S::InlineThink => &["inlineThink"],
        S::HintToolCallCorrections => &["hintToolCallCorrections"],
        S::TextEmbeddedRecovery => &["textEmbeddedRecovery"],
        S::AgentChoosesSubagentModel => &["agent_chooses_subagent_model"],
        S::DeepthinkEnabled => &["deepthink", "enabled"],
        S::Concurrency => &["concurrency"],
        S::ExitTailLines => &["tui", "exit_tail_lines"],
        S::LoopGuardThreshold => &["loop_guard", "repeat_threshold"],
        S::MaxPrimaryRounds => &["maxPrimaryRounds"],
        S::ScheduleMaxConcurrent => &["schedule", "max_concurrent"],
        S::ScheduleAllowUnboundedLoops => &["schedule", "allow_unbounded_loops"],
        S::DelegationMaxParallel => &["delegation", "max_parallel"],
        S::GoalSupervisionEnabled => &["goalSupervision", "enabled"],
        S::GoalSupervisionSkepticCount => &["goalSupervision", "coldSkepticCount"],
        S::GoalSupervisionModel => &["goalSupervision", "coldSkepticModel"],
        S::GoalSupervisionMaxRounds => &["goalSupervision", "maxVerificationAttempts"],
        S::DialogLockoutMs => &["dialog", "lockout_ms"],
        S::TimeInjectionInterval => &["system_prompt", "time_injection_interval_minutes"],
        S::PackagesDir => &["packages_directory"],
        S::RedactEnabled => &["redact", "enabled"],
        S::RedactScanEnvironment => &["redact", "scan_environment"],
        S::RedactScanDotenv => &["redact", "scan_dotenv"],
        S::RedactScanSshKeys => &["redact", "scan_ssh_keys"],
        S::RedactMinSecretLength => &["redact", "min_secret_length"],
        S::RedactPlaceholder => &["redact", "placeholder"],
        S::InjectionThreshold => &["prompt_injection_guard", "threshold"],
        S::InjectionResultAction => &["prompt_injection_guard", "result_action"],
        S::InjectionCheckPrompt => &["prompt_injection_guard", "check_prompt"],
        S::InjectionModel => &["prompt_injection_guard", "model"],
        S::PreflightEnabled => &["preflight", "enabled"],
        S::PreflightModel => &["preflight", "model"],
        S::PreflightPrompt => &["preflight", "preflight_prompt"],
        S::CompactModel => &["compact_model"],
        S::CompactPrompt => &["compact_prompt"],
        S::AllowRemoteConfig => &["allow_remote_config"],
        S::TranslationUserLanguage => &["translation", "user_language"],
        S::TranslationModelLanguage => &["translation", "model_language"],
        S::Name => &["name"],
        S::UtilityModel
        | S::TranslationModel
        | S::CheapCodeModel
        | S::SmartCodeModel
        | S::ReasoningModel
        | S::AutoTitleModel
        | S::SkillInjectionModel
        | S::PredictNextMessageModel
        | S::HarnessReportSummarizationModel
        | S::AgentDirs
        | S::GitignoreAllow
        | S::RedactExtraDotenvPaths
        | S::RedactDenylist
        | S::RedactAllowlist
        | S::Instructions
        | S::RedactPatterns => return None,
    })
}

// ── Rendering ────────────────────────────────────────────────────────────

impl SettingsCx {
    pub(super) fn render_category_page(&self, frame: &mut Frame, area: Rect, p: &CategoryPage) {
        if let Some(confirm) = &p.secret_store_confirm {
            let prompt = confirm
                .pages()
                .first()
                .map(|page| page.prompt.as_str())
                .unwrap_or(crate::tui::capability_gate::SECRET_STORE_DOWNGRADE_PROMPT);
            frame.render_widget(
                Paragraph::new(vec![
                    Line::from(prompt.to_string()),
                    Line::default(),
                    Line::from("[Confirm]  [Cancel]"),
                ])
                .wrap(Wrap { trim: false }),
                area,
            );
            return;
        }
        if let Some(prompt) = &p.shadowed_global {
            let label = prompt.setting.descriptor().label;
            frame.render_widget(
                Paragraph::new(vec![
                    Line::from(format!(
                        "Saved globally, but the project overrides {label}."
                    )),
                    Line::default(),
                    Line::from("Remove that project override?"),
                    Line::default(),
                    Line::from("[Remove override]  [Keep override]"),
                ]),
                area,
            );
            for (choice, x, width) in [
                (
                    super::pointer_actions::ConfirmationChoice::Confirm,
                    0u16,
                    17u16,
                ),
                (
                    super::pointer_actions::ConfirmationChoice::Cancel,
                    19u16,
                    15u16,
                ),
            ] {
                if area.height <= 4 || x.saturating_add(width) > area.width {
                    continue;
                }
                self.pointer_surface.register(SettingsPointerTarget {
                    rect: Rect::new(area.x + x, area.y.saturating_add(4), width, 1),
                    action: SettingsPointerAction::Page(
                        super::pointer_actions::SettingsPointerAction::Category(
                            super::pointer_actions::CategoryAction::Confirm(
                                category_pointer_id(prompt.setting),
                                choice,
                            ),
                        ),
                    ),
                    enabled: true,
                    disabled_reason: None,
                });
            }
            return;
        }

        if let Some(pending) = &p.pending_external_edit {
            frame.render_widget(
                Paragraph::new(format!(
                    "Opening {} in $EDITOR…",
                    pending.id.descriptor().label
                )),
                area,
            );
            return;
        }

        if let Some(editor) = &p.path_editor {
            editor.render(frame, area, &self.pointer_surface);
            return;
        }

        if let Some(editor) = &p.text_editor {
            editor.render(frame, area);
            let action_y = area.bottom().saturating_sub(1);
            for (action, x, width) in [
                (
                    super::pointer_actions::CategoryAction::TextEditorSave(category_pointer_id(
                        editor.id,
                    )),
                    0,
                    6,
                ),
                (
                    super::pointer_actions::CategoryAction::TextEditorCancel(category_pointer_id(
                        editor.id,
                    )),
                    8u16,
                    8u16,
                ),
                (
                    super::pointer_actions::CategoryAction::ExternalEditBegin(
                        category_pointer_id(editor.id),
                        super::pointer_actions::CategoryExternalSource::TextEditor,
                    ),
                    18u16,
                    17u16,
                ),
            ] {
                if x.saturating_add(width) > area.width {
                    continue;
                }
                self.pointer_surface.register(SettingsPointerTarget {
                    rect: Rect::new(area.x + x, action_y, width, 1),
                    action: SettingsPointerAction::Page(
                        super::pointer_actions::SettingsPointerAction::Category(action),
                    ),
                    enabled: true,
                    disabled_reason: None,
                });
            }
            frame.render_widget(
                Line::from(vec![
                    Span::styled("[Save]", selected_style()),
                    Span::raw("  "),
                    Span::styled("[Cancel]", selected_style()),
                    Span::raw("  "),
                    Span::styled("[Open in $EDITOR]", selected_style()),
                ]),
                Rect::new(area.x, action_y, area.width, 1),
            );
            return;
        }

        if let Some(picker) = &p.utility_picker {
            self.render_utility_picker(
                frame,
                area,
                picker,
                p.utility_picker_target.unwrap_or(SettingId::UtilityModel),
            );
            return;
        }

        let (settings_area, help_area) = match settings_text_columns(area) {
            TextColumnLayout::Two { left, right } => (left, right),
            TextColumnLayout::Stacked { top, bottom } => (top, bottom),
        };

        let mut lines: Vec<Line<'static>> = Vec::new();
        let mut controls = Vec::new();
        lines.push(Line::from(Span::styled(
            p.category.heading().to_string(),
            heading_style(),
        )));
        controls.push(None);
        lines.push(Line::default());
        controls.push(None);

        let ids = p.setting_ids();
        let label_w = ids
            .iter()
            .map(|id| id.descriptor().label.chars().count())
            .max()
            .unwrap_or(0);

        let mut selected_line = 0usize;
        let mut sel = 0usize;
        let mut inline_actions = None;
        let mut cursor_external_action = None;
        for row in &p.rows {
            match row {
                Row::Heading(heading) => {
                    lines.push(Line::default());
                    controls.push(None);
                    lines.push(Line::from(Span::styled(
                        format!("-- {} --", heading.title),
                        muted_style().add_modifier(Modifier::BOLD),
                    )));
                    controls.push(None);
                    let before = lines.len();
                    push_wrapped_text(
                        &mut lines,
                        settings_area.width,
                        heading.blurb,
                        muted_style(),
                    );
                    controls.resize(lines.len(), None);
                    debug_assert!(lines.len() >= before);
                }
                Row::Setting(id) => {
                    let on_cursor = sel == p.cursor;
                    if on_cursor {
                        selected_line = lines.len();
                    }
                    let before = lines.len();
                    if p.editing == Some(*id) {
                        push_label_text_field_row(
                            &mut lines,
                            settings_area.width,
                            on_cursor,
                            id.descriptor().label,
                            label_w,
                            p.buf.text(),
                            p.buf.cursor(),
                        );
                    } else {
                        push_label_value_row(
                            &mut lines,
                            settings_area.width,
                            on_cursor,
                            id.descriptor().label,
                            label_w,
                            &self.category_value(*id),
                            muted_style(),
                        );
                    }
                    let action = if p.editing == Some(*id) {
                        super::pointer_actions::CategoryAction::InlineEditBegin(
                            category_pointer_id(*id),
                        )
                    } else {
                        super::pointer_actions::CategoryAction::DescriptorActivate(
                            category_pointer_id(*id),
                        )
                    };
                    controls.resize(
                        lines.len(),
                        Some((
                            super::pointer_actions::SettingsPointerAction::Category(action),
                            true,
                            None,
                        )),
                    );
                    if on_cursor && p.editing == Some(*id) {
                        let line = lines.len();
                        lines.push(Line::from(vec![
                            Span::styled("[Save]", selected_style()),
                            Span::raw("  "),
                            Span::styled("[Cancel]", selected_style()),
                            Span::raw("  "),
                            Span::styled("[Open in $EDITOR]", selected_style()),
                        ]));
                        controls.push(None);
                        inline_actions = Some((line, *id));
                        selected_line = line;
                    }
                    // Keep the selected row's explicit external-editor action
                    // adjacent to its source control. Appending it after the
                    // entire category made normal focus scrolling clip the
                    // action even while the owning setting was visible.
                    if on_cursor && p.editing.is_none() && category_external_editable(*id) {
                        let line = lines.len();
                        lines.push(Line::from("[Open selected in $EDITOR]"));
                        controls.push(None);
                        cursor_external_action = Some((line, *id));
                        // The action is part of the selected control's focus
                        // footprint. Anchor viewport correction here so the
                        // source row immediately above and its action remain
                        // visible together instead of clipping the action at
                        // the lower edge.
                        selected_line = line;
                    }
                    debug_assert!(lines.len() > before);
                    sel += 1;
                }
            }
        }

        if let Some(label) = p.category.reset_label() {
            lines.push(Line::default());
            controls.push(None);
            if Some(p.cursor) == p.reset_cursor() {
                selected_line = lines.len();
            }
            lines.push(
                p.reset
                    .render_line(Some(p.cursor) == p.reset_cursor(), label),
            );
            controls.push(Some((
                super::pointer_actions::SettingsPointerAction::Category(
                    super::pointer_actions::CategoryAction::Reset,
                ),
                true,
                None,
            )));
        }

        if let Some(status) = &p.status {
            lines.push(Line::default());
            controls.push(None);
            lines.push(Line::from(Span::styled(status.clone(), warning_style())));
            controls.push(None);
        }

        self.scroll_states.render_control_lines(
            frame,
            settings_area,
            format!("category:{:?}", p.category),
            (lines, Some(selected_line)),
            controls,
            (
                &self.pointer_surface,
                super::shell::SettingsScrollRegionId("category:settings"),
            )
                .into(),
        );
        if let Some((line, id)) = inline_actions {
            let offset = self
                .scroll_states
                .offset_for(&format!("category:{:?}", p.category));
            if let Some(screen_row) = line.checked_sub(offset)
                && screen_row < usize::from(settings_area.height)
            {
                for (action, x, width) in [
                    (
                        super::pointer_actions::CategoryAction::InlineEditCommit(
                            category_pointer_id(id),
                        ),
                        0,
                        6,
                    ),
                    (
                        super::pointer_actions::CategoryAction::InlineEditCancel(
                            category_pointer_id(id),
                        ),
                        8u16,
                        8u16,
                    ),
                    (
                        super::pointer_actions::CategoryAction::ExternalEditBegin(
                            category_pointer_id(id),
                            super::pointer_actions::CategoryExternalSource::Inline,
                        ),
                        18u16,
                        17u16,
                    ),
                ] {
                    if x.saturating_add(width) > settings_area.width {
                        continue;
                    }
                    self.pointer_surface.register(SettingsPointerTarget {
                        rect: Rect::new(
                            settings_area.x.saturating_add(x),
                            settings_area.y.saturating_add(screen_row as u16),
                            width,
                            1,
                        ),
                        action: SettingsPointerAction::Page(
                            super::pointer_actions::SettingsPointerAction::Category(action),
                        ),
                        enabled: true,
                        disabled_reason: None,
                    });
                }
            }
        }
        if let Some((line, id)) = cursor_external_action {
            let offset = self
                .scroll_states
                .offset_for(&format!("category:{:?}", p.category));
            if let Some(screen_row) = line.checked_sub(offset)
                && screen_row < usize::from(settings_area.height)
                && settings_area.width >= 26
            {
                self.pointer_surface.register(SettingsPointerTarget {
                    rect: Rect::new(
                        settings_area.x,
                        settings_area.y.saturating_add(screen_row as u16),
                        26,
                        1,
                    ),
                    action: SettingsPointerAction::Page(
                        super::pointer_actions::SettingsPointerAction::Category(
                            super::pointer_actions::CategoryAction::ExternalEditBegin(
                                category_pointer_id(id),
                                super::pointer_actions::CategoryExternalSource::Cursor,
                            ),
                        ),
                    ),
                    enabled: true,
                    disabled_reason: None,
                });
            }
        }

        let mut help: Vec<Line<'static>> = Vec::new();
        help.push(Line::from(Span::styled(
            p.category.intro().to_string(),
            muted_style(),
        )));
        if let Some(&id) = ids.get(p.cursor) {
            help.push(Line::default());
            help.push(Line::from(Span::styled(
                id.descriptor().label.to_string(),
                Style::default()
                    .fg(ratatui::style::Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )));
            let help_text = if id == SettingId::SecretStore {
                crate::tui::capability_gate::secret_store_row_help(&self.host_capabilities)
                    .to_string()
            } else {
                id.descriptor().help.to_string()
            };
            help.push(Line::from(Span::styled(help_text, muted_style())));
        } else if Some(p.cursor) == p.reset_cursor()
            && let Some(label) = p.category.reset_label()
        {
            help.push(Line::default());
            help.push(Line::from(Span::styled(
                label.to_string(),
                Style::default()
                    .fg(ratatui::style::Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )));
            help.push(Line::from(Span::styled(
                "Restore this category's settings to their built-in defaults. \
                 Your content (names, languages, model picks, file lists, privacy lists) is kept."
                    .to_string(),
                muted_style(),
            )));
        }
        frame.render_widget(Paragraph::new(help).wrap(Wrap { trim: false }), help_area);
    }
}
fn reset_privacy_category(e: &mut cockpit_config::extended::ExtendedConfig) {
    let preserved_dotenv_patterns = e.redact.dotenv_patterns.clone();
    let preserved_extra_dotenv_paths = e.redact.extra_dotenv_paths.clone();
    let preserved_denylist = e.redact.denylist.clone();
    let preserved_allowlist = e.redact.allowlist.clone();
    let preserved_gitignore_allow = e.gitignore_allow.clone();

    e.redact = cockpit_config::extended::RedactConfig {
        dotenv_patterns: preserved_dotenv_patterns,
        extra_dotenv_paths: preserved_extra_dotenv_paths,
        denylist: preserved_denylist,
        allowlist: preserved_allowlist,
        ..cockpit_config::extended::RedactConfig::default()
    };
    e.gitignore_allow = preserved_gitignore_allow;
    e.prompt_injection_guard = cockpit_config::extended::PromptInjectionGuardConfig::default();
    e.allow_remote_config = false;
}

#[cfg(test)]
impl CategoryPage {
    /// Test helper: the selectable-cursor index of a setting on this page,
    /// or `None` if the setting isn't on it.
    pub(super) fn cursor_of(&self, id: SettingId) -> Option<usize> {
        self.setting_ids().iter().position(|s| *s == id)
    }

    /// Test helper: the selectable-cursor index of the reset button, if the
    /// category has one.
    pub(super) fn cursor_of_reset(&self) -> Option<usize> {
        self.reset_cursor()
    }
}

impl SettingsPage for CategoryPage {
    fn pointer_surface_kind(&self) -> super::SettingsPointerSurfaceKind {
        super::SettingsPointerSurfaceKind::Category
    }

    fn pointer_surface_token(&self) -> u64 {
        let mode = if let Some(picker) = &self.utility_picker {
            match &picker.mode {
                super::ui_page::PickerMode::List { .. } => 5,
                super::ui_page::PickerMode::Custom { .. } => 6,
            }
        } else if self.pending_external_edit.is_some() {
            4
        } else if self.text_editor.is_some() {
            3
        } else if self.path_editor.is_some() {
            2
        } else if self.editing.is_some() {
            1
        } else {
            0
        };
        600 + self.category as u64 * 7 + mode
    }

    fn resolve_header_back(&self) -> super::SettingsLocalBack {
        if self.editing.is_some()
            || self.path_editor.is_some()
            || self.text_editor.is_some()
            || self.utility_picker.is_some()
            || self.shadowed_global.is_some()
            || self.pending_external_edit.is_some()
        {
            super::SettingsLocalBack::LocalBack
        } else {
            super::SettingsLocalBack::NoLocalBack
        }
    }

    fn handle_key(&mut self, cx: &mut SettingsCx, key: KeyEvent) -> Nav {
        cx.handle_category_page_key(key, self)
    }

    fn render(&self, cx: &SettingsCx, frame: &mut Frame, area: Rect) {
        cx.render_category_page(frame, area, self);
    }

    fn handle_pointer_control(
        &mut self,
        cx: &mut SettingsCx,
        action: super::pointer_actions::SettingsPointerAction,
    ) -> Nav {
        use super::pointer_actions::{CategoryAction, SettingsPointerAction, UtilityModelAction};
        match action {
            SettingsPointerAction::Category(action) => match action {
                CategoryAction::PathEditBegin(_) => Nav::Stay,
                CategoryAction::SuggestionSelect(id, row) => {
                    let Some(editor) = self.path_editor.as_mut() else {
                        return Nav::Stay;
                    };
                    if category_pointer_id(editor.id) != id {
                        return Nav::Stay;
                    }
                    let Some(index) = editor
                        .suggest
                        .entries
                        .iter()
                        .position(|entry| entry.replacement == row.0)
                    else {
                        return Nav::Stay;
                    };
                    editor.suggest.selected = index;
                    let _ = cx.handle_category_page_key(
                        KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE),
                        self,
                    );
                    cx.handle_category_page_key(
                        KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
                        self,
                    )
                }
                CategoryAction::PathEditCommit(id)
                    if self
                        .path_editor
                        .as_ref()
                        .is_some_and(|editor| category_pointer_id(editor.id) == id) =>
                {
                    cx.handle_category_page_key(
                        KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
                        self,
                    )
                }
                CategoryAction::PathEditCancel(id)
                    if self
                        .path_editor
                        .as_ref()
                        .is_some_and(|editor| category_pointer_id(editor.id) == id) =>
                {
                    cx.handle_category_page_key(
                        KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE),
                        self,
                    )
                }
                CategoryAction::TextEditorSave(id)
                    if self
                        .text_editor
                        .as_ref()
                        .is_some_and(|editor| category_pointer_id(editor.id) == id) =>
                {
                    cx.handle_category_page_key(
                        KeyEvent::new(KeyCode::Char('s'), KeyModifiers::CONTROL),
                        self,
                    )
                }
                CategoryAction::TextEditorCancel(id)
                    if self
                        .text_editor
                        .as_ref()
                        .is_some_and(|editor| category_pointer_id(editor.id) == id) =>
                {
                    cx.handle_category_page_key(
                        KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE),
                        self,
                    )
                }
                CategoryAction::PickerSelect(id, option) => {
                    let Some(target) = self.utility_picker_target else {
                        return Nav::Stay;
                    };
                    if category_pointer_id(target) != id {
                        return Nav::Stay;
                    }
                    let Some(picker) = self.utility_picker.as_mut() else {
                        return Nav::Stay;
                    };
                    let super::ui_page::PickerMode::List { cursor, .. } = &mut picker.mode else {
                        return Nav::Stay;
                    };
                    let Some(index) = picker
                        .entries
                        .iter()
                        .position(|entry| entry.value() == option.0)
                    else {
                        return Nav::Stay;
                    };
                    *cursor = super::ui_page::PICKER_ACTION_ROWS + index;
                    cx.handle_category_utility_picker_key(
                        KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
                        self,
                    );
                    Nav::Stay
                }
                CategoryAction::Confirm(id, choice) => {
                    if self
                        .shadowed_global
                        .as_ref()
                        .is_none_or(|prompt| category_pointer_id(prompt.setting) != id)
                    {
                        return Nav::Stay;
                    }
                    let code = match choice {
                        super::pointer_actions::ConfirmationChoice::Confirm => KeyCode::Enter,
                        super::pointer_actions::ConfirmationChoice::Cancel => KeyCode::Esc,
                    };
                    cx.handle_category_page_key(KeyEvent::new(code, KeyModifiers::NONE), self)
                }
                CategoryAction::ExternalEditBegin(id, source) => {
                    let Some(setting) = category_setting_from_pointer(id) else {
                        return Nav::Stay;
                    };
                    let source_matches = match source {
                        super::pointer_actions::CategoryExternalSource::Cursor => {
                            self.editing.is_none()
                                && self.path_editor.is_none()
                                && self.text_editor.is_none()
                                && self
                                    .setting_ids()
                                    .get(self.cursor)
                                    .is_some_and(|candidate| *candidate == setting)
                        }
                        super::pointer_actions::CategoryExternalSource::Inline => {
                            self.editing == Some(setting)
                        }
                        super::pointer_actions::CategoryExternalSource::PathEditor => self
                            .path_editor
                            .as_ref()
                            .is_some_and(|editor| editor.id == setting),
                        super::pointer_actions::CategoryExternalSource::TextEditor => self
                            .text_editor
                            .as_ref()
                            .is_some_and(|editor| editor.id == setting),
                    };
                    if !source_matches || self.pending_external_edit.is_some() {
                        return Nav::Stay;
                    }
                    cx.handle_category_page_key(
                        KeyEvent::new(KeyCode::Char('g'), KeyModifiers::CONTROL),
                        self,
                    )
                }
                CategoryAction::DescriptorActivate(id) => {
                    let Some(setting) = category_setting_from_pointer(id) else {
                        return Nav::Stay;
                    };
                    let Some(index) = self
                        .setting_ids()
                        .iter()
                        .position(|candidate| *candidate == setting)
                    else {
                        return Nav::Stay;
                    };
                    self.cursor = index;
                    cx.handle_category_page_key(
                        KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
                        self,
                    )
                }
                CategoryAction::InlineEditBegin(id) => {
                    let Some(setting) = category_setting_from_pointer(id) else {
                        return Nav::Stay;
                    };
                    if self.editing != Some(setting) {
                        return Nav::Stay;
                    }
                    self.cursor = self
                        .setting_ids()
                        .iter()
                        .position(|candidate| *candidate == setting)
                        .unwrap_or(self.cursor);
                    Nav::Stay
                }
                CategoryAction::InlineEditCommit(id)
                    if self
                        .editing
                        .is_some_and(|editing| category_pointer_id(editing) == id) =>
                {
                    cx.handle_category_page_key(
                        KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
                        self,
                    )
                }
                CategoryAction::InlineEditCancel(id)
                    if self
                        .editing
                        .is_some_and(|editing| category_pointer_id(editing) == id) =>
                {
                    cx.handle_category_page_key(
                        KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE),
                        self,
                    )
                }
                CategoryAction::Reset => {
                    let Some(index) = self.reset_cursor() else {
                        return Nav::Stay;
                    };
                    self.cursor = index;
                    cx.handle_category_page_key(
                        KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
                        self,
                    )
                }
                CategoryAction::InlineEditCommit(_)
                | CategoryAction::InlineEditCancel(_)
                | CategoryAction::ExternalEditResult(_, _)
                | CategoryAction::PathEditCommit(_)
                | CategoryAction::PathEditCancel(_)
                | CategoryAction::TextEditorSave(_)
                | CategoryAction::TextEditorCancel(_) => Nav::Stay,
            },
            SettingsPointerAction::UtilityModel(action) => {
                let Some(picker) = self.utility_picker.as_mut() else {
                    return Nav::Stay;
                };
                use super::ui_page::{
                    PICKER_ACTION_ROWS, PICKER_CLEAR_ROW, PICKER_CUSTOM_ROW, PickerMode,
                };
                match (&mut picker.mode, action) {
                    (PickerMode::List { cursor, .. }, UtilityModelAction::Clear) => {
                        *cursor = PICKER_CLEAR_ROW
                    }
                    (PickerMode::List { cursor, .. }, UtilityModelAction::OpenCustom) => {
                        *cursor = PICKER_CUSTOM_ROW
                    }
                    (PickerMode::List { cursor, .. }, UtilityModelAction::Select(id)) => {
                        let Some(index) = picker
                            .entries
                            .iter()
                            .position(|entry| entry.value() == id.0)
                        else {
                            return Nav::Stay;
                        };
                        *cursor = PICKER_ACTION_ROWS + index;
                    }
                    (PickerMode::Custom { .. }, UtilityModelAction::EditCustom) => {
                        return Nav::Stay;
                    }
                    (PickerMode::Custom { .. }, UtilityModelAction::CommitCustom) => {
                        cx.handle_category_utility_picker_key(
                            KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
                            self,
                        );
                        return Nav::Stay;
                    }
                    (PickerMode::Custom { .. }, UtilityModelAction::CancelCustom)
                    | (_, UtilityModelAction::Back) => {
                        cx.handle_category_utility_picker_key(
                            KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE),
                            self,
                        );
                        return Nav::Stay;
                    }
                    _ => return Nav::Stay,
                }
                cx.handle_category_utility_picker_key(
                    KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
                    self,
                );
                Nav::Stay
            }
            _ => Nav::Stay,
        }
    }

    fn handle_pointer_control_at(
        &mut self,
        cx: &mut SettingsCx,
        action: super::pointer_actions::SettingsPointerAction,
        column: u16,
        _row: u16,
    ) -> Nav {
        if matches!(
            &action,
            super::pointer_actions::SettingsPointerAction::Category(
                super::pointer_actions::CategoryAction::PathEditBegin(_)
            )
        ) && let Some(editor) = self.path_editor.as_mut()
        {
            let field_x = cx
                .pointer_surface
                .targets
                .borrow()
                .iter()
                .find(|target| {
                    target.action == super::shell::SettingsPointerAction::Page(action.clone())
                })
                .map_or(column, |target| target.rect.x);
            editor
                .buf
                .set_cursor_display_col(usize::from(column.saturating_sub(field_x)));
            return Nav::Stay;
        }
        if matches!(
            &action,
            super::pointer_actions::SettingsPointerAction::UtilityModel(
                super::pointer_actions::UtilityModelAction::EditCustom
            )
        ) && let Some(picker) = self.utility_picker.as_mut()
            && let super::ui_page::PickerMode::Custom { buf } = &mut picker.mode
        {
            let value_x = cx
                .pointer_surface
                .area
                .get()
                .map_or(2, |area| area.x.saturating_add(2));
            buf.set_cursor_display_col(usize::from(column.saturating_sub(value_x)));
            return Nav::Stay;
        }
        self.handle_pointer_control(cx, action)
    }

    fn handle_pointer_scroll(
        &mut self,
        _cx: &mut SettingsCx,
        region: super::shell::SettingsScrollRegionId,
        delta: isize,
    ) -> Nav {
        if self.shadowed_global.take().is_some() {
            self.status = Some("saved; project override kept".into());
            return Nav::Stay;
        }
        if region == super::shell::SettingsScrollRegionId("category:utility-picker") {
            if let Some(picker) = self.utility_picker.as_mut()
                && let super::ui_page::PickerMode::List { cursor, scroll } = &mut picker.mode
            {
                let last = super::ui_page::PICKER_ACTION_ROWS + picker.entries.len() - 1;
                *cursor = cursor.saturating_add_signed(delta).min(last);
                *scroll =
                    super::ui_page::picker_window_scroll(*cursor, *scroll, picker.entries.len());
            }
        } else if region == super::shell::SettingsScrollRegionId("category:settings")
            && self.text_editor.is_none()
            && self.utility_picker.is_none()
        {
            self.reset.disarm();
            self.cursor = self
                .cursor
                .saturating_add_signed(delta)
                .min(self.nav_len().saturating_sub(1));
        }
        Nav::Stay
    }

    fn cancel_pointer_transients(&mut self) {
        self.reset.disarm();
        self.shadowed_global = None;
        self.external_edit_ops.cancel();
        self.pending_external_edit = None;
    }

    fn title(&self, cx: &SettingsCx) -> String {
        format!(
            "{} › {}",
            cockpit_core::welcome::display_path(&cx.config_path),
            self.category.crumb()
        )
    }

    fn help_text(&self, _cx: &SettingsCx) -> &'static str {
        if self.utility_picker.is_some() {
            "↑/↓  enter: select  esc: back / cancel"
        } else if self.is_editing() {
            "type to edit  enter: apply  esc: cancel"
        } else {
            "↑/↓/Tab/Shift+Tab  enter: edit / cycle / drill  esc/h: back  q: close"
        }
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
    #[cfg(test)]
    fn test_name(&self) -> &'static str {
        "Category"
    }
}

#[cfg(test)]
mod descriptor_tests {
    use super::*;

    #[test]
    fn approval_mode_copy_describes_sandbox_as_the_gate() {
        let manual = approval_mode_label(ApprovalMode::Manual);
        let auto = approval_mode_label(ApprovalMode::Auto);
        let yolo = approval_mode_label(ApprovalMode::Yolo);

        assert_eq!(
            manual,
            "manual (default — sandboxed by default; you approve anything that needs to leave the sandbox)"
        );
        assert!(auto.contains("sandboxed by default"));
        assert!(auto.contains("utility model"));
        let joined = [manual, auto, yolo].join("\n");
        assert!(!joined.contains("approve every command"));
        assert!(!joined.contains("gated commands"));
    }

    #[test]
    fn every_setting_id_has_descriptor() {
        for id in ALL_SETTING_IDS {
            let descriptor = id.descriptor();
            assert!(!descriptor.label.is_empty(), "missing label for {id:?}");
            assert!(!descriptor.help.is_empty(), "missing help for {id:?}");
            match descriptor.kind {
                FieldKind::Cycle | FieldKind::EditText | FieldKind::Numeric | FieldKind::Drill => {}
            }
        }
    }

    #[test]
    fn approval_mode_help_is_preserved() {
        assert_eq!(
            SettingId::ApprovalMode.descriptor().help,
            "When a command needs approval to leave the sandbox. `manual` (default) asks you — you are the gate; `auto` lets the utility-model safety gate approve when possible and asks when unsafe or unavailable; `yolo` runs without approval prompts. Distinct from the `auto` *agent*."
        );
    }

    /// AC6 (picker/settings half). Mode copy must stay harness-steering only:
    /// it may not claim, or let a reader infer, any custody or redaction
    /// effect, and it must say model trust owns that decision.
    #[test]
    fn llm_mode_copy_never_implies_trust() {
        let help = SettingId::LlmMode.descriptor().help;
        assert!(
            help.contains("mode never changes provider eligibility, data custody, or redaction"),
            "llm mode help: {help}"
        );
        assert!(
            help.contains("no mode or locality implies trust"),
            "llm mode help: {help}"
        );

        for mode in [LlmMode::Defensive, LlmMode::Normal, LlmMode::Frontier] {
            let label = llm_mode_label(mode);
            assert!(
                label.contains("steering only"),
                "{mode:?} label must stay steering-only: {label}"
            );
            let lowered = label.to_ascii_lowercase();
            assert!(
                !lowered.contains("trust") && !lowered.contains("redact"),
                "{mode:?} label must not mention custody: {label}"
            );
        }
    }
}
