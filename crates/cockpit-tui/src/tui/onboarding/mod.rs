//! Full-screen onboarding shell.
//!
//! One renderer owns every first-run surface: animated welcome, secure-store
//! choice, searchable provider catalog, provider auth/validation, model /
//! agent / lifetime stages, and completion. The shell is a *presentation and
//! navigation* reducer only:
//!
//! * stage authority lives in the daemon `OnboardingBootstrapSnapshot`
//!   consumed through [`OnboardingShell::sync_snapshot`];
//! * provider auth and validation use native screens over the existing daemon
//!   provider and OAuth operations; the TUI never owns network I/O;
//! * every Back / Defer / Cancel / Advance intent is emitted as an
//!   [`OnboardingShellAction`] for the app to map onto the daemon
//!   transition RPCs. Escape never silently defers: when work is
//!   discardable it opens a visible Back / Defer / Cancel choice.
//!
//! The welcome fly-in is driven by an explicit frame counter advanced from
//! the app wake loop (`tick`), never by sleeps; the shell reports the
//! animation as active so the app keeps its animation tick waking the loop,
//! and after landing the counter keeps advancing the ambient prop/cloud
//! motion instead of freezing at the prompt frame. `NO_COLOR`, `TERM=dumb`,
//! and the `COCKPIT_REDUCE_MOTION` / `REDUCE_MOTION` controls select the
//! deterministic static alternative.

pub(crate) mod agent;
mod auth;
mod chrome;
mod lifetime;
mod model;
mod profile;
mod progress;
mod search;
mod secure_store;
mod ui;
mod verify;
pub(crate) mod welcome;

#[cfg(test)]
mod tests;

use crossterm::event::{
    KeyCode, KeyEvent, KeyEventKind, KeyModifiers, MouseButton, MouseEvent, MouseEventKind,
};
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Position, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Clear, Padding, Paragraph, Wrap};

use crate::tui::settings::Dialog;
use crate::tui::theme::{BAD, BRASS, FOG, GOOD, HOVER_BG, INK, NIGHT};
#[cfg(any(test, feature = "test-support"))]
pub(crate) use auth::AuthPhase;
pub(crate) use auth::AuthScreen;
pub(crate) use auth::AuthSubmission;
use chrome::ActionBar;
use cockpit_core::providers::ProviderTemplate;
use cockpit_proto::{
    OnboardingBootstrapSnapshot, OnboardingBootstrapState, OnboardingStage,
    OnboardingStageSettlement, OnboardingTransitionKind,
};
use lifetime::LifetimeScreen;
#[cfg(any(test, feature = "test-support"))]
pub(crate) use model::ModelPhase;
use model::ModelScreen;
use profile::ProfileScreen;
use search::{ProviderSearchScreen, onboarding_catalog};
use secure_store::SecureStoreScreen;
pub(crate) use verify::VerifyOutcome;
pub(crate) use verify::VerifyPhase;
pub(crate) use verify::VerifyScreen;

#[derive(Debug, Clone)]
pub struct ProviderSettlementEvidence {
    pub operation_id: String,
    pub mutation_intent_hash: String,
    pub mutation_config_generation: u64,
    pub config_generation: u64,
}

#[derive(Debug)]
pub struct ProviderVerificationCompletion {
    pub provider_id: String,
    pub outcome: Result<VerifyOutcome, String>,
    pub settlement: Option<ProviderSettlementEvidence>,
}

pub use secure_store::SecureStoreSubmission;

/// Frame at which the complete fly-in has landed and its prompt is visible.
pub(crate) const WELCOME_ANIMATION_FRAMES: usize = welcome::PROMPT_FRAME;

/// Ordered progress chrome. Maps the daemon stage enum onto the eight
/// user-visible checkpoints; `Profile` owns its own slot so a failed
/// profile-engine mount can never strand the user on the Welcome "press
/// any key" screen at a later stage (#425).
use progress::STEPS as PROGRESS_STEPS;

fn progress_index(stage: OnboardingStage) -> usize {
    match stage {
        OnboardingStage::Welcome => 0,
        OnboardingStage::Profile => 1,
        OnboardingStage::SecureStore => 2,
        OnboardingStage::Provider => 3,
        OnboardingStage::Model => 4,
        OnboardingStage::Agent => 5,
        OnboardingStage::Lifetime => 6,
        OnboardingStage::Complete => 7,
    }
}

/// The full-screen shell's row layout: header (title + subtitle), the
/// progress row, a rule, one blank line, the content, and the help/action
/// footer. The rule and blank line close the chrome so the progress row never
/// reads as the first item of the content's option list.
///
/// The layout is height-adaptive and sliced by hand rather than handed to the
/// constraint solver, whose tie-breaking under pressure could shrink the
/// footer. Allocation order, so the most important rows survive longest:
///
/// 1. the footer owns the last row;
/// 2. one content row is reserved whenever it can coexist with the footer;
/// 3. header (2) then progress (1) take what is left, so they shrink before
///    content does;
/// 4. the rule, then the blank line, appear only from their thresholds;
/// 5. the rest goes to the content.
///
/// With these thresholds the content never has fewer rows than the
/// pre-redesign fixed layout (`Length(3)` header with its rule, `Length(1)`
/// progress, `Min(1)` content, `Length(1)` footer) gave it, except for the
/// deliberate blank line on terminals of 24 rows or more.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ShellRows {
    header: Rect,
    progress: Rect,
    rule: Option<Rect>,
    content: Rect,
    footer: Rect,
}

impl ShellRows {
    /// Column height from which the blank line below the rule is kept (a
    /// 24-row terminal). Below it the blank row would cost content a row
    /// relative to the pre-redesign layout.
    const BLANK_MIN_HEIGHT: u16 = 22;
    /// Column height from which the rule is kept (a 10-row terminal, whose
    /// 3 content rows still hold a bordered field or three choices). With
    /// the rule the content matches the pre-redesign layout exactly.
    const RULE_MIN_HEIGHT: u16 = 8;

    fn split(col: Rect) -> Self {
        let mut budget = col.height;
        let mut reserve = |want: u16| {
            let got = want.min(budget);
            budget -= got;
            got
        };
        let footer_height = reserve(1);
        let reserved_content = reserve(1);
        let header_height = reserve(2);
        let progress_height = reserve(1);
        let rule_height = if col.height >= Self::RULE_MIN_HEIGHT {
            reserve(1)
        } else {
            0
        };
        let blank_height = if col.height >= Self::BLANK_MIN_HEIGHT {
            reserve(1)
        } else {
            0
        };
        let content_height = reserved_content + budget;

        let mut y = col.y;
        let mut take = |height: u16| {
            let rect = Rect {
                x: col.x,
                y,
                width: col.width,
                height,
            };
            y += height;
            rect
        };
        let header = take(header_height);
        let progress = take(progress_height);
        let rule = (rule_height > 0).then(|| take(rule_height));
        take(blank_height);
        let content = take(content_height);
        let footer = take(footer_height);
        Self {
            header,
            progress,
            rule,
            content,
            footer,
        }
    }
}

/// Invariants every onboarding golden must hold, asserted on the freshly
/// rendered buffer inside the shared golden path (never by re-reading fixture
/// files, which a concurrent regeneration may be rewriting). `◆` is reserved
/// for the progress row: it appears exactly once, on that row, and never on
/// the edge-to-edge Welcome scene.
#[cfg(any(test, feature = "test-support"))]
pub(crate) fn assert_golden_invariants(screen: &str, buf: &ratatui::buffer::Buffer) {
    let area = buf.area;
    let rows: Vec<String> = (area.top()..area.bottom())
        .map(|y| {
            (area.left()..area.right())
                .map(|x| buf[(x, y)].symbol())
                .collect()
        })
        .collect();
    let hits: Vec<u16> = rows
        .iter()
        .zip(area.top()..)
        .filter(|(row, _)| row.contains(progress::CURRENT_MARK))
        .map(|(_, y)| y)
        .collect();
    let total: usize = rows
        .iter()
        .map(|row| row.matches(progress::CURRENT_MARK).count())
        .sum();
    if screen.starts_with("welcome") {
        assert_eq!(
            total, 0,
            "{screen}: the Welcome scene draws no progress row"
        );
        return;
    }
    let progress_row = ShellRows::split(ui::column(area)).progress;
    let expected: Vec<u16> = if progress_row.height == 0 {
        Vec::new()
    } else {
        vec![progress_row.y]
    };
    assert_eq!(
        hits, expected,
        "{screen}: `◆` must mark only the progress row"
    );
    assert_eq!(total, expected.len(), "{screen}: `◆` must appear once");
}

/// Deterministic reduced-motion detection shared by the shell.
pub(crate) fn reduced_motion_enabled() -> bool {
    reduced_motion_for(
        std::env::var_os("NO_COLOR").is_some(),
        std::env::var("TERM").ok().as_deref(),
        ["COCKPIT_REDUCE_MOTION", "REDUCE_MOTION"].map(|name| std::env::var(name).ok()),
    )
}

fn reduced_motion_for(no_color: bool, term: Option<&str>, controls: [Option<String>; 2]) -> bool {
    no_color || term == Some("dumb") || controls.iter().flatten().any(|value| value.as_str() != "0")
}

fn welcome_cloud_seed() -> u64 {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos() as u64)
        .unwrap_or(0x5EED);
    nanos ^ u64::from(std::process::id()).rotate_left(32)
}

/// The screen the shell is presenting. `EmbeddedSettings` remains only for
/// non-provider setup surfaces that still delegate to the app-held dialog.
pub(crate) enum OnboardingScreen {
    Welcome,
    Profile(ProfileScreen),
    SecureStore(Box<SecureStoreScreen>),
    ProviderSearch(Box<ProviderSearchScreen>),
    Authenticate(Box<AuthScreen>),
    Verify(Box<VerifyScreen>),
    AgentAuthoring(Box<agent::AgentAuthoringScreen>),
    Model(Box<ModelScreen>),
    Lifetime(LifetimeScreen),
    EmbeddedSettings,
    Complete { summary: String, cursor: usize },
}

/// Screen classification for callers that only need to know whether the
/// embedded settings engine currently owns the content area.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OnboardingScreenKind {
    Welcome,
    Profile,
    SecureStore,
    ProviderSearch,
    Authenticate,
    Verify,
    AgentAuthoring,
    Model,
    Lifetime,
    EmbeddedSettings,
    Complete,
}

impl std::fmt::Debug for OnboardingScreen {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Discriminant-only: the secure-store screen holds zeroizing
        // passphrase state that must never be formatted.
        match self {
            Self::Welcome => formatter.write_str("Welcome"),
            Self::Profile(_) => formatter.write_str("Profile"),
            Self::SecureStore(_) => formatter.write_str("SecureStore([REDACTED])"),
            Self::ProviderSearch(_) => formatter.write_str("ProviderSearch"),
            Self::Authenticate(_) => formatter.write_str("Authenticate([REDACTED])"),
            Self::Verify(_) => formatter.write_str("Verify"),
            Self::AgentAuthoring(_) => formatter.write_str("AgentAuthoring"),
            Self::Model(_) => formatter.write_str("Model"),
            Self::Lifetime(_) => formatter.write_str("Lifetime"),
            Self::EmbeddedSettings => formatter.write_str("EmbeddedSettings"),
            Self::Complete { .. } => formatter.write_str("Complete"),
        }
    }
}

/// An intent the app must map onto a daemon operation. The shell never
/// performs config, credential, or state writes itself.
pub(crate) enum OnboardingShellAction {
    /// Request a daemon transition. Settlement is required to leave the
    /// provider/model/agent stages.
    Transition(OnboardingTransitionKind, Option<OnboardingStageSettlement>),
    /// Apply the chosen secure-store placement through the sensitive
    /// daemon ingress.
    SecureIntent(SecureStoreSubmission),
    /// Apply the native profile field through the existing setup-wizard authority.
    ApplyProfile(String),
    /// Apply the native lifetime choice through the existing setup-wizard authority.
    ApplyLifetime(bool),
    /// Apply all six native model choices through the setup-wizard authority.
    ApplyModel(cockpit_core::wizard::OnboardingModelSubmission),
    /// Present native authentication for the selected canonical template.
    SelectTemplate(&'static ProviderTemplate),
    /// Persist a provider credential and begin daemon-owned verification.
    AuthenticateProvider {
        template: &'static ProviderTemplate,
        submission: AuthSubmission,
    },
    /// Continue a real daemon-owned OAuth state machine for the native screen.
    OAuth(crate::tui::settings::OAuthFlowRequest),
    /// Re-run the daemon-owned verification request.
    RetryProviderVerification { provider_id: String },
    /// Settle this provider stage, or loop back to the catalog.
    FinishProvider {
        settlement: OnboardingStageSettlement,
        add_another: bool,
    },
    /// Leave the "add another provider" detour and present the stored
    /// completion summary again. Purely shell-local: the daemon stage is
    /// already `Complete`.
    ReturnToCompletion,
    /// Close the shell preserving committed daemon progress; discard only
    /// local unsaved text.
    Close,
    /// Agent authoring preview/apply/refresh intents for the app daemon
    /// bridge.
    AgentAuthoring(agent::AgentAuthoringShellAction),
}

impl std::fmt::Debug for OnboardingShellAction {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transition(kind, settlement) => formatter
                .debug_tuple("Transition")
                .field(kind)
                .field(settlement)
                .finish(),
            // The submission may carry the passphrase ingress; it never
            // receives a payload-bearing representation.
            Self::SecureIntent(_) => formatter.write_str("SecureIntent([REDACTED])"),
            Self::ApplyProfile(_) => formatter.write_str("ApplyProfile([REDACTED])"),
            Self::ApplyLifetime(value) => {
                formatter.debug_tuple("ApplyLifetime").field(value).finish()
            }
            Self::ApplyModel(_) => formatter.write_str("ApplyModel"),
            Self::SelectTemplate(template) => formatter
                .debug_tuple("SelectTemplate")
                .field(&template.id)
                .finish(),
            Self::AuthenticateProvider { template, .. } => formatter
                .debug_struct("AuthenticateProvider")
                .field("template", &template.id)
                .field("submission", &"[REDACTED]")
                .finish(),
            Self::OAuth(action) => formatter
                .debug_tuple("OAuth")
                .field(&action.provider)
                .finish(),
            Self::RetryProviderVerification { provider_id } => formatter
                .debug_tuple("RetryProviderVerification")
                .field(provider_id)
                .finish(),
            Self::FinishProvider {
                settlement,
                add_another,
            } => formatter
                .debug_struct("FinishProvider")
                .field("provider_id", &settlement.provider_id)
                .field("add_another", add_another)
                .finish(),
            Self::ReturnToCompletion => formatter.write_str("ReturnToCompletion"),
            Self::Close => formatter.write_str("Close"),
            Self::AgentAuthoring(action) => formatter
                .debug_tuple("AgentAuthoring")
                .field(action)
                .finish(),
        }
    }
}

/// Result of pointer routing: whether the shell consumed the event and any
/// intent produced by it.
#[derive(Default)]
pub(crate) struct PointerOutcome {
    pub consumed: bool,
    pub action: Option<OnboardingShellAction>,
}

impl PointerOutcome {
    fn ignored() -> Self {
        Self::default()
    }

    fn consumed() -> Self {
        Self {
            consumed: true,
            action: None,
        }
    }

    fn acted(action: OnboardingShellAction) -> Self {
        Self {
            consumed: true,
            action: Some(action),
        }
    }
}

/// The visible Escape choice. Escape never maps to an implicit deferral;
/// it opens this menu when work is discardable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EscapeChoice {
    Back,
    Defer,
    Cancel,
    /// Shell-local: leave the completion-screen "add another provider"
    /// detour and present the stored summary again.
    ReturnToSummary,
}

impl EscapeChoice {
    fn label(self) -> &'static str {
        match self {
            Self::Back => "Back to the previous step",
            Self::Defer => "Defer provider setup (limited mode)",
            Self::Cancel => "Cancel setup for now",
            Self::ReturnToSummary => "Return to the setup summary",
        }
    }

    fn action(self) -> OnboardingShellAction {
        match self {
            Self::Back => OnboardingShellAction::Transition(OnboardingTransitionKind::Back, None),
            Self::Defer => {
                OnboardingShellAction::Transition(OnboardingTransitionKind::DeferProvider, None)
            }
            Self::Cancel => OnboardingShellAction::Close,
            Self::ReturnToSummary => OnboardingShellAction::ReturnToCompletion,
        }
    }
}

struct EscapeMenu {
    cursor: usize,
    choices: Vec<EscapeChoice>,
    row_rects: Vec<Rect>,
    hover: Option<usize>,
}

impl EscapeMenu {
    /// Build the visible Escape choices for the current shell state, or
    /// `None` when nothing is offerable and Escape must stay inert.
    ///
    /// Authority work in flight is never discardable and never deferrable:
    /// the daemon owns its settlement, so while any engine authority
    /// operation is pending there is no menu at all (Escape flows to the
    /// engine's correlated handling). Outside the detour the menu offers
    /// only transitions the daemon accepts for the stage: `Back` is
    /// withheld on `Provider` because the committed secure-store choice
    /// cannot be reopened through onboarding.
    fn open(
        stage: OnboardingStage,
        engine_has_authority_pending: bool,
        completion_detour: bool,
    ) -> Option<Self> {
        if engine_has_authority_pending {
            return None;
        }
        let mut choices = Vec::new();
        if completion_detour {
            choices.push(EscapeChoice::ReturnToSummary);
        } else {
            let can_navigate_back = !matches!(
                stage,
                OnboardingStage::Welcome | OnboardingStage::Profile | OnboardingStage::Provider
            );
            if can_navigate_back {
                choices.push(EscapeChoice::Back);
            }
            if stage == OnboardingStage::Provider {
                choices.push(EscapeChoice::Defer);
            }
            choices.push(EscapeChoice::Cancel);
        }
        if choices.is_empty() {
            return None;
        }
        Some(Self {
            cursor: 0,
            choices,
            row_rects: Vec::new(),
            hover: None,
        })
    }

    fn handle_key(&mut self, key: KeyEvent) -> Option<EscapeChoice> {
        match key.code {
            KeyCode::Up => {
                self.cursor = self.cursor.saturating_sub(1);
                None
            }
            KeyCode::Down => {
                self.cursor = (self.cursor + 1).min(self.choices.len().saturating_sub(1));
                None
            }
            KeyCode::Enter => self.choices.get(self.cursor).copied(),
            _ => None,
        }
    }

    fn handle_mouse(&mut self, mouse: MouseEvent) -> EscapeMenuPointer {
        let pos = Position::new(mouse.column, mouse.row);
        match mouse.kind {
            MouseEventKind::Moved | MouseEventKind::Drag(_) => {
                self.hover = self
                    .row_rects
                    .iter()
                    .position(|rect| chrome::hit(*rect, pos));
                if let Some(index) = self.hover {
                    self.cursor = index;
                }
                EscapeMenuPointer::Tracked
            }
            MouseEventKind::Down(MouseButton::Left) => {
                let Some(index) = self
                    .row_rects
                    .iter()
                    .position(|rect| chrome::hit(*rect, pos))
                else {
                    return EscapeMenuPointer::Dismiss;
                };
                self.cursor = index;
                match self.choices.get(index).copied() {
                    Some(choice) => EscapeMenuPointer::Chosen(choice),
                    None => EscapeMenuPointer::Dismiss,
                }
            }
            _ => EscapeMenuPointer::Tracked,
        }
    }
}

enum EscapeMenuPointer {
    Tracked,
    Dismiss,
    Chosen(EscapeChoice),
}

/// The single onboarding renderer.
pub struct OnboardingShell {
    run_id: uuid::Uuid,
    attempt_id: uuid::Uuid,
    revision: u64,
    stage: OnboardingStage,
    limited_mode: bool,
    bootstrap_state: OnboardingBootstrapState,
    reduced_motion: bool,
    /// Explicit frame counter for the welcome scene; advanced only by
    /// [`Self::tick`]. Past [`WELCOME_ANIMATION_FRAMES`] it keeps driving
    /// the ambient prop bob and cloud drift while the screen is shown.
    frame: usize,
    /// Cloud entropy is chosen once per shell and injectable by golden tests.
    welcome_cloud_seed: u64,
    screen: OnboardingScreen,
    escape: Option<EscapeMenu>,
    /// Summary text computed when the lifetime stage settled; presented on
    /// the completion screen when the authoritative `Complete` revision
    /// lands, and again when the "add another provider" detour ends.
    completion_summary: Option<String>,
    /// True while the shell is in the completion screen's local "add
    /// another provider" detour (search + native auth/verify). The daemon
    /// stage stays `Complete`; Escape offers a local return instead of a
    /// daemon transition.
    completion_detour: bool,
    /// Latched daemon transition awaiting its snapshot, so a stage that
    /// completed cannot request the same transition twice before the
    /// authoritative revision lands.
    pending_transition: Option<(u64, OnboardingTransitionKind)>,
    /// Row rects of the active pointer-selectable list (secure-store
    /// choices, provider search rows) recorded at the last render.
    list_row_rects: Vec<Rect>,
    /// Hit area of the last-rendered list body; wheel events are gated on it.
    list_area: Rect,
    back_rect: Rect,
    back_hover: bool,
    actions: ActionBar,
}

impl OnboardingShell {
    pub(crate) fn new(snapshot: &OnboardingBootstrapSnapshot, reduced_motion: bool) -> Self {
        let screen = Self::native_screen_for(snapshot);
        Self {
            run_id: snapshot.run_id,
            attempt_id: snapshot.attempt_id,
            revision: snapshot.revision,
            stage: snapshot.stage,
            limited_mode: snapshot.limited_mode,
            bootstrap_state: snapshot.bootstrap_state,
            reduced_motion,
            frame: 0,
            welcome_cloud_seed: welcome_cloud_seed(),
            screen,
            escape: None,
            completion_summary: None,
            completion_detour: false,
            pending_transition: None,
            list_row_rects: Vec::new(),
            list_area: Rect::default(),
            back_rect: Rect::default(),
            back_hover: false,
            actions: ActionBar::default(),
        }
    }

    fn native_screen_for(snapshot: &OnboardingBootstrapSnapshot) -> OnboardingScreen {
        match snapshot.stage {
            // Only the authoritative Welcome stage presents the Welcome
            // screen. Profile owns a native field so a failed daemon
            // settlement keeps the user on the named step instead of
            // remounting the legacy setup engine (#425).
            OnboardingStage::Welcome => OnboardingScreen::Welcome,
            OnboardingStage::Profile => OnboardingScreen::Profile(ProfileScreen::new()),
            OnboardingStage::SecureStore => OnboardingScreen::SecureStore(Box::new(
                SecureStoreScreen::new(snapshot.host_capabilities.clone()),
            )),
            OnboardingStage::Provider => {
                OnboardingScreen::ProviderSearch(Box::new(ProviderSearchScreen::new()))
            }
            OnboardingStage::Lifetime => OnboardingScreen::Lifetime(LifetimeScreen::new()),
            OnboardingStage::Model => OnboardingScreen::Model(Box::new(ModelScreen::new(
                &cockpit_config::config::providers::ProvidersConfig::default(),
                None,
            ))),
            OnboardingStage::Complete => {
                // A fresh construction at `Complete` only happens when a
                // caller bypassed the occupancy fence; present the
                // completion surface rather than panicking on a stage that
                // has no engine.
                OnboardingScreen::Complete {
                    summary: "Cockpit is ready.".to_string(),
                    cursor: 1,
                }
            }
            OnboardingStage::Agent => {
                // The app mounts nested authoring asynchronously; keep the
                // embedded-settings pairing until `present_agent_authoring`.
                OnboardingScreen::EmbeddedSettings
            }
        }
    }

    pub(crate) fn stage(&self) -> OnboardingStage {
        self.stage
    }

    #[cfg(test)]
    pub(crate) fn screen_is_complete(&self) -> bool {
        matches!(self.screen, OnboardingScreen::Complete { .. })
    }

    pub(crate) fn screen_is_agent_authoring(&self) -> bool {
        matches!(self.screen, OnboardingScreen::AgentAuthoring(_))
    }

    #[cfg(test)]
    pub(crate) fn test_secure_store_cursor_placement(
        &self,
    ) -> Option<cockpit_proto::OnboardingSecurePlacement> {
        match &self.screen {
            OnboardingScreen::SecureStore(screen) => screen.cursor_placement(),
            _ => None,
        }
    }

    #[cfg(test)]
    pub(crate) fn model_phase(&self) -> Option<ModelPhase> {
        match &self.screen {
            OnboardingScreen::Model(screen) => Some(screen.phase()),
            _ => None,
        }
    }

    #[cfg(test)]
    pub(crate) fn model_selection(&self) -> Option<(&str, &str)> {
        match &self.screen {
            OnboardingScreen::Model(screen) => Some(screen.selection()),
            _ => None,
        }
    }

    #[cfg(test)]
    pub(crate) fn model_row_rects(&self) -> &[Rect] {
        match &self.screen {
            OnboardingScreen::Model(screen) => screen.test_row_rects(),
            _ => &[],
        }
    }

    #[cfg(test)]
    pub(crate) fn test_agent_authoring_phase(&self) -> Option<agent::Phase> {
        match &self.screen {
            OnboardingScreen::AgentAuthoring(screen) => Some(screen.test_phase()),
            _ => None,
        }
    }

    pub(crate) fn agent_authoring_settlement(
        &self,
        run_id: uuid::Uuid,
        attempt_id: uuid::Uuid,
        stage_revision: u64,
        config_generation: u64,
    ) -> Option<cockpit_proto::OnboardingStageSettlement> {
        match &self.screen {
            OnboardingScreen::AgentAuthoring(screen) => {
                screen.stage_settlement(run_id, attempt_id, stage_revision, config_generation)
            }
            _ => None,
        }
    }

    pub(crate) fn take_agent_authoring_action(
        &mut self,
    ) -> Option<agent::AgentAuthoringShellAction> {
        match &mut self.screen {
            OnboardingScreen::AgentAuthoring(screen) => screen.take_pending_action(),
            _ => None,
        }
    }

    pub(crate) fn apply_agent_authoring_outcome(
        &mut self,
        outcome: cockpit_proto::ApplyAuthoredAgentPackageOutcome,
    ) {
        if let OnboardingScreen::AgentAuthoring(screen) = &mut self.screen {
            screen.apply_outcome(outcome);
        }
    }

    pub(crate) fn screen_kind(&self) -> OnboardingScreenKind {
        match &self.screen {
            OnboardingScreen::Welcome => OnboardingScreenKind::Welcome,
            OnboardingScreen::Profile(_) => OnboardingScreenKind::Profile,
            OnboardingScreen::SecureStore(_) => OnboardingScreenKind::SecureStore,
            OnboardingScreen::ProviderSearch(_) => OnboardingScreenKind::ProviderSearch,
            OnboardingScreen::Authenticate(_) => OnboardingScreenKind::Authenticate,
            OnboardingScreen::Verify(_) => OnboardingScreenKind::Verify,
            OnboardingScreen::AgentAuthoring(_) => OnboardingScreenKind::AgentAuthoring,
            OnboardingScreen::Model(_) => OnboardingScreenKind::Model,
            OnboardingScreen::Lifetime(_) => OnboardingScreenKind::Lifetime,
            OnboardingScreen::EmbeddedSettings => OnboardingScreenKind::EmbeddedSettings,
            OnboardingScreen::Complete { .. } => OnboardingScreenKind::Complete,
        }
    }

    /// Consume the authoritative snapshot. A stage change rebuilds the
    /// native screen and clears any latched transition whose revision the
    /// daemon has consumed.
    pub(crate) fn sync_snapshot(&mut self, snapshot: &OnboardingBootstrapSnapshot) -> bool {
        let stage_changed = self.stage != snapshot.stage;
        let authority_changed = self.run_id != snapshot.run_id
            || self.attempt_id != snapshot.attempt_id
            || self.revision != snapshot.revision;
        self.limited_mode = snapshot.limited_mode;
        self.bootstrap_state = snapshot.bootstrap_state;
        if self.run_id != snapshot.run_id
            || self.attempt_id != snapshot.attempt_id
            || self
                .pending_transition
                .is_some_and(|(revision, _)| snapshot.revision > revision)
        {
            self.pending_transition = None;
        }
        if !stage_changed && !authority_changed {
            // Host capabilities advance independently of the onboarding
            // revision: the daemon serves the locked bootstrap with a probing
            // snapshot and publishes the settled one later at the same
            // revision. Feed it to the mounted screen (generation-monotonic).
            self.apply_host_capabilities(&snapshot.host_capabilities);
            return false;
        }
        self.run_id = snapshot.run_id;
        self.attempt_id = snapshot.attempt_id;
        self.revision = snapshot.revision;
        self.stage = snapshot.stage;
        self.escape = None;
        self.frame = 0;
        self.screen = Self::native_screen_for(snapshot);
        true
    }

    /// The app mounts the engine dialog for wizard/provider stages; call
    /// this when the mount happens so the shell presents it.
    pub(crate) fn present_embedded_settings(&mut self) {
        self.screen = OnboardingScreen::EmbeddedSettings;
        self.escape = None;
    }

    /// Mount the nested agent authoring editor for the onboarding agent stage.
    pub(crate) fn present_agent_authoring(
        &mut self,
        projection: cockpit_proto::AgentAuthoringProjection,
        client_operation_id: String,
    ) {
        self.screen = OnboardingScreen::AgentAuthoring(Box::new(agent::AgentAuthoringScreen::new(
            projection,
            client_operation_id,
        )));
        self.escape = None;
    }

    pub(crate) fn present_model(
        &mut self,
        config: &cockpit_config::config::providers::ProvidersConfig,
        preselect: Option<(&str, &str)>,
    ) {
        self.screen = OnboardingScreen::Model(Box::new(ModelScreen::new(config, preselect)));
        self.escape = None;
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn set_model_phase_for_golden(&mut self, phase: ModelPhase) {
        if let OnboardingScreen::Model(screen) = &mut self.screen {
            screen.set_phase_for_golden(phase);
        }
    }

    /// Adopt an authoritative `Complete` revision without rebuilding the
    /// native screen: the completion surface is presented from the summary
    /// recorded when the lifetime stage settled. The local "add another
    /// provider" detour is occupancy on top of the completion stage — the
    /// same class of fence as a user dismissal — so an authority refresh
    /// (including the daemon-global broadcast from a concurrent client)
    /// updates the correlation fields but never unmounts an in-flight
    /// detour; the detour ends only through its own local return path.
    pub(crate) fn note_authoritative_complete(
        &mut self,
        snapshot: &OnboardingBootstrapSnapshot,
    ) -> bool {
        self.run_id = snapshot.run_id;
        self.attempt_id = snapshot.attempt_id;
        self.revision = snapshot.revision;
        self.stage = snapshot.stage;
        self.limited_mode = snapshot.limited_mode;
        self.bootstrap_state = snapshot.bootstrap_state;
        self.pending_transition = None;
        if self.completion_detour {
            // Authority fields adopted; the detour keeps screen occupancy.
            return false;
        }
        self.escape = None;
        if matches!(self.screen, OnboardingScreen::Complete { .. }) {
            return false;
        }
        self.present_completion(
            self.completion_summary
                .clone()
                .unwrap_or_else(|| "Cockpit is ready.".to_string()),
        );
        true
    }

    /// Record the summary computed when the lifetime stage settled; it is
    /// presented on the completion screen once the authoritative `Complete`
    /// revision lands.
    pub(crate) fn note_completion_summary(&mut self, summary: String) {
        self.completion_summary = Some(summary);
    }

    /// Swap to the completion screen (the daemon stage is already
    /// `Complete`: the terminal transition was requested when the lifetime
    /// stage settled, and the authoritative revision presented this screen).
    pub(crate) fn present_completion(&mut self, summary: String) {
        self.screen = OnboardingScreen::Complete { summary, cursor: 1 };
        self.completion_detour = false;
        self.escape = None;
    }

    /// Return to the stored completion summary, leaving the "add another
    /// provider" detour.
    pub(crate) fn return_to_completion(&mut self) {
        let summary = self
            .completion_summary
            .clone()
            .unwrap_or_else(|| "Cockpit is ready.".to_string());
        self.present_completion(summary);
    }

    /// True while the completion screen's "add another provider" detour is
    /// active.
    pub(crate) fn completion_detour_active(&self) -> bool {
        self.completion_detour
    }

    /// Enter the completion screen's local "add another provider" detour:
    /// the searchable catalog and native authentication/verification screens
    /// with a shell-local return path. The daemon stage stays
    /// `Complete`; the added provider settles through the ordinary
    /// provider mutation authority, not an onboarding transition.
    pub(crate) fn begin_completion_provider_detour(&mut self, status: Option<String>) {
        let mut screen = ProviderSearchScreen::new();
        screen.set_status(status);
        self.screen = OnboardingScreen::ProviderSearch(Box::new(screen));
        self.completion_detour = true;
        self.escape = None;
    }

    /// Return to the provider catalog while preserving completion-detour state.
    pub(crate) fn present_provider_search(&mut self, status: Option<String>) {
        let mut screen = ProviderSearchScreen::new();
        screen.set_status(status);
        self.screen = OnboardingScreen::ProviderSearch(Box::new(screen));
        self.escape = None;
    }

    pub(crate) fn present_authenticate(&mut self, template: &'static ProviderTemplate) {
        self.screen = OnboardingScreen::Authenticate(Box::new(AuthScreen::new(template)));
        self.escape = None;
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn set_auth_phase_for_golden(&mut self, phase: AuthPhase) {
        if let OnboardingScreen::Authenticate(screen) = &mut self.screen {
            screen.set_phase_for_golden(phase);
        }
    }

    pub(crate) fn present_verify(&mut self, provider_id: String) {
        self.screen = OnboardingScreen::Verify(Box::new(VerifyScreen::new(provider_id)));
        self.escape = None;
    }

    pub(crate) fn verifying_provider_id(&self) -> Option<&str> {
        match &self.screen {
            OnboardingScreen::Verify(screen) => Some(screen.provider_id()),
            _ => None,
        }
    }

    #[cfg(test)]
    pub(crate) fn provider_verification_succeeded(&self) -> bool {
        matches!(
            &self.screen,
            OnboardingScreen::Verify(screen)
                if matches!(screen.phase(), verify::VerifyPhase::Success(_))
        )
    }

    pub(crate) fn apply_provider_verification(
        &mut self,
        provider_id: &str,
        outcome: VerifyOutcome,
        evidence: Option<ProviderSettlementEvidence>,
    ) {
        if let OnboardingScreen::Verify(screen) = &mut self.screen
            && screen.provider_id() == provider_id
        {
            screen.apply(outcome, evidence);
        }
    }

    pub(crate) fn onboarding_oauth_provider(&self) -> Option<crate::tui::settings::OAuthProvider> {
        match &self.screen {
            OnboardingScreen::Authenticate(screen) => screen.oauth_provider(),
            _ => None,
        }
    }

    pub(crate) fn apply_onboarding_oauth_acknowledgement(
        &mut self,
        client_flow_id: crate::tui::settings::OAuthFlowId,
        operation_id: crate::tui::settings::PointerOperationId,
        result: Result<(), String>,
    ) -> Option<crate::tui::settings::OAuthFlowRequest> {
        match &mut self.screen {
            OnboardingScreen::Authenticate(screen) => {
                screen.apply_oauth_acknowledgement(client_flow_id, operation_id, result)
            }
            _ => None,
        }
    }

    pub(crate) fn apply_onboarding_oauth_begin(
        &mut self,
        client_flow_id: crate::tui::settings::OAuthFlowId,
        operation_id: crate::tui::settings::PointerOperationId,
        result: crate::tui::settings::OAuthBeginResult,
    ) -> Option<crate::tui::settings::OAuthFlowRequest> {
        match &mut self.screen {
            OnboardingScreen::Authenticate(screen) => {
                screen.apply_oauth_begin(client_flow_id, operation_id, result)
            }
            _ => None,
        }
    }

    pub(crate) fn apply_onboarding_oauth_present(
        &mut self,
        client_flow_id: crate::tui::settings::OAuthFlowId,
        operation_id: crate::tui::settings::PointerOperationId,
        result: Result<crate::tui::settings::OAuthPresentationResult, String>,
    ) -> Option<crate::tui::settings::OAuthFlowRequest> {
        match &mut self.screen {
            OnboardingScreen::Authenticate(screen) => {
                screen.apply_oauth_present(client_flow_id, operation_id, result)
            }
            _ => None,
        }
    }

    pub(crate) fn apply_onboarding_oauth_complete(
        &mut self,
        client_flow_id: crate::tui::settings::OAuthFlowId,
        operation_id: crate::tui::settings::PointerOperationId,
        result: Result<bool, String>,
    ) -> Option<(&'static ProviderTemplate, AuthSubmission)> {
        match &mut self.screen {
            OnboardingScreen::Authenticate(screen) => {
                let template = screen.template();
                screen
                    .apply_oauth_complete(client_flow_id, operation_id, result)
                    .map(|submission| (template, submission))
            }
            _ => None,
        }
    }

    pub(crate) fn apply_onboarding_oauth_cancel(
        &mut self,
        client_flow_id: crate::tui::settings::OAuthFlowId,
        operation_id: crate::tui::settings::PointerOperationId,
        result: Result<bool, String>,
    ) {
        if let OnboardingScreen::Authenticate(screen) = &mut self.screen {
            screen.apply_oauth_cancel(client_flow_id, operation_id, result);
        }
    }

    pub(crate) fn apply_onboarding_oauth_settlement_unknown(
        &mut self,
        client_flow_id: crate::tui::settings::OAuthFlowId,
        operation_id: crate::tui::settings::PointerOperationId,
        error: String,
        acknowledgement: bool,
    ) {
        if let OnboardingScreen::Authenticate(screen) = &mut self.screen {
            screen.apply_oauth_settlement_unknown(
                client_flow_id,
                operation_id,
                error,
                acknowledgement,
            );
        }
    }

    pub(crate) fn apply_onboarding_oauth_cancel_authoritative_failure(
        &mut self,
        client_flow_id: crate::tui::settings::OAuthFlowId,
        operation_id: crate::tui::settings::PointerOperationId,
        error: String,
    ) {
        if let OnboardingScreen::Authenticate(screen) = &mut self.screen {
            screen.apply_oauth_cancel_authoritative_failure(client_flow_id, operation_id, error);
        }
    }

    fn provider_settlement_for(
        run_id: uuid::Uuid,
        attempt_id: uuid::Uuid,
        revision: u64,
        screen: &VerifyScreen,
    ) -> Option<OnboardingStageSettlement> {
        let evidence = screen.settlement()?;
        Some(OnboardingStageSettlement {
            run_id,
            attempt_id,
            stage_revision: revision,
            settlement_operation_id: evidence.operation_id.clone(),
            provider_id: Some(screen.provider_id().to_string()),
            mutation_intent_hash: Some(evidence.mutation_intent_hash.clone()),
            provider_mutation_config_generation: Some(evidence.mutation_config_generation),
            wizard_id: None,
            config_generation: evidence.config_generation,
        })
    }

    /// Latch a requested transition so duplicate completions cannot double
    /// advance before the authoritative revision lands.
    pub(crate) fn latch_transition(&mut self, revision: u64, kind: OnboardingTransitionKind) {
        self.pending_transition = Some((revision, kind));
    }

    pub(crate) fn transition_pending(&self) -> bool {
        self.pending_transition.is_some()
    }

    /// The latched in-flight transition kind, if any. Callers suppress a
    /// duplicate request of the *same* kind while it is in flight; a
    /// different kind supersedes it (the app aborts the earlier RPC).
    pub(crate) fn pending_transition_kind(&self) -> Option<OnboardingTransitionKind> {
        self.pending_transition.map(|(_, kind)| kind)
    }

    /// Clear the latch after a failed transition so the stage can retry.
    pub(crate) fn clear_pending_transition(&mut self) {
        self.pending_transition = None;
    }

    /// Feed live host capabilities to the secure-store screen. Placement is
    /// gated on these rows; a bootstrap snapshot fetched while capabilities
    /// were unpublished must not strand a stale view. Generation-monotonic:
    /// an unpublished placeholder never clobbers published rows.
    /// Whether the mounted secure-store screen is still showing the daemon's
    /// probing placeholder (host probes not yet settled).
    pub(crate) fn secure_store_capabilities_probing(&self) -> bool {
        matches!(&self.screen, OnboardingScreen::SecureStore(screen) if screen.probing())
    }

    pub(crate) fn apply_host_capabilities(
        &mut self,
        capabilities: &cockpit_proto::HostCapabilitySnapshot,
    ) {
        if let OnboardingScreen::SecureStore(screen) = &mut self.screen
            && capabilities.generation >= screen.capabilities.generation
        {
            screen.set_capabilities(capabilities.clone());
        }
    }

    /// Pin the welcome fly-in frame for golden dumps.
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn set_frame_for_golden(&mut self, frame: usize) {
        self.frame = frame;
    }

    /// Select a password-entry sub-step for deterministic secure-store dumps.
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn set_secure_store_password_phase_for_golden(&mut self, confirmation: bool) {
        if let OnboardingScreen::SecureStore(screen) = &mut self.screen {
            screen.phase = if confirmation {
                secure_store::SecureStoreInputPhase::Confirmation
            } else {
                secure_store::SecureStoreInputPhase::Passphrase
            };
        }
    }

    /// Pin procedural cloud generation for deterministic screen dumps.
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn set_welcome_cloud_seed_for_golden(&mut self, seed: u64) {
        self.welcome_cloud_seed = seed;
    }

    /// Advance the welcome scene exactly one frame. Returns whether the
    /// frame changed (redraw needed).
    ///
    /// The counter never stops while the Welcome screen is shown: the
    /// fly-in itself settles at [`WELCOME_ANIMATION_FRAMES`] (the prompt
    /// becomes visible), and past that the same counter keeps driving the
    /// ambient prop bob and cloud drift so the landed scene never
    /// freezes. Reduced motion never ticks — its static scene is drawn
    /// landed with the prompt from frame 0.
    pub(crate) fn tick(&mut self) -> bool {
        if let OnboardingScreen::Authenticate(screen) = &mut self.screen {
            screen.tick();
            return true;
        }
        if let OnboardingScreen::Verify(screen) = &mut self.screen {
            screen.tick();
            return true;
        }
        if !self.welcome_animation_active() {
            return false;
        }
        self.frame = self.frame.saturating_add(1);
        true
    }

    /// True while the Welcome screen is animating — the fly-in or the
    /// post-landing ambient motion — and therefore needs the app's
    /// animation tick to keep waking the loop. Without that tick the
    /// frame counter only advances on unrelated wakes and the fly-in
    /// strands at frame 0.
    pub(crate) fn welcome_animation_active(&self) -> bool {
        matches!(self.screen, OnboardingScreen::Welcome) && !self.reduced_motion
    }

    fn welcome_is_flying(&self) -> bool {
        matches!(self.screen, OnboardingScreen::Welcome)
            && !self.reduced_motion
            && self.frame < WELCOME_ANIMATION_FRAMES
    }

    fn welcome_prompt_visible(&self) -> bool {
        matches!(self.screen, OnboardingScreen::Welcome)
            && (self.reduced_motion || self.frame >= welcome::PROMPT_FRAME)
    }

    /// Back is withheld where the daemon rejects the transition (`Welcome`,
    /// `Provider`) and during the welcome fly-in (no chrome). The completion
    /// detour's back is a local return, not a daemon Back.
    fn back_enabled(&self) -> bool {
        if self.welcome_is_flying() {
            return false;
        }
        if self.completion_detour {
            return true;
        }
        if let OnboardingScreen::SecureStore(screen) = &self.screen {
            return !matches!(screen.phase, secure_store::SecureStoreInputPhase::Choice);
        }
        if matches!(
            self.screen,
            OnboardingScreen::Authenticate(_) | OnboardingScreen::Verify(_)
        ) {
            return true;
        }
        !matches!(
            self.stage,
            OnboardingStage::Welcome | OnboardingStage::Provider
        )
    }

    fn is_quit_chord(key: &KeyEvent) -> bool {
        key.modifiers.contains(KeyModifiers::CONTROL)
            && matches!(key.code, KeyCode::Char('c') | KeyCode::Char('C'))
    }

    fn accepts_key(key: &KeyEvent) -> bool {
        matches!(key.kind, KeyEventKind::Press | KeyEventKind::Repeat)
    }

    fn activate_primary(&mut self, engine: &mut Dialog) -> Option<OnboardingShellAction> {
        let correlation = (self.run_id, self.attempt_id, self.revision);
        match &mut self.screen {
            OnboardingScreen::Welcome => {
                if !self.welcome_prompt_visible() {
                    return None;
                }
                if self.stage == OnboardingStage::Welcome {
                    Some(OnboardingShellAction::Transition(
                        OnboardingTransitionKind::Advance,
                        None,
                    ))
                } else {
                    None
                }
            }
            OnboardingScreen::Profile(screen) => {
                screen.submit().map(OnboardingShellAction::ApplyProfile)
            }
            OnboardingScreen::SecureStore(screen) => {
                screen.confirm_focused();
                screen
                    .take_submission()
                    .map(OnboardingShellAction::SecureIntent)
            }
            OnboardingScreen::ProviderSearch(screen) => screen
                .activate_focused()
                .map(OnboardingShellAction::SelectTemplate),
            OnboardingScreen::Authenticate(screen) => {
                let template = screen.template();
                let last = screen.buttons().len().saturating_sub(1);
                if let Some(submission) = screen.action(last) {
                    Some(OnboardingShellAction::AuthenticateProvider {
                        template,
                        submission,
                    })
                } else {
                    screen.take_oauth_action().map(OnboardingShellAction::OAuth)
                }
            }
            OnboardingScreen::Verify(screen) => match screen.phase() {
                verify::VerifyPhase::Success(_) | verify::VerifyPhase::NoEndpoint => {
                    Self::provider_settlement_for(
                        correlation.0,
                        correlation.1,
                        correlation.2,
                        screen,
                    )
                    .map(|settlement| OnboardingShellAction::FinishProvider {
                        settlement,
                        add_another: false,
                    })
                }
                verify::VerifyPhase::Error(_) => {
                    let provider_id = screen.provider_id().to_string();
                    screen.retry();
                    Some(OnboardingShellAction::RetryProviderVerification { provider_id })
                }
                verify::VerifyPhase::Fetching => None,
            },
            OnboardingScreen::AgentAuthoring(screen) => screen
                .handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
                .map(OnboardingShellAction::AgentAuthoring),
            OnboardingScreen::Lifetime(screen) => {
                Some(OnboardingShellAction::ApplyLifetime(screen.submit()))
            }
            OnboardingScreen::Model(screen) => {
                screen.advance().map(OnboardingShellAction::ApplyModel)
            }
            OnboardingScreen::Complete { cursor, .. } => {
                if *cursor == 0 {
                    self.begin_completion_provider_detour(Some(
                        "Add another provider; live validation is required.".into(),
                    ));
                    None
                } else {
                    Some(OnboardingShellAction::Close)
                }
            }
            OnboardingScreen::EmbeddedSettings => {
                let closed = engine.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
                if closed {
                    self.open_escape_menu(engine);
                }
                None
            }
        }
    }

    fn activate_back(&mut self) -> Option<OnboardingShellAction> {
        if !self.back_enabled() {
            return None;
        }
        if self.completion_detour {
            self.return_to_completion();
            return Some(OnboardingShellAction::ReturnToCompletion);
        }
        if let OnboardingScreen::SecureStore(screen) = &mut self.screen {
            screen.return_to_choice();
            return None;
        }
        if let OnboardingScreen::Model(screen) = &mut self.screen
            && screen.back()
        {
            return None;
        }
        if let OnboardingScreen::AgentAuthoring(screen) = &mut self.screen
            && screen.back()
        {
            return None;
        }
        if matches!(
            self.screen,
            OnboardingScreen::Authenticate(_) | OnboardingScreen::Verify(_)
        ) {
            self.present_provider_search(None);
            return None;
        }
        Some(OnboardingShellAction::Transition(
            OnboardingTransitionKind::Back,
            None,
        ))
    }

    /// Route a key through the shell. `engine` is the app's settings dialog
    /// that renders engine-stage content.
    pub(crate) fn handle_key(
        &mut self,
        key: KeyEvent,
        engine: &mut Dialog,
    ) -> Option<OnboardingShellAction> {
        if !Self::accepts_key(&key) {
            return None;
        }
        if Self::is_quit_chord(&key) {
            return Some(OnboardingShellAction::Close);
        }

        if let Some(menu) = self.escape.as_mut() {
            if matches!(key.code, KeyCode::Esc) {
                self.escape = None;
                return None;
            }
            return menu.handle_key(key).map(|choice| {
                self.escape = None;
                self.apply_escape_choice(choice)
            });
        }

        let correlation = (self.run_id, self.attempt_id, self.revision);
        match &mut self.screen {
            OnboardingScreen::Welcome => {
                if matches!(key.code, KeyCode::Esc) {
                    self.open_escape_menu(engine);
                    return None;
                }
                if !self.welcome_prompt_visible() {
                    return None;
                }
                // Any other key begins setup. Only the authoritative Welcome
                // stage advances; a defensively mis-paired screen must never
                // skip the stage it does not own.
                if self.stage == OnboardingStage::Welcome {
                    return Some(OnboardingShellAction::Transition(
                        OnboardingTransitionKind::Advance,
                        None,
                    ));
                }
                None
            }
            OnboardingScreen::Profile(screen) => {
                if matches!(key.code, KeyCode::Esc) {
                    self.open_escape_menu(engine);
                    return None;
                }
                screen
                    .handle_key(key)
                    .map(OnboardingShellAction::ApplyProfile)
            }
            OnboardingScreen::SecureStore(screen) => {
                if matches!(key.code, KeyCode::Esc)
                    && matches!(screen.phase, secure_store::SecureStoreInputPhase::Choice)
                {
                    self.open_escape_menu(engine);
                    return None;
                }
                screen.handle_key(key);
                screen
                    .take_submission()
                    .map(OnboardingShellAction::SecureIntent)
            }
            OnboardingScreen::ProviderSearch(screen) => {
                if matches!(key.code, KeyCode::Esc) {
                    self.open_escape_menu(engine);
                    return None;
                }
                screen
                    .handle_key(key)
                    .map(OnboardingShellAction::SelectTemplate)
            }
            OnboardingScreen::Authenticate(screen) => {
                if matches!(key.code, KeyCode::Esc) {
                    let phase = screen.auth_phase();
                    if phase == auth::AuthPhase::DevicePolling {
                        if let Some(action) = screen.cancel_oauth() {
                            return Some(OnboardingShellAction::OAuth(action));
                        }
                        return None;
                    }
                    let oauth_cancel = if matches!(
                        phase,
                        auth::AuthPhase::DeviceIdle
                            | auth::AuthPhase::PasteCallback
                            | auth::AuthPhase::ApiKey
                    ) {
                        screen.cancel_oauth()
                    } else {
                        None
                    };
                    self.present_provider_search(None);
                    return oauth_cancel.map(OnboardingShellAction::OAuth);
                }
                let template = screen.template();
                if let Some(submission) = screen.handle_key(key) {
                    Some(OnboardingShellAction::AuthenticateProvider {
                        template,
                        submission,
                    })
                } else {
                    screen.take_oauth_action().map(OnboardingShellAction::OAuth)
                }
            }
            OnboardingScreen::Verify(screen) => {
                if matches!(key.code, KeyCode::Esc) {
                    self.present_provider_search(None);
                    return None;
                }
                match key.code {
                    KeyCode::Char('r')
                        if matches!(screen.phase(), verify::VerifyPhase::Error(_)) =>
                    {
                        let provider_id = screen.provider_id().to_string();
                        screen.retry();
                        Some(OnboardingShellAction::RetryProviderVerification { provider_id })
                    }
                    KeyCode::Char('a')
                        if matches!(
                            screen.phase(),
                            verify::VerifyPhase::Success(_) | verify::VerifyPhase::NoEndpoint
                        ) =>
                    {
                        Self::provider_settlement_for(
                            correlation.0,
                            correlation.1,
                            correlation.2,
                            screen,
                        )
                        .map(|settlement| {
                            OnboardingShellAction::FinishProvider {
                                settlement,
                                add_another: true,
                            }
                        })
                    }
                    KeyCode::Enter
                        if matches!(
                            screen.phase(),
                            verify::VerifyPhase::Success(_) | verify::VerifyPhase::NoEndpoint
                        ) =>
                    {
                        Self::provider_settlement_for(
                            correlation.0,
                            correlation.1,
                            correlation.2,
                            screen,
                        )
                        .map(|settlement| {
                            OnboardingShellAction::FinishProvider {
                                settlement,
                                add_another: false,
                            }
                        })
                    }
                    _ => {
                        screen.handle_key(key);
                        None
                    }
                }
            }
            OnboardingScreen::AgentAuthoring(screen) => {
                if matches!(key.code, KeyCode::Esc) {
                    if !screen.back() {
                        self.open_escape_menu(engine);
                    }
                    return None;
                }
                screen
                    .handle_key(key)
                    .map(OnboardingShellAction::AgentAuthoring)
            }
            OnboardingScreen::Lifetime(screen) => {
                if matches!(key.code, KeyCode::Esc) {
                    self.open_escape_menu(engine);
                    return None;
                }
                if matches!(key.code, KeyCode::Enter) {
                    return Some(OnboardingShellAction::ApplyLifetime(screen.submit()));
                }
                screen.handle_key(key);
                None
            }
            OnboardingScreen::Model(screen) => {
                if matches!(key.code, KeyCode::Esc) {
                    if !screen.back() {
                        self.open_escape_menu(engine);
                    }
                    return None;
                }
                if matches!(key.code, KeyCode::Enter) {
                    return screen.advance().map(OnboardingShellAction::ApplyModel);
                }
                screen.handle_key(key);
                None
            }
            OnboardingScreen::Complete { cursor, .. } => {
                match key.code {
                    KeyCode::Esc => {
                        // Completion has nothing discardable; Escape keeps
                        // the choice visible instead of silently closing.
                        self.open_escape_menu(engine);
                    }
                    KeyCode::Up | KeyCode::BackTab | KeyCode::Char('k') => {
                        *cursor = cursor.saturating_sub(1);
                    }
                    KeyCode::Down | KeyCode::Tab | KeyCode::Char('j') => {
                        *cursor = (*cursor + 1).min(1);
                    }
                    KeyCode::Enter | KeyCode::Char(' ') => {
                        if *cursor == 0 {
                            // Local detour: the daemon stage stays Complete.
                            self.begin_completion_provider_detour(Some(
                                "Add another provider; live validation is required.".into(),
                            ));
                        } else {
                            // The terminal Complete transition already
                            // committed when the lifetime stage settled;
                            // leaving the summary is a local close that
                            // preserves committed progress.
                            return Some(OnboardingShellAction::Close);
                        }
                    }
                    _ => {}
                }
                None
            }
            OnboardingScreen::EmbeddedSettings => {
                if matches!(key.code, KeyCode::Esc) {
                    // While the engine owns an unsettled authority operation,
                    // Escape belongs to its correlated handling (the engine
                    // keeps the page mounted until the operation settles),
                    // not to the shell menu.
                    if !engine.has_unsettled_local_authority() {
                        self.open_escape_menu(engine);
                        return None;
                    }
                }
                let closed = engine.handle_key(key);
                if closed {
                    // An engine closing itself onboarding-first would strand
                    // the flow; present the visible choice instead.
                    self.open_escape_menu(engine);
                }
                None
            }
        }
    }

    fn open_escape_menu(&mut self, engine: &Dialog) {
        // Authority work in flight is a property of the app's daemon
        // effects, not of which screen holds focus: even on a native screen
        // (for example the catalog after an abandoned engine) an in-flight
        // provider mutation makes Back/Defer/Cancel unofferable.
        let authority_pending = engine.has_unsettled_local_authority();
        self.escape = EscapeMenu::open(self.stage, authority_pending, self.completion_detour);
    }

    /// Translate a confirmed escape-menu choice. Shell-local navigation
    /// (returning to the stored completion summary) is applied here — the
    /// same as entering the detour — so the shell's own state always
    /// reflects the confirmed choice; the returned action still reaches the
    /// app so it can unmount the detour's engine dialog.
    fn apply_escape_choice(&mut self, choice: EscapeChoice) -> OnboardingShellAction {
        if matches!(choice, EscapeChoice::ReturnToSummary) {
            self.return_to_completion();
        }
        choice.action()
    }

    /// Pointer routing for the shell's own chrome and native screens. The
    /// escape menu is modal; otherwise chrome (back → action bar → rows)
    /// is hit-tested in that order. Engine pointer routing that misses
    /// chrome keeps flowing through the app's ordinary settings path.
    pub(crate) fn handle_mouse(
        &mut self,
        mouse: MouseEvent,
        engine: &mut Dialog,
    ) -> PointerOutcome {
        let pos = Position::new(mouse.column, mouse.row);
        if let Some(menu) = self.escape.as_mut() {
            return match menu.handle_mouse(mouse) {
                EscapeMenuPointer::Chosen(choice) => {
                    self.escape = None;
                    PointerOutcome::acted(self.apply_escape_choice(choice))
                }
                EscapeMenuPointer::Dismiss
                    if matches!(mouse.kind, MouseEventKind::Down(MouseButton::Left)) =>
                {
                    self.escape = None;
                    PointerOutcome::consumed()
                }
                EscapeMenuPointer::Tracked | EscapeMenuPointer::Dismiss => {
                    PointerOutcome::consumed()
                }
            };
        }

        self.back_hover = chrome::hit(self.back_rect, pos);
        self.actions.track(pos);
        match mouse.kind {
            MouseEventKind::Moved => PointerOutcome::consumed(),
            MouseEventKind::Down(MouseButton::Left) if chrome::hit(self.back_rect, pos) => {
                match self.activate_back() {
                    Some(action) => PointerOutcome::acted(action),
                    None => PointerOutcome::consumed(),
                }
            }
            MouseEventKind::Down(MouseButton::Left) if self.actions.clicked(pos).is_some() => {
                let index = self.actions.clicked(pos);
                self.handle_action_bar_click(index, engine)
            }
            MouseEventKind::Down(MouseButton::Left)
                if matches!(self.screen, OnboardingScreen::Welcome) =>
            {
                if self.welcome_prompt_visible() {
                    match self.activate_primary(engine) {
                        Some(action) => PointerOutcome::acted(action),
                        None => PointerOutcome::consumed(),
                    }
                } else {
                    PointerOutcome::consumed()
                }
            }
            _ => self.handle_content_mouse(mouse, pos),
        }
    }

    fn handle_action_bar_click(
        &mut self,
        index: Option<usize>,
        engine: &mut Dialog,
    ) -> PointerOutcome {
        match (&self.screen, index) {
            (OnboardingScreen::Authenticate(_), Some(index)) => {
                let OnboardingScreen::Authenticate(screen) = &mut self.screen else {
                    unreachable!()
                };
                let template = screen.template();
                match screen.action(index) {
                    Some(submission) => {
                        PointerOutcome::acted(OnboardingShellAction::AuthenticateProvider {
                            template,
                            submission,
                        })
                    }
                    None => screen
                        .take_oauth_action()
                        .map(OnboardingShellAction::OAuth)
                        .map(PointerOutcome::acted)
                        .unwrap_or_else(PointerOutcome::consumed),
                }
            }
            (OnboardingScreen::Verify(screen), Some(0))
                if matches!(screen.phase(), verify::VerifyPhase::Error(_)) =>
            {
                let OnboardingScreen::Verify(screen) = &mut self.screen else {
                    unreachable!()
                };
                let provider_id = screen.provider_id().to_string();
                screen.retry();
                PointerOutcome::acted(OnboardingShellAction::RetryProviderVerification {
                    provider_id,
                })
            }
            (OnboardingScreen::Verify(screen), Some(index))
                if matches!(
                    screen.phase(),
                    verify::VerifyPhase::Success(_) | verify::VerifyPhase::NoEndpoint
                ) =>
            {
                match Self::provider_settlement_for(
                    self.run_id,
                    self.attempt_id,
                    self.revision,
                    screen,
                ) {
                    Some(settlement) => {
                        PointerOutcome::acted(OnboardingShellAction::FinishProvider {
                            settlement,
                            add_another: index == 0,
                        })
                    }
                    None => PointerOutcome::consumed(),
                }
            }
            (OnboardingScreen::SecureStore(screen), Some(0))
                if !matches!(screen.phase, secure_store::SecureStoreInputPhase::Choice) =>
            {
                if let OnboardingScreen::SecureStore(screen) = &mut self.screen {
                    screen.toggle_reveal();
                }
                PointerOutcome::consumed()
            }
            (OnboardingScreen::SecureStore(screen), Some(1))
                if !matches!(screen.phase, secure_store::SecureStoreInputPhase::Choice) =>
            {
                match self.activate_primary(engine) {
                    Some(action) => PointerOutcome::acted(action),
                    None => PointerOutcome::consumed(),
                }
            }
            (OnboardingScreen::Complete { .. }, Some(0)) => {
                self.begin_completion_provider_detour(Some(
                    "Add another provider; live validation is required.".into(),
                ));
                PointerOutcome::consumed()
            }
            (OnboardingScreen::Complete { .. }, Some(1)) => {
                PointerOutcome::acted(OnboardingShellAction::Close)
            }
            (OnboardingScreen::AgentAuthoring(_), Some(index)) => {
                let OnboardingScreen::AgentAuthoring(screen) = &mut self.screen else {
                    unreachable!()
                };
                match screen.action_bar_click(index) {
                    Some(action) => {
                        PointerOutcome::acted(OnboardingShellAction::AgentAuthoring(action))
                    }
                    None => PointerOutcome::consumed(),
                }
            }
            _ => match self.activate_primary(engine) {
                Some(action) => PointerOutcome::acted(action),
                None => PointerOutcome::consumed(),
            },
        }
    }

    fn handle_content_mouse(&mut self, mouse: MouseEvent, pos: Position) -> PointerOutcome {
        match &mut self.screen {
            OnboardingScreen::Profile(screen) => {
                if matches!(mouse.kind, MouseEventKind::Down(MouseButton::Left))
                    && chrome::hit(screen.field_rect(), pos)
                {
                    PointerOutcome::consumed()
                } else {
                    PointerOutcome::ignored()
                }
            }
            OnboardingScreen::SecureStore(screen) => {
                let over_list = chrome::hit(self.list_area, pos);
                match mouse.kind {
                    MouseEventKind::ScrollUp
                        if over_list
                            && matches!(
                                screen.phase,
                                secure_store::SecureStoreInputPhase::Choice
                            ) =>
                    {
                        screen.move_choice(-1);
                        screen.status = None;
                        PointerOutcome::consumed()
                    }
                    MouseEventKind::ScrollDown
                        if over_list
                            && matches!(
                                screen.phase,
                                secure_store::SecureStoreInputPhase::Choice
                            ) =>
                    {
                        screen.move_choice(1);
                        screen.status = None;
                        PointerOutcome::consumed()
                    }
                    MouseEventKind::Down(MouseButton::Left) => {
                        let rects = std::mem::take(&mut self.list_row_rects);
                        screen.handle_mouse(mouse, &rects);
                        self.list_row_rects = rects;
                        match screen.take_submission() {
                            Some(submission) => PointerOutcome::acted(
                                OnboardingShellAction::SecureIntent(submission),
                            ),
                            None => PointerOutcome::consumed(),
                        }
                    }
                    _ => PointerOutcome::ignored(),
                }
            }
            OnboardingScreen::Lifetime(screen) => {
                let over_list = chrome::hit(self.list_area, pos);
                match mouse.kind {
                    MouseEventKind::ScrollUp if over_list => {
                        screen.move_choice(-1);
                        PointerOutcome::consumed()
                    }
                    MouseEventKind::ScrollDown if over_list => {
                        screen.move_choice(1);
                        PointerOutcome::consumed()
                    }
                    MouseEventKind::Down(MouseButton::Left) => {
                        let rects = std::mem::take(&mut self.list_row_rects);
                        screen.handle_mouse(mouse, &rects);
                        self.list_row_rects = rects;
                        PointerOutcome::consumed()
                    }
                    _ => PointerOutcome::ignored(),
                }
            }
            OnboardingScreen::Model(screen) => {
                screen.handle_mouse(mouse);
                PointerOutcome::consumed()
            }
            OnboardingScreen::ProviderSearch(screen) => {
                let over_list = chrome::hit(self.list_area, pos);
                if matches!(
                    mouse.kind,
                    MouseEventKind::ScrollUp | MouseEventKind::ScrollDown
                ) && !over_list
                {
                    return PointerOutcome::ignored();
                }
                let rects = std::mem::take(&mut self.list_row_rects);
                let was_dragging_scrollbar = screen.dragging_scrollbar();
                let action = screen.handle_mouse(mouse, &rects);
                let is_dragging_scrollbar = screen.dragging_scrollbar();
                self.list_row_rects = rects;
                match action {
                    Some(template) => {
                        PointerOutcome::acted(OnboardingShellAction::SelectTemplate(template))
                    }
                    None if matches!(
                        mouse.kind,
                        MouseEventKind::ScrollUp
                            | MouseEventKind::ScrollDown
                            | MouseEventKind::Down(MouseButton::Left)
                    ) =>
                    {
                        PointerOutcome::consumed()
                    }
                    None if matches!(mouse.kind, MouseEventKind::Drag(MouseButton::Left))
                        && (was_dragging_scrollbar || is_dragging_scrollbar) =>
                    {
                        PointerOutcome::consumed()
                    }
                    None if matches!(mouse.kind, MouseEventKind::Up(MouseButton::Left))
                        && was_dragging_scrollbar =>
                    {
                        PointerOutcome::consumed()
                    }
                    None => PointerOutcome::ignored(),
                }
            }
            OnboardingScreen::Authenticate(screen) => {
                screen.handle_mouse(mouse);
                PointerOutcome::consumed()
            }
            OnboardingScreen::Verify(screen) => {
                screen.handle_mouse(mouse);
                PointerOutcome::consumed()
            }
            OnboardingScreen::AgentAuthoring(screen) => {
                if screen.handle_mouse(mouse) {
                    if let Some(action) = screen.take_pending_action() {
                        PointerOutcome::acted(OnboardingShellAction::AgentAuthoring(action))
                    } else {
                        PointerOutcome::consumed()
                    }
                } else if matches!(
                    mouse.kind,
                    MouseEventKind::ScrollUp | MouseEventKind::ScrollDown
                ) {
                    PointerOutcome::consumed()
                } else {
                    PointerOutcome::ignored()
                }
            }
            OnboardingScreen::Complete { cursor, .. } => {
                if !matches!(mouse.kind, MouseEventKind::Down(MouseButton::Left)) {
                    return PointerOutcome::ignored();
                }
                let index = self
                    .list_row_rects
                    .iter()
                    .position(|rect| chrome::hit(*rect, pos));
                let Some(index) = index else {
                    return PointerOutcome::consumed();
                };
                if *cursor == index.min(1) {
                    if *cursor == 0 {
                        self.begin_completion_provider_detour(Some(
                            "Add another provider; live validation is required.".into(),
                        ));
                        PointerOutcome::consumed()
                    } else {
                        PointerOutcome::acted(OnboardingShellAction::Close)
                    }
                } else {
                    *cursor = index.min(1);
                    PointerOutcome::consumed()
                }
            }
            _ => PointerOutcome::ignored(),
        }
    }

    /// Paste into the focused shell field (search query or passphrase).
    pub(crate) fn paste(&mut self, text: &str) {
        match &mut self.screen {
            OnboardingScreen::Profile(screen) => screen.paste(text),
            OnboardingScreen::ProviderSearch(screen) => screen.paste_query(text),
            OnboardingScreen::Authenticate(screen) => screen.paste(text),
            OnboardingScreen::SecureStore(screen) => screen.paste(text),
            OnboardingScreen::AgentAuthoring(screen) => screen.paste(text),
            OnboardingScreen::Model(screen) => screen.paste(text),
            _ => {}
        }
    }

    /// Render the full-screen shell. `engine` renders engine-stage content
    /// into the shell's content area.
    pub(crate) fn render(
        &mut self,
        frame: &mut Frame,
        area: Rect,
        engine: &Dialog,
        links: &mut crate::tui::links::LinkRegistry,
    ) {
        // Hit geometry is repopulated by this frame's renderers only. Clear
        // all of it first — shell and screen — so an early return, a
        // zero-height content area, or a screen swap can never leave a
        // previous frame's rectangle clickable.
        self.clear_hit_geometry();
        if area.width == 0 || area.height == 0 {
            return;
        }
        frame.render_widget(Clear, area);

        // Welcome is an edge-to-edge cinematic scene. Its own prompt is the
        // only action affordance, and this stage never paints a Back button.
        if matches!(self.screen, OnboardingScreen::Welcome) {
            welcome::Scene::new(
                area.width,
                area.height,
                self.frame,
                self.reduced_motion,
                self.welcome_cloud_seed,
            )
            .render(frame, area);
            if let Some(menu) = self.escape.as_mut() {
                Self::render_escape_menu(frame, area, menu);
            }
            return;
        }

        let back_visible = !matches!(
            &self.screen,
            OnboardingScreen::SecureStore(screen)
                if matches!(screen.phase, secure_store::SecureStoreInputPhase::Choice)
        );
        let back_enabled = self.back_enabled();
        if !(back_visible && back_enabled) {
            // The hovered target no longer exists in this layout.
            self.back_hover = false;
        }
        self.back_rect =
            chrome::render_back_button(frame, area, back_visible, back_enabled, self.back_hover);

        let col = ui::column(area);
        let ShellRows {
            header,
            progress: progress_row,
            rule,
            content,
            footer,
        } = ShellRows::split(col);

        let title = format!(
            "{} · step {}/{}",
            self.screen_title(),
            progress_index(self.stage) + 1,
            PROGRESS_STEPS.len()
        );
        let subtitle = self.screen_subtitle();
        let title_color = match &self.screen {
            OnboardingScreen::Verify(screen) => match screen.phase() {
                verify::VerifyPhase::Success(_) | verify::VerifyPhase::NoEndpoint => GOOD,
                verify::VerifyPhase::Error(_) => BAD,
                verify::VerifyPhase::Fetching => INK,
            },
            OnboardingScreen::AgentAuthoring(screen) if screen.header_is_failure() => BAD,
            _ => INK,
        };
        ui::render_header_colored(frame, header, &title, &subtitle, title_color);
        self.render_progress(frame, progress_row);
        if let Some(rule) = rule {
            ui::render_rule(frame, rule);
        }
        self.list_area = content;
        match &mut self.screen {
            OnboardingScreen::Welcome => unreachable!("welcome returned above"),
            OnboardingScreen::Profile(screen) => screen.render(frame, content),
            OnboardingScreen::SecureStore(screen) => {
                if matches!(screen.phase, secure_store::SecureStoreInputPhase::Choice) {
                    Self::render_secure_store(frame, content, screen, &mut self.list_row_rects);
                } else {
                    self.list_row_rects.clear();
                    screen.render_password(frame, content);
                }
            }
            OnboardingScreen::ProviderSearch(screen) => {
                self.list_area =
                    Self::render_search(frame, content, screen, &mut self.list_row_rects);
            }
            OnboardingScreen::Authenticate(screen) => screen.render(frame, content),
            OnboardingScreen::Verify(screen) => screen.render(frame, content),
            OnboardingScreen::AgentAuthoring(screen) => {
                screen.render(frame, content);
            }
            OnboardingScreen::Lifetime(screen) => {
                Self::render_lifetime(frame, content, screen, &mut self.list_row_rects);
            }
            OnboardingScreen::Model(screen) => screen.render(frame, content),
            OnboardingScreen::Complete { summary, .. } => {
                Self::render_complete(frame, content, summary, &mut self.list_row_rects);
            }
            OnboardingScreen::EmbeddedSettings => {
                engine.render(frame, content, links);
            }
        }
        let buttons = Self::action_buttons(&self.screen);
        let bar_width = chrome::action_bar_width(&buttons);
        let help_width = footer.width.saturating_sub(bar_width.saturating_add(1));
        ui::render_help(
            frame,
            Rect {
                x: footer.x,
                y: footer.y,
                width: help_width,
                height: 1,
            },
            self.help_text(),
        );
        self.actions.render(frame, footer, &buttons);
        if let Some(menu) = self.escape.as_mut() {
            Self::render_escape_menu(frame, area, menu);
        }
    }

    /// Forget every clickable rectangle from the previous frame: the shell's
    /// back button, action bar, list rows, and Escape menu rows, plus the
    /// active screen's own geometry.
    ///
    /// Only per-frame geometry is cleared. Cross-frame interaction state —
    /// action-bar and Escape-menu hover, the back button's hover, a provider
    /// scrollbar drag, field focus, a pending double-click selection — is
    /// kept, and is invalidated only where the new layout shows its target
    /// is gone (see `ActionBar::render`, `set_scrollbar_area`, and the back
    /// button below).
    fn clear_hit_geometry(&mut self) {
        self.back_rect = Rect::default();
        self.actions.clear_geometry();
        self.list_row_rects.clear();
        self.list_area = Rect::default();
        if let Some(menu) = self.escape.as_mut() {
            menu.row_rects.clear();
        }
        match &mut self.screen {
            OnboardingScreen::Profile(screen) => screen.clear_hit_geometry(),
            OnboardingScreen::SecureStore(screen) => screen.clear_hit_geometry(),
            OnboardingScreen::ProviderSearch(screen) => screen.clear_hit_geometry(),
            OnboardingScreen::Authenticate(screen) => screen.clear_hit_geometry(),
            OnboardingScreen::Model(screen) => screen.clear_hit_geometry(),
            OnboardingScreen::AgentAuthoring(screen) => screen.clear_hit_geometry(),
            OnboardingScreen::Welcome
            | OnboardingScreen::Verify(_)
            | OnboardingScreen::Lifetime(_)
            | OnboardingScreen::Complete { .. }
            | OnboardingScreen::EmbeddedSettings => {}
        }
    }

    fn screen_title(&self) -> &'static str {
        match &self.screen {
            OnboardingScreen::Welcome => "Welcome",
            OnboardingScreen::Profile(_) => "What should Cockpit call you?",
            OnboardingScreen::SecureStore(_) => "Secure your secrets",
            OnboardingScreen::ProviderSearch(_) => "Let's add a provider",
            OnboardingScreen::Authenticate(screen) => screen.title(),
            OnboardingScreen::Verify(screen) => screen.title(),
            OnboardingScreen::Complete { .. } => "You're ready to fly",
            OnboardingScreen::AgentAuthoring(screen) => screen.phase_title(),
            OnboardingScreen::Lifetime(_) => "Background agents",
            OnboardingScreen::Model(screen) => screen.title(),
            OnboardingScreen::EmbeddedSettings => "Cockpit setup",
        }
    }

    fn screen_subtitle(&self) -> String {
        let mut parts = Vec::new();
        let base = match &self.screen {
            OnboardingScreen::Profile(_) => "Set an optional display name.".to_string(),
            OnboardingScreen::SecureStore(_) => {
                "Choose how Cockpit protects your API keys and sealed values.".to_string()
            }
            OnboardingScreen::ProviderSearch(_) => "Pick who you'll fly with.".to_string(),
            OnboardingScreen::Authenticate(screen) => screen.subtitle(),
            OnboardingScreen::Verify(screen) => screen.subtitle(),
            OnboardingScreen::Lifetime(_) => {
                "Choose what happens after the last Cockpit window closes.".to_string()
            }
            OnboardingScreen::Model(screen) => screen.subtitle().to_string(),
            OnboardingScreen::AgentAuthoring(screen) => screen.phase_subtitle(),
            OnboardingScreen::Complete { .. } => "Your setup is complete.".to_string(),
            _ => String::new(),
        };
        if self.limited_mode {
            parts.push("limited mode".to_string());
        }
        match self.bootstrap_state {
            OnboardingBootstrapState::Materializing => {
                parts.push("Preparing the secure store…".to_string());
            }
            OnboardingBootstrapState::Failed => {
                parts.push("Onboarding bootstrap failed; retrying ready construction…".to_string());
            }
            _ => {}
        }
        if !base.is_empty() {
            parts.push(base);
        }
        parts.join(" · ")
    }

    fn help_text(&self) -> &'static str {
        match &self.screen {
            OnboardingScreen::Welcome => "any key: begin setup  esc: options",
            OnboardingScreen::Profile(_) => {
                "type a name or leave blank  enter: continue  esc: options"
            }
            OnboardingScreen::SecureStore(screen) => screen.help_text(),
            OnboardingScreen::ProviderSearch(screen) => screen.help_text(),
            OnboardingScreen::Authenticate(screen) => screen.help_text(),
            OnboardingScreen::Verify(screen) => screen.help_text(),
            OnboardingScreen::AgentAuthoring(screen) => screen.help_text(),
            OnboardingScreen::Lifetime(_) => {
                "↑↓ move   click choose   enter continue   esc options"
            }
            OnboardingScreen::Model(screen) => screen.help_text(),
            OnboardingScreen::EmbeddedSettings => "wizard  esc: options",
            OnboardingScreen::Complete { .. } => "↑/↓  enter: choose",
        }
    }

    fn action_buttons(screen: &OnboardingScreen) -> Vec<chrome::Button<'static>> {
        match screen {
            OnboardingScreen::Welcome => vec![chrome::Button::primary("Continue")],
            OnboardingScreen::Profile(_) => vec![chrome::Button::primary("Continue")],
            OnboardingScreen::SecureStore(screen)
                if !matches!(screen.phase, secure_store::SecureStoreInputPhase::Choice) =>
            {
                vec![
                    chrome::Button::secondary("Reveal"),
                    chrome::Button::primary("Save"),
                ]
            }
            OnboardingScreen::SecureStore(screen) => {
                vec![chrome::Button::primary("Continue").enabled(screen.row_enabled(screen.cursor))]
            }
            OnboardingScreen::ProviderSearch(screen) => {
                vec![chrome::Button::primary("Choose").enabled(screen.choose_enabled())]
            }
            OnboardingScreen::Authenticate(screen) => screen.buttons(),
            OnboardingScreen::Verify(screen) => screen.buttons(),
            OnboardingScreen::AgentAuthoring(screen) => screen.buttons(),
            OnboardingScreen::Lifetime(_) => vec![chrome::Button::primary("Continue")],
            OnboardingScreen::Model(_) => vec![chrome::Button::primary("Continue")],
            OnboardingScreen::EmbeddedSettings => vec![chrome::Button::primary("Continue")],
            OnboardingScreen::Complete { cursor, .. } if *cursor == 0 => vec![
                chrome::Button::primary("Add another provider"),
                chrome::Button::secondary("Start coding"),
            ],
            OnboardingScreen::Complete { .. } => vec![
                chrome::Button::secondary("Add another provider"),
                chrome::Button::primary("Start coding"),
            ],
        }
    }

    fn render_progress(&self, frame: &mut Frame, area: Rect) {
        // The row picks its own tier for the width (full, compact, minimal)
        // and is never wrapped: a wrap into this single row used to cut the
        // last steps off silently on narrow terminals.
        let (_, line) = progress::progress_line(progress_index(self.stage), area.width);
        frame.render_widget(Paragraph::new(line), area);
    }

    fn render_secure_store(
        frame: &mut Frame,
        area: Rect,
        screen: &SecureStoreScreen,
        list_row_rects: &mut Vec<Rect>,
    ) {
        let lines = screen.lines();
        let mut y = area.y;
        for line in lines {
            if y >= area.bottom() {
                break;
            }
            frame.render_widget(
                Paragraph::new(line).wrap(Wrap { trim: false }),
                Rect {
                    x: area.x,
                    y,
                    width: area.width,
                    height: 1,
                },
            );
            y += 1;
        }
        list_row_rects.clear();
        if matches!(screen.phase, secure_store::SecureStoreInputPhase::Choice) {
            for index in 0..3u16 {
                let y = area.y + index;
                if y < area.bottom() {
                    list_row_rects.push(if screen.row_enabled(index as usize) {
                        Rect {
                            x: area.x,
                            y,
                            width: area.width,
                            height: 1,
                        }
                    } else {
                        Rect::default()
                    });
                }
            }
            let detail_area = Rect {
                x: area.x,
                y: (area.y + 4).min(area.bottom()),
                width: area.width,
                height: area.height.saturating_sub(4),
            };
            frame.render_widget(
                Paragraph::new(screen.detail_lines()).wrap(Wrap { trim: true }),
                detail_area,
            );
        }
    }

    fn render_lifetime(
        frame: &mut Frame,
        area: Rect,
        screen: &LifetimeScreen,
        list_row_rects: &mut Vec<Rect>,
    ) {
        let lines = screen.lines();
        for (y, line) in (area.y..).zip(lines) {
            if y >= area.bottom() {
                break;
            }
            frame.render_widget(
                Paragraph::new(line).wrap(Wrap { trim: false }),
                Rect {
                    x: area.x,
                    y,
                    width: area.width,
                    height: 1,
                },
            );
        }
        list_row_rects.clear();
        for index in 0..2u16 {
            let row_y = area.y + index;
            if row_y < area.bottom() {
                list_row_rects.push(Rect {
                    x: area.x,
                    y: row_y,
                    width: area.width,
                    height: 1,
                });
            }
        }
        let detail_area = Rect {
            x: area.x,
            y: (area.y + 3).min(area.bottom()),
            width: area.width,
            height: area.height.saturating_sub(3),
        };
        frame.render_widget(
            Paragraph::new(screen.detail_lines()).wrap(Wrap { trim: true }),
            detail_area,
        );
    }

    fn render_search(
        frame: &mut Frame,
        area: Rect,
        screen: &mut ProviderSearchScreen,
        list_row_rects: &mut Vec<Rect>,
    ) -> Rect {
        let chunks = Layout::vertical([
            Constraint::Length(3),
            Constraint::Length(1),
            Constraint::Min(6),
            Constraint::Length(4),
        ])
        .split(area);
        if let Some(caret) = ui::render_field(
            frame,
            chunks[0],
            "Filter",
            screen.query_field(),
            true,
            "filter by name",
        ) {
            frame.set_cursor_position(caret);
        }
        let total = onboarding_catalog().len();
        let filtered = screen.filtered().len();
        let title = if filtered == total {
            format!(" Providers  ·  {total} ")
        } else {
            format!(" Providers  ·  {filtered} of {total} ")
        };
        let block = Block::bordered()
            .border_type(crate::tui::chrome::rounded_border_type())
            .border_style(Style::new().fg(NIGHT))
            .title(Span::styled(title, Style::new().fg(INK)))
            .padding(Padding::horizontal(1));
        let list_area = block.inner(chunks[2]);
        frame.render_widget(block, chunks[2]);
        let capacity = list_area.height as usize;
        screen.observe_viewport(capacity);
        let rows = screen.visible_rows(capacity);
        let show_scrollbar = filtered > capacity && list_area.width >= 2;
        let row_width = if show_scrollbar {
            list_area.width.saturating_sub(1)
        } else {
            list_area.width
        };
        list_row_rects.clear();
        let mut row_y = list_area.y;
        for row in &rows {
            if row_y >= list_area.bottom() {
                break;
            }
            frame.render_widget(
                Paragraph::new(screen.render_row(row)),
                Rect {
                    x: list_area.x,
                    y: row_y,
                    width: row_width,
                    height: 1,
                },
            );
            list_row_rects.push(Rect {
                x: list_area.x,
                y: row_y,
                width: row_width,
                height: 1,
            });
            row_y += 1;
        }
        if rows.is_empty() {
            let y = list_area.y.min(list_area.bottom().saturating_sub(1));
            frame.render_widget(
                Paragraph::new(Line::from(Span::styled(
                    "No provider matches this search.",
                    Style::default().fg(FOG),
                ))),
                Rect {
                    x: list_area.x,
                    y,
                    width: list_area.width,
                    height: 1,
                },
            );
        }
        if show_scrollbar {
            let scrollbar_area = Rect {
                x: list_area.right().saturating_sub(1),
                y: list_area.y,
                width: 1,
                height: list_area.height,
            };
            screen.set_scrollbar_area(scrollbar_area);
            ui::render_scrollbar(
                frame,
                scrollbar_area,
                filtered,
                capacity.max(1),
                screen.offset_for_scroll(),
                screen.dragging_scrollbar(),
            );
        } else {
            screen.set_scrollbar_area(Rect::default());
        }
        if let Some(status) = screen.status_paragraph() {
            frame.render_widget(status, chunks[3]);
        } else if let Some(lines) = screen.selected_detail() {
            frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), chunks[3]);
        } else {
            frame.render_widget(
                Paragraph::new(Span::styled(
                    "Type a few letters to narrow the list.",
                    Style::new().fg(FOG),
                )),
                chunks[3],
            );
        }
        list_area
    }

    fn render_complete(
        frame: &mut Frame,
        area: Rect,
        summary: &str,
        list_row_rects: &mut Vec<Rect>,
    ) {
        list_row_rects.clear();
        let head = vec![
            Line::from("Cockpit is ready."),
            Line::from(summary.to_string()),
            Line::default(),
            Line::from("Next: run /setup security to choose project trust and approval defaults."),
            Line::from("Use /help any time to see available commands."),
        ];
        let block = Block::bordered()
            .border_type(crate::tui::chrome::rounded_border_type())
            .border_style(Style::new().fg(GOOD))
            .title(Span::styled(
                " Summary ",
                Style::new().fg(GOOD).add_modifier(Modifier::BOLD),
            ))
            .padding(Padding::horizontal(1));
        let inner = block.inner(area);
        frame.render_widget(block, area);
        frame.render_widget(Paragraph::new(head).wrap(Wrap { trim: false }), inner);
    }

    fn render_escape_menu(frame: &mut Frame, area: Rect, menu: &mut EscapeMenu) {
        let width = 48.min(area.width.saturating_sub(4));
        let height = (menu.choices.len() as u16 + 4)
            .min(area.height.saturating_sub(2))
            .max(menu.choices.len() as u16 + 2);
        let x = area.x + (area.width.saturating_sub(width)) / 2;
        let y = area.y + (area.height.saturating_sub(height)) / 2;
        let rect = Rect {
            x,
            y,
            width,
            height,
        };
        frame.render_widget(Clear, rect);
        let block = Block::bordered()
            .border_type(crate::tui::chrome::rounded_border_type())
            .border_style(Style::new().fg(BRASS))
            .title(Span::styled(" Leave setup? ", Style::new().fg(BRASS)));
        let inner = block.inner(rect);
        frame.render_widget(block, rect);
        let intro = [
            Line::from(Span::styled(
                "Unsaved entries in this step are discarded.",
                Style::new().fg(FOG),
            )),
            Line::default(),
        ];
        let mut y = inner.y;
        for line in intro {
            if y >= inner.bottom() {
                break;
            }
            frame.render_widget(
                Paragraph::new(line),
                Rect {
                    x: inner.x,
                    y,
                    width: inner.width,
                    height: 1,
                },
            );
            y += 1;
        }
        menu.row_rects.clear();
        for (index, choice) in menu.choices.iter().enumerate() {
            if y >= inner.bottom() {
                break;
            }
            let selected = index == menu.cursor;
            let hovered = menu.hover == Some(index);
            let mut style = if selected {
                Style::default().fg(BRASS).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(INK)
            };
            if hovered {
                style = style.bg(HOVER_BG);
            }
            frame.render_widget(
                Paragraph::new(Line::from(Span::styled(
                    format!("{} {}", if selected { "›" } else { " " }, choice.label()),
                    style,
                ))),
                Rect {
                    x: inner.x,
                    y,
                    width: inner.width,
                    height: 1,
                },
            );
            menu.row_rects.push(Rect {
                x: inner.x,
                y,
                width: inner.width,
                height: 1,
            });
            y += 1;
        }
    }
}
