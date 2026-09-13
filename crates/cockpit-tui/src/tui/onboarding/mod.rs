//! Full-screen onboarding shell.
//!
//! One renderer owns every first-run surface: animated welcome, secure-store
//! choice, searchable provider catalog, provider auth/validation, model /
//! agent / lifetime stages, and completion. The shell is a *presentation and
//! navigation* reducer only:
//!
//! * stage authority lives in the daemon `OnboardingBootstrapSnapshot`
//!   consumed through [`OnboardingShell::sync_snapshot`];
//! * provider auth, validation, and config writes stay in the embedded
//!   settings provider engine (a [`settings::Dialog`] driven through the
//!   ordinary daemon effect plumbing);
//! * every Back / Defer / Cancel / Advance intent is emitted as an
//!   [`OnboardingShellAction`] for the app to map onto the daemon
//!   transition RPCs. Escape never silently defers: when work is
//!   discardable it opens a visible Back / Defer / Cancel choice.
//!
//! The welcome fly-in is driven by an explicit frame counter advanced from
//! the app wake loop (`tick`), never by sleeps. `NO_COLOR`, `TERM=dumb`, and
//! the `COCKPIT_REDUCE_MOTION` / `REDUCE_MOTION` controls select the
//! deterministic static alternative.

mod search;
mod secure_store;

#[cfg(test)]
mod tests;

use crossterm::event::{KeyCode, KeyEvent, MouseButton, MouseEvent, MouseEventKind};
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};

use crate::tui::settings::Dialog;
use crate::tui::theme::MUTED_COLOR_INDEX;
use cockpit_core::providers::ProviderTemplate;
use cockpit_proto::{
    OnboardingBootstrapSnapshot, OnboardingBootstrapState, OnboardingStage,
    OnboardingStageSettlement, OnboardingTransitionKind,
};
use search::ProviderSearchScreen;
use secure_store::SecureStoreScreen;

pub use secure_store::SecureStoreSubmission;

/// Frames the welcome fly-in runs for before settling on the static layout.
const WELCOME_ANIMATION_FRAMES: usize = 18;

/// Ordered progress chrome. Maps the daemon stage enum onto the seven
/// user-visible checkpoints (welcome/profile share the first slot).
const PROGRESS_STEPS: [&str; 7] = [
    "Welcome",
    "Secure store",
    "Provider",
    "Model",
    "Agent",
    "Lifetime",
    "Ready",
];

fn progress_index(stage: OnboardingStage) -> usize {
    match stage {
        OnboardingStage::Welcome | OnboardingStage::Profile => 0,
        OnboardingStage::SecureStore => 1,
        OnboardingStage::Provider => 2,
        OnboardingStage::Model => 3,
        OnboardingStage::Agent => 4,
        OnboardingStage::Lifetime => 5,
        OnboardingStage::Complete => 6,
    }
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

/// Which onboarding stage the embedded settings-dialog engine renders.
/// The engine itself is owned by the app and driven through the ordinary
/// `Dialog` daemon-effect accessors; the shell records the pairing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EngineStage {
    Profile,
    Provider,
    Model,
    Agent,
    Lifetime,
}

impl EngineStage {
    fn for_stage(stage: OnboardingStage) -> Option<Self> {
        match stage {
            OnboardingStage::Profile => Some(Self::Profile),
            OnboardingStage::Provider => Some(Self::Provider),
            OnboardingStage::Model => Some(Self::Model),
            OnboardingStage::Agent => Some(Self::Agent),
            OnboardingStage::Lifetime => Some(Self::Lifetime),
            OnboardingStage::Welcome | OnboardingStage::SecureStore | OnboardingStage::Complete => {
                None
            }
        }
    }
}

/// The screen the shell is presenting. `Engine` screens delegate their
/// content area to the app-held settings dialog (provider add wizard or
/// setup wizard); the shell still owns chrome, navigation, and semantics.
pub(crate) enum OnboardingScreen {
    Welcome,
    SecureStore(Box<SecureStoreScreen>),
    ProviderSearch(Box<ProviderSearchScreen>),
    Engine(EngineStage),
    Complete { summary: String, cursor: usize },
}

/// Screen classification for callers that only need to know whether the
/// embedded settings engine currently owns the content area.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OnboardingScreenKind {
    Welcome,
    SecureStore,
    ProviderSearch,
    Engine,
    Complete,
}

impl std::fmt::Debug for OnboardingScreen {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Discriminant-only: the secure-store screen holds zeroizing
        // passphrase state that must never be formatted.
        match self {
            Self::Welcome => formatter.write_str("Welcome"),
            Self::SecureStore(_) => formatter.write_str("SecureStore([REDACTED])"),
            Self::ProviderSearch(_) => formatter.write_str("ProviderSearch"),
            Self::Engine(stage) => formatter.debug_tuple("Engine").field(stage).finish(),
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
    /// Seed the provider engine with the selected canonical template.
    SelectTemplate(&'static ProviderTemplate),
    /// Leave the "add another provider" detour and present the stored
    /// completion summary again. Purely shell-local: the daemon stage is
    /// already `Complete`.
    ReturnToCompletion,
    /// Close the shell preserving committed daemon progress; discard only
    /// local unsaved text.
    Close,
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
            Self::SelectTemplate(template) => formatter
                .debug_tuple("SelectTemplate")
                .field(&template.id)
                .finish(),
            Self::ReturnToCompletion => formatter.write_str("ReturnToCompletion"),
            Self::Close => formatter.write_str("Close"),
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

    fn handle_mouse(&mut self, mouse: MouseEvent) -> Option<EscapeChoice> {
        if !matches!(mouse.kind, MouseEventKind::Down(MouseButton::Left)) {
            return None;
        }
        let index = self
            .row_rects
            .iter()
            .position(|rect| rect.contains((mouse.column, mouse.row).into()))?;
        self.cursor = index;
        self.choices.get(index).copied()
    }
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
    /// Explicit frame counter for the welcome fly-in; advanced only by
    /// [`Self::tick`].
    frame: usize,
    screen: OnboardingScreen,
    escape: Option<EscapeMenu>,
    /// Summary text computed when the lifetime stage settled; presented on
    /// the completion screen when the authoritative `Complete` revision
    /// lands, and again when the "add another provider" detour ends.
    completion_summary: Option<String>,
    /// True while the shell is in the completion screen's local "add
    /// another provider" detour (search + provider engine). The daemon
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
            screen,
            escape: None,
            completion_summary: None,
            completion_detour: false,
            pending_transition: None,
            list_row_rects: Vec::new(),
        }
    }

    fn native_screen_for(snapshot: &OnboardingBootstrapSnapshot) -> OnboardingScreen {
        match snapshot.stage {
            OnboardingStage::Welcome | OnboardingStage::Profile => OnboardingScreen::Welcome,
            OnboardingStage::SecureStore => OnboardingScreen::SecureStore(Box::new(
                SecureStoreScreen::new(snapshot.host_capabilities.clone()),
            )),
            OnboardingStage::Provider => {
                OnboardingScreen::ProviderSearch(Box::new(ProviderSearchScreen::new()))
            }
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
            // Engine stages are mounted by the app, which owns the settings
            // dialog; `present_engine` pairs the screen with that mount
            // before the next render.
            stage => OnboardingScreen::Engine(
                EngineStage::for_stage(stage).expect("engine stages map onto engine screens"),
            ),
        }
    }

    pub(crate) fn stage(&self) -> OnboardingStage {
        self.stage
    }

    pub(crate) fn screen_is_complete(&self) -> bool {
        matches!(self.screen, OnboardingScreen::Complete { .. })
    }

    pub(crate) fn screen_is_engine(&self, stage: EngineStage) -> bool {
        matches!(self.screen, OnboardingScreen::Engine(current) if current == stage)
    }

    pub(crate) fn screen_kind(&self) -> OnboardingScreenKind {
        match &self.screen {
            OnboardingScreen::Welcome => OnboardingScreenKind::Welcome,
            OnboardingScreen::SecureStore(_) => OnboardingScreenKind::SecureStore,
            OnboardingScreen::ProviderSearch(_) => OnboardingScreenKind::ProviderSearch,
            OnboardingScreen::Engine(_) => OnboardingScreenKind::Engine,
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
    pub(crate) fn present_engine(&mut self, stage: EngineStage) {
        self.screen = OnboardingScreen::Engine(stage);
        self.escape = None;
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
    /// the searchable catalog (and, after a selection, the provider
    /// engine) with a shell-local return path. The daemon stage stays
    /// `Complete`; the added provider settles through the ordinary
    /// provider mutation authority, not an onboarding transition.
    pub(crate) fn begin_completion_provider_detour(&mut self, status: Option<String>) {
        let mut screen = ProviderSearchScreen::new();
        screen.set_status(status);
        self.screen = OnboardingScreen::ProviderSearch(Box::new(screen));
        self.completion_detour = true;
        self.escape = None;
    }

    /// Return to the provider catalog. Used when a provider engine mounted
    /// from the `Provider` stage abandons its Add page. The completion
    /// detour flag is preserved: abandoning the detour's engine stays
    /// inside the detour, whose Escape offers a local return.
    pub(crate) fn present_provider_search(&mut self, status: Option<String>) {
        let mut screen = ProviderSearchScreen::new();
        screen.set_status(status);
        self.screen = OnboardingScreen::ProviderSearch(Box::new(screen));
        self.escape = None;
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

    /// Reconcile the provider-engine pairing after any input path (key,
    /// pointer, tick): an engine that left its Add page abandoned provider
    /// setup, so the shell returns to the searchable catalog instead of a
    /// settings list. Completion is *not* an abandon — the onboarding
    /// wizard never leaves its Add page on Done; the daemon transition
    /// owns that exit.
    pub(crate) fn reconcile_provider_engine(&mut self, engine: &Dialog) {
        if matches!(self.screen, OnboardingScreen::Engine(EngineStage::Provider))
            && !engine.is_provider_add()
        {
            self.present_provider_search(Some(
                "Provider setup was cancelled; nothing was saved.".into(),
            ));
        }
    }

    /// Feed live host capabilities to the secure-store screen. Placement is
    /// gated on these rows; a bootstrap snapshot fetched while capabilities
    /// were unpublished must not strand a stale view. Generation-monotonic:
    /// an unpublished placeholder never clobbers published rows.
    pub(crate) fn apply_host_capabilities(
        &mut self,
        capabilities: &cockpit_proto::HostCapabilitySnapshot,
    ) {
        if let OnboardingScreen::SecureStore(screen) = &mut self.screen {
            if capabilities.generation >= screen.capabilities.generation {
                screen.capabilities = capabilities.clone();
            }
        }
    }

    /// Advance the welcome fly-in exactly one frame. Returns whether the
    /// frame changed (redraw needed).
    pub(crate) fn tick(&mut self) -> bool {
        if !matches!(self.screen, OnboardingScreen::Welcome) || self.reduced_motion {
            return false;
        }
        if self.frame < WELCOME_ANIMATION_FRAMES {
            self.frame += 1;
            true
        } else {
            false
        }
    }

    /// Route a key through the shell. `engine` is the app's settings dialog
    /// that renders engine-stage content.
    pub(crate) fn handle_key(
        &mut self,
        key: KeyEvent,
        engine: &mut Dialog,
    ) -> Option<OnboardingShellAction> {
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

        match &mut self.screen {
            OnboardingScreen::Welcome => {
                if matches!(key.code, KeyCode::Esc) {
                    self.open_escape_menu(engine);
                    return None;
                }
                // Any other key begins setup. A Welcome screen paired with a
                // later stage (a failed profile-engine mount) must not skip
                // that stage; only the authoritative Welcome stage advances.
                if self.stage == OnboardingStage::Welcome {
                    return Some(OnboardingShellAction::Transition(
                        OnboardingTransitionKind::Advance,
                        None,
                    ));
                }
                None
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
            OnboardingScreen::Complete { cursor, .. } => {
                match key.code {
                    KeyCode::Esc => {
                        // Completion has nothing discardable; Escape keeps
                        // the choice visible instead of silently closing.
                        self.open_escape_menu(engine);
                    }
                    KeyCode::Up => *cursor = cursor.saturating_sub(1),
                    KeyCode::Down => *cursor = (*cursor + 1).min(1),
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
            OnboardingScreen::Engine(current) => {
                let stage = *current;
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
                if stage == EngineStage::Provider {
                    self.reconcile_provider_engine(engine);
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
    /// escape menu is modal; otherwise only native list surfaces consume
    /// events, so engine pointer routing keeps flowing through the app's
    /// ordinary settings path.
    pub(crate) fn handle_mouse(&mut self, mouse: MouseEvent) -> PointerOutcome {
        if let Some(menu) = self.escape.as_mut() {
            if matches!(mouse.kind, MouseEventKind::Moved) {
                return PointerOutcome::ignored();
            }
            return match menu.handle_mouse(mouse) {
                Some(choice) => {
                    self.escape = None;
                    PointerOutcome::acted(self.apply_escape_choice(choice))
                }
                // The menu is modal: clicks that miss its rows dismiss it
                // without effect, and other events stop here.
                None => {
                    self.escape = None;
                    PointerOutcome::consumed()
                }
            };
        }
        match &mut self.screen {
            OnboardingScreen::SecureStore(screen) => match mouse.kind {
                MouseEventKind::ScrollUp => {
                    screen.cursor = screen.cursor.saturating_sub(1);
                    PointerOutcome::consumed()
                }
                MouseEventKind::ScrollDown => {
                    screen.cursor = (screen.cursor + 1).min(2);
                    PointerOutcome::consumed()
                }
                MouseEventKind::Down(MouseButton::Left) => {
                    let rects = std::mem::take(&mut self.list_row_rects);
                    screen.handle_mouse(mouse, &rects);
                    self.list_row_rects = rects;
                    match screen.take_submission() {
                        Some(submission) => {
                            PointerOutcome::acted(OnboardingShellAction::SecureIntent(submission))
                        }
                        None => PointerOutcome::consumed(),
                    }
                }
                _ => PointerOutcome::ignored(),
            },
            OnboardingScreen::ProviderSearch(screen) => {
                let rects = std::mem::take(&mut self.list_row_rects);
                let action = screen.handle_mouse(mouse, &rects);
                self.list_row_rects = rects;
                match action {
                    Some(template) => {
                        PointerOutcome::acted(OnboardingShellAction::SelectTemplate(template))
                    }
                    // The search screen owns the whole content area while
                    // active; wheel scrolls and row clicks are its input.
                    None if matches!(
                        mouse.kind,
                        MouseEventKind::ScrollUp
                            | MouseEventKind::ScrollDown
                            | MouseEventKind::Down(MouseButton::Left)
                    ) =>
                    {
                        PointerOutcome::consumed()
                    }
                    None => PointerOutcome::ignored(),
                }
            }
            OnboardingScreen::Complete { cursor, .. } => {
                if !matches!(mouse.kind, MouseEventKind::Down(MouseButton::Left)) {
                    return PointerOutcome::ignored();
                }
                let index = self
                    .list_row_rects
                    .iter()
                    .position(|rect| rect.contains((mouse.column, mouse.row).into()));
                let Some(index) = index else {
                    return PointerOutcome::consumed();
                };
                *cursor = index.min(1);
                if *cursor == 0 {
                    self.begin_completion_provider_detour(Some(
                        "Add another provider; live validation is required.".into(),
                    ));
                    PointerOutcome::consumed()
                } else {
                    PointerOutcome::acted(OnboardingShellAction::Close)
                }
            }
            _ => PointerOutcome::ignored(),
        }
    }

    /// Paste into the focused shell field (search query or passphrase).
    pub(crate) fn paste(&mut self, text: &str) {
        match &mut self.screen {
            OnboardingScreen::ProviderSearch(screen) => screen.paste_query(text),
            OnboardingScreen::SecureStore(screen) => screen.paste(text),
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
        if area.width == 0 || area.height == 0 {
            return;
        }
        // Full-screen frame: the shell replaces the chat UI entirely.
        let mut title = format!(
            " Cockpit setup · step {}/{} ",
            progress_index(self.stage) + 1,
            PROGRESS_STEPS.len()
        );
        if self.limited_mode {
            title.push_str("· limited mode ");
        }
        let block = Block::default().borders(Borders::ALL).title(title);
        let inner = block.inner(area);
        frame.render_widget(Clear, area);
        frame.render_widget(block, area);
        let rows = Layout::vertical([
            Constraint::Length(1), // progress
            Constraint::Min(1),    // content
            Constraint::Length(1), // status
            Constraint::Length(1), // help
        ])
        .split(inner);
        self.render_progress(frame, rows[0]);
        match &mut self.screen {
            OnboardingScreen::Welcome => {
                Self::render_welcome(self.reduced_motion, self.frame, frame, rows[1]);
            }
            OnboardingScreen::SecureStore(screen) => {
                Self::render_secure_store(frame, rows[1], screen, &mut self.list_row_rects);
            }
            OnboardingScreen::ProviderSearch(screen) => {
                Self::render_search(frame, rows[1], screen, &mut self.list_row_rects);
            }
            OnboardingScreen::Complete { summary, cursor } => {
                Self::render_complete(frame, rows[1], summary, *cursor, &mut self.list_row_rects);
            }
            OnboardingScreen::Engine(_) => {
                engine.render(frame, rows[1], links);
            }
        }
        self.render_status(frame, rows[2]);
        self.render_help(frame, rows[3]);
        if let Some(menu) = self.escape.as_mut() {
            Self::render_escape_menu(frame, area, menu);
        }
    }

    fn render_progress(&self, frame: &mut Frame, area: Rect) {
        let current = progress_index(self.stage);
        let mut spans = Vec::new();
        for (index, step) in PROGRESS_STEPS.iter().enumerate() {
            let (mark, color) = if index < current {
                ("●", Color::Green)
            } else if index == current {
                ("◐", Color::Yellow)
            } else {
                ("○", Color::Indexed(MUTED_COLOR_INDEX))
            };
            let mut style = Style::default().fg(color);
            if index == current {
                style = style.add_modifier(Modifier::BOLD);
            }
            spans.push(Span::styled(format!("{mark} {step}"), style));
            if index + 1 < PROGRESS_STEPS.len() {
                spans.push(Span::raw("  "));
            }
        }
        frame.render_widget(
            Paragraph::new(Line::from(spans)).wrap(Wrap { trim: false }),
            area,
        );
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
        // Record the three selectable placement rows for pointer input:
        // they start after the two intro lines and one blank line.
        list_row_rects.clear();
        if matches!(screen.phase, secure_store::SecureStoreInputPhase::Choice) {
            for index in 0..3u16 {
                let y = area.y + 3 + index;
                if y < area.bottom() {
                    list_row_rects.push(Rect {
                        x: area.x,
                        y,
                        width: area.width,
                        height: 1,
                    });
                }
            }
        }
    }

    fn render_welcome(reduced_motion: bool, frame_count: usize, frame: &mut Frame, area: Rect) {
        let flying = !reduced_motion && frame_count < WELCOME_ANIMATION_FRAMES;
        // Fly-in: the mark travels from the left edge toward its resting
        // column over the animation window, then the static layout remains.
        let progress = if flying {
            frame_count as f64 / WELCOME_ANIMATION_FRAMES as f64
        } else {
            1.0
        };
        let rest_col = f64::from(area.width.saturating_sub(12) / 2);
        let mark_col = if reduced_motion {
            rest_col
        } else {
            rest_col * progress
        };
        let mark_col = mark_col.round() as u16;
        let mark = if reduced_motion {
            "✈"
        } else if flying {
            match (frame_count / 3) % 4 {
                0 => "·",
                1 => "✦",
                2 => "✈",
                _ => "✦",
            }
        } else {
            "✈"
        };
        let mut lines = Vec::new();
        let mut logo_line = Line::default();
        logo_line
            .spans
            .push(Span::raw(" ".repeat(mark_col as usize)));
        logo_line.spans.push(Span::styled(
            format!("{mark}  FlyCockpit"),
            if reduced_motion {
                Style::default()
            } else {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            },
        ));
        lines.push(logo_line);
        lines.push(Line::default());
        let description = if area.width < 54 {
            "Your coding cockpit."
        } else {
            "A focused cockpit for coding with the models you choose."
        };
        lines.push(Line::from(description));
        lines.push(Line::default());
        lines.push(Line::from("No Cockpit telemetry is collected."));
        lines.push(Line::from(
            "Inference providers may have their own telemetry policies.",
        ));
        // The call to action appears once the fly-in settles; the
        // deterministic reduced-motion layout shows it immediately.
        if !flying {
            lines.push(Line::default());
            lines.push(Line::from(Span::styled(
                "Press any key to begin setup.",
                Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX)),
            )));
        }
        lines.truncate(lines.len().min(area.height as usize));
        frame.render_widget(
            Paragraph::new(lines)
                .alignment(ratatui::layout::Alignment::Left)
                .wrap(Wrap { trim: false }),
            area,
        );
    }

    fn render_search(
        frame: &mut Frame,
        area: Rect,
        screen: &mut ProviderSearchScreen,
        list_row_rects: &mut Vec<Rect>,
    ) {
        // Layout inside the content area: query line, blank, rows, then a
        // trailing status/hint row pair.
        let capacity = area.height.saturating_sub(4) as usize;
        screen.observe_viewport(capacity);
        let rows = screen.visible_rows(capacity);
        frame.render_widget(
            Paragraph::new(screen.render_query_line()),
            Rect {
                x: area.x,
                y: area.y,
                width: area.width,
                height: 1,
            },
        );
        list_row_rects.clear();
        let mut row_y = area.y + 2;
        for row in &rows {
            if row_y >= area.bottom() {
                break;
            }
            frame.render_widget(
                Paragraph::new(screen.render_row(row)),
                Rect {
                    x: area.x,
                    y: row_y,
                    width: area.width,
                    height: 1,
                },
            );
            list_row_rects.push(Rect {
                x: area.x,
                y: row_y,
                width: area.width,
                height: 1,
            });
            row_y += 1;
        }
        if rows.is_empty() {
            let y = (area.y + 2).min(area.bottom().saturating_sub(1));
            frame.render_widget(
                Paragraph::new(Line::from(Span::styled(
                    "No provider matches this search.",
                    Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX)),
                ))),
                Rect {
                    x: area.x,
                    y,
                    width: area.width,
                    height: 1,
                },
            );
        }
        if let Some(status) = screen.status_paragraph() {
            let y = area.bottom().saturating_sub(2).max(area.y + 2);
            frame.render_widget(
                status,
                Rect {
                    x: area.x,
                    y,
                    width: area.width,
                    height: 1,
                },
            );
        }
        let help_y = area.bottom().saturating_sub(1);
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                screen.help_text(),
                Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX)),
            ))),
            Rect {
                x: area.x,
                y: help_y,
                width: area.width,
                height: 1,
            },
        );
    }

    fn render_complete(
        frame: &mut Frame,
        area: Rect,
        summary: &str,
        cursor: usize,
        list_row_rects: &mut Vec<Rect>,
    ) {
        list_row_rects.clear();
        let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
        let head = vec![
            Line::from("Cockpit is ready."),
            Line::from(summary.to_string()),
            Line::default(),
            Line::from("Next: run /setup security to choose project trust and approval defaults."),
            Line::from("Use /help any time to see available commands."),
        ];
        frame.render_widget(
            Paragraph::new(head).wrap(Wrap { trim: false }),
            Rect {
                x: area.x,
                y: area.y,
                width: area.width,
                height: 5.min(area.height),
            },
        );
        let mut y = area.y + 5;
        for (index, label) in ["Add another provider", "Start coding"].iter().enumerate() {
            if y >= area.bottom() {
                break;
            }
            frame.render_widget(
                Paragraph::new(Line::from(Span::styled(
                    format!("{} {label}", if index == cursor { "›" } else { " " }),
                    if index == cursor {
                        Style::default().fg(Color::Yellow)
                    } else {
                        muted
                    },
                ))),
                Rect {
                    x: area.x,
                    y,
                    width: area.width,
                    height: 1,
                },
            );
            list_row_rects.push(Rect {
                x: area.x,
                y,
                width: area.width,
                height: 1,
            });
            y += 1;
        }
    }

    fn render_status(&self, frame: &mut Frame, area: Rect) {
        let text = match self.bootstrap_state {
            OnboardingBootstrapState::Materializing => {
                Some("Preparing the secure store…".to_string())
            }
            OnboardingBootstrapState::Failed => {
                Some("Onboarding bootstrap failed; retrying ready construction…".to_string())
            }
            _ => None,
        };
        if let Some(text) = text {
            frame.render_widget(
                Paragraph::new(Line::from(Span::styled(
                    text,
                    Style::default().fg(Color::Yellow),
                ))),
                area,
            );
        }
    }

    fn render_help(&self, frame: &mut Frame, area: Rect) {
        let help = match &self.screen {
            OnboardingScreen::Welcome => "any key: begin setup  esc: options",
            OnboardingScreen::SecureStore(screen) => screen.help_text(),
            OnboardingScreen::ProviderSearch(screen) => screen.help_text(),
            OnboardingScreen::Engine(EngineStage::Provider) => {
                "follow the provider wizard  esc: options"
            }
            OnboardingScreen::Engine(_) => "follow the wizard  esc: options",
            OnboardingScreen::Complete { .. } => "↑/↓  enter: choose",
        };
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                help.to_string(),
                Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX)),
            ))),
            area,
        );
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
        let block = Block::default()
            .borders(Borders::ALL)
            .title(" Leave setup? ");
        let inner = block.inner(rect);
        frame.render_widget(block, rect);
        let intro = [
            Line::from("Unsaved entries in this step are discarded."),
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
            frame.render_widget(
                Paragraph::new(Line::from(Span::styled(
                    format!("{} {}", if selected { "▸" } else { " " }, choice.label()),
                    if selected {
                        Style::default()
                            .fg(Color::Yellow)
                            .add_modifier(Modifier::BOLD)
                    } else {
                        Style::default()
                    },
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
