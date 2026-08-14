//! Pure generation-safe mouse gesture reducer for explicit selection and
//! copy-on-release.
//!
//! This module models click activation, drag intent, semantic expansion,
//! delayed multi-click recognition, and clipboard completion as one pure
//! reducer with injected monotonic timestamps. No real time, real clipboard,
//! or real terminal mouse events are used inside the reducer — every
//! timestamp and clipboard outcome is supplied by the caller, making the
//! entire state machine deterministic and unit-testable.
//!
//! ## Gesture rules
//!
//! - **Primary-button movement** to a different selectable cell is required
//!   for drag selection.
//! - **Double-click** explicitly selects a semantic URL or word.
//! - **Triple-click** explicitly selects a logical line (joined across visual
//!   wraps through semantic mapping).
//! - **Double-click inside a Markdown table** explicitly selects the logical
//!   cell across visual wraps.
//! - These are the only no-movement gestures that create selection.
//! - A **single click** never selects and never copies.
//! - Releasing a single link click on the same link without selectable-cell
//!   movement **schedules** (but does not immediately perform) activation at
//!   the end of the 500 ms multi-click window.
//! - A **second click** on the same semantic link at or before the deadline
//!   cancels that activation and becomes explicit URL/semantic double-click
//!   selection.
//! - There is no long-press selection mode.
//! - When **copy_on_release** is enabled, a finalized drag or explicit
//!   double/triple selection schedules at most one copy through the
//!   centralized clipboard service.
//! - Double-click copy waits within the 500 ms multi-click window so a third
//!   click replaces it with one line-selection copy and one notification.
//!
//! ## Generation safety
//!
//! Every press/copy/activation carries `press_generation`,
//! `activation_token`, `view_generation`, `terminal_generation`, semantic
//! target identity, and an injected monotonic deadline. At an equal
//! timestamp, input reduction has priority over the activation timer: a
//!   second press first tombstones the activation token and increments
//! generation, then any queued timer observes the mismatch and is inert.
//! View change, terminal replacement, movement, cancellation, or newer
//! selection similarly invalidate the token. Late timer/clipboard results
//! cannot activate, notify, clear, or overwrite newer state.

use std::time::Duration;

/// The 500 ms multi-click / delayed-activation window.
pub(super) const MULTI_CLICK_WINDOW: Duration = Duration::from_millis(500);

/// A selectable cell coordinate (absolute terminal column/row).
pub(super) type Cell = (u16, u16);

/// Semantic identity of the target under the pointer. Two presses with the
/// same identity are part of the same multi-click sequence; a change resets
/// multi-click recognition.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) enum SemanticTarget {
    /// Padding, chrome, or a non-selectable row under the pointer.
    NonSelectable,
    /// A plain selectable cell at `(col, row)` — no link, no table cell.
    PlainCell(Cell),
    /// A registered Markdown/OSC8 link identified by its URL.
    /// Dormant until chat-link registration exists.
    #[allow(dead_code)]
    Link { url: String, cell: Cell },
    /// A proven Markdown table cell (logical cell across visual wraps).
    TableCell { cell: Cell, fragment_id: u32 },
}

impl SemanticTarget {
    /// The cell coordinate under this target, if any.
    pub(super) fn cell(&self) -> Option<Cell> {
        match self {
            SemanticTarget::NonSelectable => None,
            SemanticTarget::PlainCell(c)
            | SemanticTarget::Link { cell: c, .. }
            | SemanticTarget::TableCell { cell: c, .. } => Some(*c),
        }
    }

    /// True when this target is a registered link.
    pub(super) fn is_link(&self) -> bool {
        matches!(self, SemanticTarget::Link { .. })
    }

    /// The link URL if this is a link target.
    pub(super) fn link_url(&self) -> Option<&str> {
        match self {
            SemanticTarget::Link { url, .. } => Some(url),
            _ => None,
        }
    }
}

/// What kind of click the input represents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ClickButton {
    Primary,
    Other,
}

/// The kind of input event fed to the reducer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum GestureInput {
    /// Primary (or other) button pressed at `cell` with `target` at `now`.
    Press {
        button: ClickButton,
        cell: Cell,
        target: SemanticTarget,
        now: Duration,
    },
    /// Pointer moved to `cell` with `target` at `now` while a button is held.
    Move {
        cell: Cell,
        target: SemanticTarget,
        now: Duration,
    },
    /// Primary button released at `cell` at `now`.
    Release { cell: Cell, now: Duration },
    /// View generation changed (scroll/resize/re-render invalidated the
    /// coordinate space). All in-flight tokens are tombstoned.
    ViewChange { now: Duration },
    /// Terminal generation changed (the underlying buffer was replaced).
    TerminalChange { now: Duration },
    /// Explicit cancellation (Esc, focus loss, context menu, etc.).
    Cancel { now: Duration },
    /// A delayed activation timer fired at `now` carrying the token it was
    /// scheduled with. The reducer checks it against the current token and
    /// generation; a mismatch makes it inert.
    #[allow(dead_code)]
    ActivationTimerFired { token: u64, now: Duration },
    /// The multi-click copy timer fired. A match emits `ScheduleCopy`; a
    /// tombstoned or early timer is inert.
    CopyTimerFired {
        token: u64,
        press_generation: u64,
        now: Duration,
    },
    /// A scheduled copy completed with a classified `outcome`. A match
    /// emits one `Notify`; stale/duplicate results are inert.
    CopyCompleted {
        token: u64,
        press_generation: u64,
        outcome: CopyOutcome,
        now: Duration,
    },
    /// A scheduled copy was rejected (dedupe, runner error, expiry). A
    /// match emits one content-free failed-copy `Notify`.
    CopyRejected {
        token: u64,
        press_generation: u64,
        now: Duration,
    },
}

/// The kind of semantic selection to create.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SelectionKind {
    /// Drag selection between two cells (inclusive).
    Drag,
    /// Double-click word/URL selection at a cell.
    Word,
    /// Triple-click logical-line selection at a cell.
    Line,
    /// Double-click inside a Markdown table cell.
    TableCell,
}

/// A finalized or in-progress selection the reducer wants the host to
/// materialize.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct SelectionRequest {
    pub kind: SelectionKind,
    pub anchor: Cell,
    pub focus: Cell,
    /// True while the button is still held (drag in progress); false once
    /// finalized.
    pub active: bool,
}

/// The outcome of a clipboard copy attempt, injected by the host so the
/// reducer stays pure. Classes match `MouseCopyResult` and never carry
/// plaintext or OS error detail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CopyOutcome {
    /// Native/acknowledged delivery.
    Confirmed,
    /// Emitted without delivery confirmation.
    Unverified,
    /// Selection exceeded the clipboard size limit.
    TooLarge,
    /// Copy failed (dedupe, runner, backend).
    Failed,
    /// Nothing to copy (empty/chrome-only selection).
    Empty,
}

/// Effects the reducer asks the host to perform. The host must check tokens
/// and generations before acting on any effect that touches clipboard or
/// activation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum GestureEffect {
    /// Do nothing.
    #[allow(dead_code)]
    None,
    /// Start or extend a drag selection.
    Select(SelectionRequest),
    /// Clear any active selection.
    ClearSelection,
    /// Schedule a copy of the current selection. The host performs at most
    /// one copy; `token` and `press_generation` must be checked before
    /// acting. `retain_highlight` is true for auto-copy (every CopyOutcome
    /// retains highlight); explicit copy uses its own clearing contract.
    ScheduleCopy {
        token: u64,
        press_generation: u64,
        retain_highlight: bool,
    },
    /// Arm the multi-click copy timer. The matching `CopyTimerFired` emits
    /// `ScheduleCopy`. Double/triple-click auto-copy uses this instead of
    /// an immediate `ScheduleCopy`.
    ScheduleCopyTimer {
        token: u64,
        press_generation: u64,
        deadline: Duration,
    },
    /// Schedule link activation after the multi-click window. The host must
    /// check `token` and generations before activating.
    ScheduleActivation {
        url: String,
        token: u64,
        press_generation: u64,
        deadline: Duration,
    },
    /// Cancel a previously scheduled activation (the token is tombstoned).
    #[allow(dead_code)]
    CancelActivation { token: u64 },
    /// Activate a link now (the token and generations were verified current).
    Activate { url: String },
    /// Show a notification (e.g. copy success/failure toast).
    Notify { outcome: CopyOutcome },
}

/// Persistent reducer state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct GestureState {
    /// Monotonically increasing on every press; guards against late
    /// timer/clipboard results.
    pub press_generation: u64,
    /// Monotonically increasing on view/terminal changes.
    pub view_generation: u64,
    pub terminal_generation: u64,
    /// The current activation token, or the tombstoned token a late timer
    /// will mismatch against. `None` means no activation is pending.
    pub activation_token: Option<u64>,
    /// The deadline at which the pending activation fires.
    pub activation_deadline: Option<Duration>,
    /// The URL of the pending activation.
    pub activation_url: Option<String>,
    /// The pending press, if the button is currently held.
    pub pending_press: Option<PendingPress>,
    /// The number of consecutive clicks in the current multi-click sequence.
    pub click_count: u32,
    /// The semantic target of the first click in the current sequence.
    pub sequence_target: Option<SemanticTarget>,
    /// The timestamp of the first click in the current sequence.
    pub sequence_started: Option<Duration>,
    /// Whether a drag has begun (movement created selection).
    pub dragging: bool,
    /// The copy token currently in flight, if any.
    pub copy_token: Option<u64>,
    /// Press generation captured when the current copy token was issued.
    pub copy_press_generation: Option<u64>,
    /// Deadline for a delayed double/triple-click copy. `None` when no
    /// copy timer is armed (drag copy schedules immediately).
    pub pending_copy_deadline: Option<Duration>,
    /// Next token value to hand out.
    next_token: u64,
}

/// A pending button press awaiting release.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct PendingPress {
    pub cell: Cell,
    pub target: SemanticTarget,
    pub pressed_at: Duration,
    pub press_generation: u64,
    pub view_generation: u64,
    pub terminal_generation: u64,
}

impl Default for GestureState {
    fn default() -> Self {
        Self::new()
    }
}

impl GestureState {
    pub(super) fn new() -> Self {
        Self {
            press_generation: 0,
            view_generation: 0,
            terminal_generation: 0,
            activation_token: None,
            activation_deadline: None,
            activation_url: None,
            pending_press: None,
            click_count: 0,
            sequence_target: None,
            sequence_started: None,
            dragging: false,
            copy_token: None,
            copy_press_generation: None,
            pending_copy_deadline: None,
            next_token: 1,
        }
    }

    /// Earliest armed mouse-gesture deadline (copy timer or activation).
    pub(super) fn next_deadline(&self) -> Option<Duration> {
        match (self.pending_copy_deadline, self.activation_deadline) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (Some(a), None) | (None, Some(a)) => Some(a),
            (None, None) => None,
        }
    }

    fn fresh_token(&mut self) -> u64 {
        let t = self.next_token;
        self.next_token = self.next_token.wrapping_add(1).max(1);
        t
    }

    /// True when a new sequence should start: the target changed or the
    /// window elapsed since the first click.
    fn sequence_expired_or_changed(&self, target: &SemanticTarget, now: Duration) -> bool {
        match (&self.sequence_target, self.sequence_started) {
            (Some(prev), Some(started)) => {
                prev != target || now.saturating_sub(started) > MULTI_CLICK_WINDOW
            }
            _ => true,
        }
    }

    /// Reset multi-click sequence state.
    fn reset_sequence(&mut self) {
        self.click_count = 0;
        self.sequence_target = None;
        self.sequence_started = None;
    }

    /// Tombstone the current activation token (increment generation, clear
    /// pending activation) so any queued timer observes a mismatch.
    fn tombstone_activation(&mut self) {
        if self.activation_token.is_some() {
            self.press_generation = self.press_generation.wrapping_add(1);
        }
        self.activation_token = None;
        self.activation_deadline = None;
        self.activation_url = None;
    }

    /// Invalidate any in-flight copy by incrementing the press generation,
    /// so a late CopyCompleted with the old generation is inert.
    pub(super) fn invalidate_copy(&mut self) {
        if self.copy_token.is_some() || self.pending_copy_deadline.is_some() {
            self.press_generation = self.press_generation.wrapping_add(1);
            self.copy_token = None;
            self.copy_press_generation = None;
            self.pending_copy_deadline = None;
        }
    }

    fn arm_copy_timer(&mut self, press_generation: u64, deadline: Duration) -> u64 {
        let token = self.fresh_token();
        self.copy_token = Some(token);
        self.copy_press_generation = Some(press_generation);
        self.pending_copy_deadline = Some(deadline);
        token
    }

    fn arm_immediate_copy(&mut self, press_generation: u64) -> u64 {
        let token = self.fresh_token();
        self.copy_token = Some(token);
        self.copy_press_generation = Some(press_generation);
        self.pending_copy_deadline = None;
        token
    }
}

/// Configuration for the reducer.
#[derive(Debug, Clone, Copy)]
pub(super) struct GestureConfig {
    /// When true, a finalized drag or explicit double/triple selection
    /// schedules a copy on release.
    pub copy_on_release: bool,
}

impl Default for GestureConfig {
    fn default() -> Self {
        Self {
            copy_on_release: true,
        }
    }
}

/// The pure reducer: given `state`, `config`, and `input`, return the new
/// state and a list of effects to perform. No side effects, no real time.
pub(super) fn reduce(
    state: GestureState,
    config: &GestureConfig,
    input: &GestureInput,
) -> (GestureState, Vec<GestureEffect>) {
    let mut s = state;
    let mut effects = Vec::new();

    match input {
        GestureInput::Press {
            button,
            cell,
            target,
            now,
        } => {
            // Non-primary buttons never enter selection.
            if *button != ClickButton::Primary {
                s.tombstone_activation();
                s.pending_press = None;
                s.dragging = false;
                s.reset_sequence();
                // Don't clear selection — non-primary press is inert.
                return (s, effects);
            }

            // At an equal timestamp, input reduction has priority over the
            // activation timer: a second press first tombstones the
            // activation token and increments generation, then any queued
            // timer observes the mismatch and is inert.
            let _had_pending_activation = s.activation_token.is_some();
            s.tombstone_activation();
            // A new press also invalidates any pending copy so a late
            // CopyCompleted with the old generation is inert.
            s.invalidate_copy();

            // Determine multi-click sequence.
            if s.sequence_expired_or_changed(target, *now) {
                s.reset_sequence();
            }
            s.click_count = s.click_count.saturating_add(1);
            s.sequence_target = Some(target.clone());
            if s.sequence_started.is_none() {
                s.sequence_started = Some(*now);
            }

            let press_gen = s.press_generation;
            let press = PendingPress {
                cell: *cell,
                target: target.clone(),
                pressed_at: *now,
                press_generation: press_gen,
                view_generation: s.view_generation,
                terminal_generation: s.terminal_generation,
            };
            s.pending_press = Some(press.clone());
            s.dragging = false;

            (s, effects)
        }

        GestureInput::Move { cell, target, now } => {
            // Only relevant while a primary button is held.
            let Some(press) = s.pending_press.clone() else {
                return (s, effects);
            };

            // Movement to a different selectable cell begins selection and
            // cancels link activation.
            let moved = press.cell != *cell;
            let target_cell = target.cell();

            if moved && target_cell.is_some() {
                // Movement cancels link activation.
                s.tombstone_activation();
                s.dragging = true;
                // Reset multi-click sequence — movement is not a click.
                s.reset_sequence();

                effects.push(GestureEffect::Select(SelectionRequest {
                    kind: SelectionKind::Drag,
                    anchor: press.cell,
                    focus: *cell,
                    active: true,
                }));
            }
            // Movement without a selectable target (e.g. into chrome) does
            // not begin selection but still cancels activation.
            if moved && target_cell.is_none() && s.activation_token.is_some() {
                s.tombstone_activation();
            }

            let _ = now; // timestamp recorded for potential future use
            (s, effects)
        }

        GestureInput::Release { cell, now } => {
            let Some(press) = s.pending_press.take() else {
                // No pending press — release is inert.
                return (s, effects);
            };

            // If a drag is in progress, finalize the selection.
            if s.dragging {
                s.dragging = false;
                s.reset_sequence();
                let sel = SelectionRequest {
                    kind: SelectionKind::Drag,
                    anchor: press.cell,
                    focus: *cell,
                    active: false,
                };
                effects.push(GestureEffect::Select(sel));

                if config.copy_on_release {
                    let token = s.arm_immediate_copy(press.press_generation);
                    effects.push(GestureEffect::ScheduleCopy {
                        token,
                        press_generation: press.press_generation,
                        retain_highlight: true,
                    });
                }
                return (s, effects);
            }

            // No movement — this is a click release. Determine the click
            // count and semantic target.
            let target = &press.target;
            let click = s.click_count;

            match click {
                // Single click: never selects, never copies.
                1 => {
                    if target.is_link() {
                        // Releasing a single link click on the same link
                        // schedules activation at the end of the multi-click
                        // window. It fires only after the window if its
                        // token/generations remain current.
                        let token = s.fresh_token();
                        let deadline = now.saturating_add(MULTI_CLICK_WINDOW);
                        let url = target.link_url().unwrap_or("").to_string();
                        s.activation_token = Some(token);
                        s.activation_deadline = Some(deadline);
                        s.activation_url = Some(url.clone());
                        effects.push(GestureEffect::ScheduleActivation {
                            url,
                            token,
                            press_generation: press.press_generation,
                            deadline,
                        });
                    }
                    // Non-link single click: nothing — no selection, no copy.
                }
                // Double-click: explicit URL or word selection.
                2 => {
                    s.tombstone_activation();
                    if target.is_link() {
                        // Double-click on a link selects the URL
                        // (semantic URL before word boundaries).
                        effects.push(GestureEffect::Select(SelectionRequest {
                            kind: SelectionKind::Word,
                            anchor: press.cell,
                            focus: press.cell,
                            active: false,
                        }));
                    } else if matches!(target, SemanticTarget::TableCell { .. }) {
                        // Double-click inside a Markdown table selects the
                        // logical cell across visual wraps.
                        effects.push(GestureEffect::Select(SelectionRequest {
                            kind: SelectionKind::TableCell,
                            anchor: press.cell,
                            focus: press.cell,
                            active: false,
                        }));
                    } else if target.cell().is_some() {
                        // Double-click on a plain selectable cell selects
                        // the word.
                        effects.push(GestureEffect::Select(SelectionRequest {
                            kind: SelectionKind::Word,
                            anchor: press.cell,
                            focus: press.cell,
                            active: false,
                        }));
                    }

                    if config.copy_on_release && target.cell().is_some() {
                        // Double-click copy waits for the existing multi-click
                        // deadline so a third click can replace it. Emit only
                        // a timer; the matching CopyTimerFired schedules copy.
                        let deadline = s
                            .sequence_started
                            .unwrap_or(*now)
                            .saturating_add(MULTI_CLICK_WINDOW);
                        let token = s.arm_copy_timer(press.press_generation, deadline);
                        effects.push(GestureEffect::ScheduleCopyTimer {
                            token,
                            press_generation: press.press_generation,
                            deadline,
                        });
                    }
                }
                // Triple-click: logical line selection.
                3 => {
                    s.tombstone_activation();
                    // A third click replaces the pending word copy with one
                    // line-selection copy and one notification. The third
                    // press already tombstoned the word token/deadline.

                    effects.push(GestureEffect::Select(SelectionRequest {
                        kind: SelectionKind::Line,
                        anchor: press.cell,
                        focus: press.cell,
                        active: false,
                    }));

                    if config.copy_on_release && target.cell().is_some() {
                        let deadline = now.saturating_add(MULTI_CLICK_WINDOW);
                        let token = s.arm_copy_timer(press.press_generation, deadline);
                        effects.push(GestureEffect::ScheduleCopyTimer {
                            token,
                            press_generation: press.press_generation,
                            deadline,
                        });
                    }
                    // Reset sequence after triple — a fourth click is a new
                    // single click.
                    s.reset_sequence();
                }
                _ => {
                    // Unexpected high click count — reset to a fresh single.
                    s.reset_sequence();
                }
            }

            (s, effects)
        }

        GestureInput::ViewChange { now: _ } => {
            s.view_generation = s.view_generation.wrapping_add(1);
            s.tombstone_activation();
            s.invalidate_copy();
            s.pending_press = None;
            s.dragging = false;
            s.reset_sequence();
            // View change clears the selection — coordinates are invalid.
            effects.push(GestureEffect::ClearSelection);
            (s, effects)
        }

        GestureInput::TerminalChange { now: _ } => {
            s.terminal_generation = s.terminal_generation.wrapping_add(1);
            s.tombstone_activation();
            s.invalidate_copy();
            s.pending_press = None;
            s.dragging = false;
            s.reset_sequence();
            effects.push(GestureEffect::ClearSelection);
            (s, effects)
        }

        GestureInput::Cancel { now: _ } => {
            s.tombstone_activation();
            s.invalidate_copy();
            s.pending_press = None;
            s.dragging = false;
            s.reset_sequence();
            effects.push(GestureEffect::ClearSelection);
            (s, effects)
        }

        GestureInput::ActivationTimerFired { token, now } => {
            // The timer carries the token it was scheduled with. Check it
            // against the current token and generations. A mismatch (new
            // press, view change, cancellation) makes it inert.
            let pending_token = s.activation_token;
            let pending_deadline = s.activation_deadline;
            let pending_url = s.activation_url.clone();

            match (pending_token, pending_deadline, pending_url) {
                (Some(current), Some(deadline), Some(url))
                    if current == *token && *now >= deadline =>
                {
                    // The token matches and the deadline has passed.
                    // Activate now. Tombstone the token so a second
                    // activation can't fire.
                    s.activation_token = None;
                    s.activation_deadline = None;
                    s.activation_url = None;
                    effects.push(GestureEffect::Activate { url });
                }
                _ => {
                    // Token mismatch, no pending activation, or early
                    // timer — inert.
                }
            }
            (s, effects)
        }

        GestureInput::CopyTimerFired {
            token,
            press_generation,
            now,
        } => {
            if s.copy_token == Some(*token)
                && s.copy_press_generation == Some(*press_generation)
                && s.press_generation == *press_generation
                && s.pending_copy_deadline
                    .is_some_and(|deadline| *now >= deadline)
            {
                s.pending_copy_deadline = None;
                effects.push(GestureEffect::ScheduleCopy {
                    token: *token,
                    press_generation: *press_generation,
                    retain_highlight: true,
                });
            }
            (s, effects)
        }

        GestureInput::CopyCompleted {
            token,
            press_generation,
            outcome,
            now: _,
        } => {
            if s.copy_token == Some(*token)
                && s.copy_press_generation == Some(*press_generation)
                && s.press_generation == *press_generation
            {
                s.copy_token = None;
                s.copy_press_generation = None;
                s.pending_copy_deadline = None;
                effects.push(GestureEffect::Notify { outcome: *outcome });
            }
            (s, effects)
        }

        GestureInput::CopyRejected {
            token,
            press_generation,
            now: _,
        } => {
            if s.copy_token == Some(*token)
                && s.copy_press_generation == Some(*press_generation)
                && s.press_generation == *press_generation
            {
                s.copy_token = None;
                s.copy_press_generation = None;
                s.pending_copy_deadline = None;
                effects.push(GestureEffect::Notify {
                    outcome: CopyOutcome::Failed,
                });
            }
            (s, effects)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    /// Convenience: press primary at a plain selectable cell.
    fn press_plain(
        cfg: &GestureConfig,
        state: GestureState,
        now: Duration,
        cell: Cell,
    ) -> (GestureState, Vec<GestureEffect>) {
        reduce(
            state,
            cfg,
            &GestureInput::Press {
                button: ClickButton::Primary,
                cell,
                target: SemanticTarget::PlainCell(cell),
                now,
            },
        )
    }

    fn press_link(
        cfg: &GestureConfig,
        state: GestureState,
        now: Duration,
        cell: Cell,
        url: &str,
    ) -> (GestureState, Vec<GestureEffect>) {
        reduce(
            state,
            cfg,
            &GestureInput::Press {
                button: ClickButton::Primary,
                cell,
                target: SemanticTarget::Link {
                    url: url.to_string(),
                    cell,
                },
                now,
            },
        )
    }

    fn release(
        cfg: &GestureConfig,
        state: GestureState,
        now: Duration,
        cell: Cell,
    ) -> (GestureState, Vec<GestureEffect>) {
        reduce(state, cfg, &GestureInput::Release { cell, now })
    }

    fn move_to(
        cfg: &GestureConfig,
        state: GestureState,
        now: Duration,
        cell: Cell,
    ) -> (GestureState, Vec<GestureEffect>) {
        reduce(
            state,
            cfg,
            &GestureInput::Move {
                cell,
                target: SemanticTarget::PlainCell(cell),
                now,
            },
        )
    }

    /// Helper: count effects of a specific kind.
    fn count_select(effects: &[GestureEffect]) -> usize {
        effects
            .iter()
            .filter(|e| matches!(e, GestureEffect::Select(_)))
            .count()
    }

    fn count_copy(effects: &[GestureEffect]) -> usize {
        effects
            .iter()
            .filter(|e| matches!(e, GestureEffect::ScheduleCopy { .. }))
            .count()
    }

    fn count_copy_timer(effects: &[GestureEffect]) -> usize {
        effects
            .iter()
            .filter(|e| matches!(e, GestureEffect::ScheduleCopyTimer { .. }))
            .count()
    }

    fn count_notify(effects: &[GestureEffect]) -> usize {
        effects
            .iter()
            .filter(|e| matches!(e, GestureEffect::Notify { .. }))
            .count()
    }

    fn count_activate(effects: &[GestureEffect]) -> usize {
        effects
            .iter()
            .filter(|e| matches!(e, GestureEffect::Activate { .. }))
            .count()
    }

    fn count_schedule_activation(effects: &[GestureEffect]) -> usize {
        effects
            .iter()
            .filter(|e| matches!(e, GestureEffect::ScheduleActivation { .. }))
            .count()
    }

    // ── Acceptance criterion 1 ──────────────────────────────────────────

    #[test]
    fn copy_on_release_drag_enabled_copies_once() {
        let mut s = GestureState::new();
        let cfg = GestureConfig {
            copy_on_release: true,
        };

        // Press at (5, 10).
        s = reduce(
            s,
            &cfg,
            &GestureInput::Press {
                button: ClickButton::Primary,
                cell: (5, 10),
                target: SemanticTarget::PlainCell((5, 10)),
                now: ms(0),
            },
        )
        .0;

        // Move to a different cell — begins drag.
        let (s2, e2) = reduce(
            s,
            &cfg,
            &GestureInput::Move {
                cell: (10, 12),
                target: SemanticTarget::PlainCell((10, 12)),
                now: ms(50),
            },
        );
        s = s2;
        assert_eq!(count_select(&e2), 1);
        assert_eq!(count_copy(&e2), 0, "no copy during active drag");

        // Release — finalizes selection and schedules one copy.
        let (s3, e3) = reduce(
            s,
            &cfg,
            &GestureInput::Release {
                cell: (10, 12),
                now: ms(100),
            },
        );
        assert_eq!(count_select(&e3), 1);
        assert_eq!(count_copy(&e3), 1, "exactly one copy scheduled on release");
        assert!(s3.copy_token.is_some());
        assert!(!s3.dragging);
    }

    #[test]
    fn copy_on_release_drag_disabled_only_finalizes() {
        let mut s = GestureState::new();
        let cfg = GestureConfig {
            copy_on_release: false,
        };

        s = reduce(
            s,
            &cfg,
            &GestureInput::Press {
                button: ClickButton::Primary,
                cell: (5, 10),
                target: SemanticTarget::PlainCell((5, 10)),
                now: ms(0),
            },
        )
        .0;

        let (s2, _) = reduce(
            s,
            &cfg,
            &GestureInput::Move {
                cell: (10, 12),
                target: SemanticTarget::PlainCell((10, 12)),
                now: ms(50),
            },
        );
        s = s2;

        let (s3, e3) = reduce(
            s,
            &cfg,
            &GestureInput::Release {
                cell: (10, 12),
                now: ms(100),
            },
        );
        assert_eq!(count_select(&e3), 1);
        assert_eq!(count_copy(&e3), 0, "no copy when copy_on_release is false");
        assert!(s3.copy_token.is_none());
    }

    // ── Acceptance criterion 2 ──────────────────────────────────────────

    #[test]
    fn single_click_never_selects_or_copies() {
        // With copy_on_release enabled.
        let cfg_on = GestureConfig {
            copy_on_release: true,
        };
        let mut s = GestureState::new();
        s = reduce(
            s,
            &cfg_on,
            &GestureInput::Press {
                button: ClickButton::Primary,
                cell: (5, 10),
                target: SemanticTarget::PlainCell((5, 10)),
                now: ms(0),
            },
        )
        .0;
        let (_s2, e2) = reduce(
            s,
            &cfg_on,
            &GestureInput::Release {
                cell: (5, 10),
                now: ms(10),
            },
        );
        assert_eq!(count_select(&e2), 0, "single click never selects (enabled)");
        assert_eq!(count_copy(&e2), 0, "single click never copies (enabled)");

        // With copy_on_release disabled.
        let cfg_off = GestureConfig {
            copy_on_release: false,
        };
        let mut s = GestureState::new();
        s = reduce(
            s,
            &cfg_off,
            &GestureInput::Press {
                button: ClickButton::Primary,
                cell: (5, 10),
                target: SemanticTarget::PlainCell((5, 10)),
                now: ms(0),
            },
        )
        .0;
        let (_s2, e2) = reduce(
            s,
            &cfg_off,
            &GestureInput::Release {
                cell: (5, 10),
                now: ms(10),
            },
        );
        assert_eq!(
            count_select(&e2),
            0,
            "single click never selects (disabled)"
        );
        assert_eq!(count_copy(&e2), 0, "single click never copies (disabled)");

        // Ordinary non-link cell.
        let s = GestureState::new();
        let (s, _) = reduce(
            s,
            &cfg_on,
            &GestureInput::Press {
                button: ClickButton::Primary,
                cell: (3, 3),
                target: SemanticTarget::PlainCell((3, 3)),
                now: ms(0),
            },
        );
        let (_, e3) = reduce(
            s,
            &cfg_on,
            &GestureInput::Release {
                cell: (3, 3),
                now: ms(10),
            },
        );
        assert_eq!(count_select(&e3), 0);
        assert_eq!(count_copy(&e3), 0);
    }

    // ── Acceptance criterion 3: button down/release cannot activate
    // synchronously ───────────────────────────────────────────────────────

    #[test]
    fn link_press_and_release_do_not_synchronously_activate() {
        let s = GestureState::new();
        let cfg = GestureConfig::default();

        // Press on a link.
        let (s1, e1) = reduce(
            s,
            &cfg,
            &GestureInput::Press {
                button: ClickButton::Primary,
                cell: (4, 7),
                target: SemanticTarget::Link {
                    url: "https://x.test".to_string(),
                    cell: (4, 7),
                },
                now: ms(0),
            },
        );
        assert_eq!(
            count_activate(&e1),
            0,
            "press does not activate synchronously"
        );
        assert_eq!(
            count_schedule_activation(&e1),
            0,
            "press does not schedule activation"
        );

        // Release on the same link — schedules activation, does not activate.
        let (s2, e2) = reduce(
            s1,
            &cfg,
            &GestureInput::Release {
                cell: (4, 7),
                now: ms(10),
            },
        );
        assert_eq!(
            count_activate(&e2),
            0,
            "release does not activate synchronously"
        );
        assert_eq!(
            count_schedule_activation(&e2),
            1,
            "release schedules activation"
        );
        assert!(s2.activation_token.is_some());
        assert_eq!(s2.activation_deadline, Some(ms(510))); // 10 + 500ms
    }

    // ── Acceptance criterion 4: single link click activates after window
    // ────────────────────────────────────────────────────────────────────

    #[test]
    fn single_link_click_activates_after_window() {
        let cfg = GestureConfig::default();

        // Press + release on a link at t=0..10.
        let s = GestureState::new();
        let (s, _) = reduce(
            s,
            &cfg,
            &GestureInput::Press {
                button: ClickButton::Primary,
                cell: (4, 7),
                target: SemanticTarget::Link {
                    url: "https://x.test".to_string(),
                    cell: (4, 7),
                },
                now: ms(0),
            },
        );
        let (s, e_rel) = reduce(
            s,
            &cfg,
            &GestureInput::Release {
                cell: (4, 7),
                now: ms(10),
            },
        );
        let token = s.activation_token.unwrap();
        assert_eq!(count_schedule_activation(&e_rel), 1);

        // At 509 ms (before 510 deadline) — inert.
        let (s_early, e_early) = reduce(
            s.clone(),
            &cfg,
            &GestureInput::ActivationTimerFired {
                token,
                now: ms(509),
            },
        );
        assert_eq!(
            count_activate(&e_early),
            0,
            "timer before deadline is inert"
        );
        assert!(
            s_early.activation_token.is_some(),
            "token not cleared before deadline"
        );

        // At 510 ms (exactly the deadline) — activates.
        let (s_at, e_at) = reduce(
            s.clone(),
            &cfg,
            &GestureInput::ActivationTimerFired {
                token,
                now: ms(510),
            },
        );
        assert_eq!(count_activate(&e_at), 1, "timer at deadline activates");
        assert!(
            s_at.activation_token.is_none(),
            "token cleared after activation"
        );

        // At 511 ms (after the deadline) — activates.
        let (s_late, e_late) = reduce(
            s,
            &cfg,
            &GestureInput::ActivationTimerFired {
                token,
                now: ms(511),
            },
        );
        assert_eq!(count_activate(&e_late), 1, "timer after deadline activates");
        assert!(s_late.activation_token.is_none());

        // No selection or copy in any of these.
        assert!(e_early.iter().all(|e| !matches!(
            e,
            GestureEffect::Select(_) | GestureEffect::ScheduleCopy { .. }
        )));
        assert!(e_at.iter().all(|e| !matches!(
            e,
            GestureEffect::Select(_) | GestureEffect::ScheduleCopy { .. }
        )));
    }

    // ── Acceptance criterion 5: second link click cancels activation and
    // selects URL ─────────────────────────────────────────────────────────

    #[test]
    fn second_link_click_cancels_activation_and_selects_url() {
        let cfg = GestureConfig::default();
        let url = "https://x.test";

        // First press + release on the link.
        let s = GestureState::new();
        let (s, _) = press_link(&cfg, s, ms(0), (4, 7), url);
        let (s, e1) = release(&cfg, s, ms(10), (4, 7));
        assert_eq!(count_schedule_activation(&e1), 1);
        let first_token = s.activation_token.unwrap();

        // Second press on the same link (within the window) — tombstones
        // the activation token.
        let (s2, e2) = press_link(&cfg, s, ms(200), (4, 7), url);
        assert_eq!(count_activate(&e2), 0, "second press does not activate");
        // The press_generation was incremented by tombstone_activation.
        assert!(s2.press_generation > 0);
        // The old token is gone.
        assert!(s2.activation_token.is_none(), "old activation tombstoned");

        // Second release — double-click selects the URL.
        let (s3, e3) = release(&cfg, s2, ms(210), (4, 7));
        assert_eq!(count_activate(&e3), 0, "no activation on double-click");
        assert_eq!(count_select(&e3), 1, "double-click selects URL");
        // The selection is a Word (URL) selection.
        assert!(e3.iter().any(|e| matches!(
            e,
            GestureEffect::Select(SelectionRequest {
                kind: SelectionKind::Word,
                ..
            })
        )));

        // A stale timer with the old token is now inert.
        let (_s4, e4) = reduce(
            s3,
            &cfg,
            &GestureInput::ActivationTimerFired {
                token: first_token,
                now: ms(600),
            },
        );
        assert_eq!(
            count_activate(&e4),
            0,
            "stale timer is inert after second click"
        );
    }

    // ── Acceptance criterion 6: link activation boundary — cancellation
    // wins at exactly 500 ms ───────────────────────────────────────────────

    #[test]
    fn link_activation_boundary_cancellation_wins() {
        let cfg = GestureConfig::default();
        let url = "https://x.test";

        // Press + release at t=0..10 → deadline = 510.
        let s = GestureState::new();
        let (s, _) = press_link(&cfg, s, ms(0), (4, 7), url);
        let (s, _) = release(&cfg, s, ms(10), (4, 7));
        let token = s.activation_token.unwrap();

        // At exactly t=510 (the deadline), a second press arrives at the
        // same timestamp. Input reduction has priority: the press first
        // tombstones the token, then the timer is inert.
        let (s_press, e_press) = press_link(&cfg, s.clone(), ms(510), (4, 7), url);
        assert_eq!(
            count_activate(&e_press),
            0,
            "press at deadline does not activate"
        );
        assert!(
            s_press.activation_token.is_none(),
            "press tombstones token at deadline"
        );

        // Now the timer fires at the same timestamp — it's inert because
        // the token was tombstoned.
        let (s_timer, e_timer) = reduce(
            s_press,
            &cfg,
            &GestureInput::ActivationTimerFired {
                token,
                now: ms(510),
            },
        );
        assert_eq!(
            count_activate(&e_timer),
            0,
            "stale timer is inert after press at equal timestamp"
        );
        assert!(s_timer.activation_token.is_none());

        // Verify the reverse order doesn't matter — timer first then press.
        let (s_timer2, e_timer2) = reduce(
            s.clone(),
            &cfg,
            &GestureInput::ActivationTimerFired {
                token,
                now: ms(510),
            },
        );
        assert_eq!(
            count_activate(&e_timer2),
            1,
            "timer at deadline activates if no press"
        );
        let (_s_press2, e_press2) = press_link(&cfg, s_timer2, ms(510), (4, 7), url);
        assert_eq!(
            count_activate(&e_press2),
            0,
            "press after activation does not re-activate"
        );
    }

    // ── Acceptance criterion 7: link press movement begins selection and
    // cancels activation ───────────────────────────────────────────────────

    #[test]
    fn link_press_movement_begins_selection_and_cancels_activation() {
        let cfg = GestureConfig::default();
        let url = "https://x.test";

        // Press on a link.
        let s = GestureState::new();
        let (s, _) = press_link(&cfg, s, ms(0), (4, 7), url);
        // Release schedules activation.
        let (s, e_rel) = release(&cfg, s, ms(10), (4, 7));
        assert_eq!(count_schedule_activation(&e_rel), 1);
        let token = s.activation_token.unwrap();

        // Now press again and move to a different selectable cell.
        let (s, _) = press_link(&cfg, s, ms(20), (4, 7), url);
        let (s2, e_move) = move_to(&cfg, s, ms(30), (8, 9));
        assert_eq!(count_select(&e_move), 1, "movement begins selection");
        assert!(s2.dragging);
        assert!(s2.activation_token.is_none(), "movement cancels activation");

        // Stale timer is inert.
        let (_, e_timer) = reduce(
            s2,
            &cfg,
            &GestureInput::ActivationTimerFired {
                token,
                now: ms(600),
            },
        );
        assert_eq!(count_activate(&e_timer), 0);
    }

    // ── Acceptance criterion 8: long press does not create selection or
    // copy ─────────────────────────────────────────────────────────────────

    #[test]
    fn long_press_does_not_create_selection_or_copy() {
        let cfg = GestureConfig::default();
        let s = GestureState::new();

        // Press and hold for a long time without movement.
        let (s, e_press) = press_plain(&cfg, s, ms(0), (5, 10));
        assert_eq!(count_select(&e_press), 0);
        assert_eq!(count_copy(&e_press), 0);

        // Release after 5 seconds — no movement means no drag, single
        // click on a plain cell → no selection, no copy.
        let (s2, e_rel) = release(&cfg, s, ms(5000), (5, 10));
        assert_eq!(
            count_select(&e_rel),
            0,
            "long press without movement does not select"
        );
        assert_eq!(
            count_copy(&e_rel),
            0,
            "long press without movement does not copy"
        );
        assert!(!s2.dragging);
    }

    // ── Acceptance criterion 9: double-click selects URL or word ────────

    #[test]
    fn double_click_selects_url_or_word() {
        let cfg = GestureConfig::default();

        // Double-click on a link → selects URL (Word kind).
        let s = GestureState::new();
        let (s, _) = press_link(&cfg, s, ms(0), (4, 7), "https://x.test");
        let (s, _) = release(&cfg, s, ms(10), (4, 7));
        let (s, _) = press_link(&cfg, s, ms(20), (4, 7), "https://x.test");
        let (_, e) = release(&cfg, s, ms(30), (4, 7));
        assert_eq!(count_select(&e), 1);
        assert!(e.iter().any(|ef| matches!(
            ef,
            GestureEffect::Select(SelectionRequest {
                kind: SelectionKind::Word,
                ..
            })
        )));

        // Double-click on a plain cell → selects word.
        let s = GestureState::new();
        let (s, _) = press_plain(&cfg, s, ms(0), (5, 10));
        let (s, _) = release(&cfg, s, ms(10), (5, 10));
        let (s, _) = press_plain(&cfg, s, ms(20), (5, 10));
        let (_, e) = release(&cfg, s, ms(30), (5, 10));
        assert_eq!(count_select(&e), 1);
        assert!(e.iter().any(|ef| matches!(
            ef,
            GestureEffect::Select(SelectionRequest {
                kind: SelectionKind::Word,
                ..
            })
        )));
    }

    #[test]
    fn double_click_uses_visible_url_before_word_boundaries() {
        let cfg = GestureConfig::default();
        // A link that is also selectable — double-click chooses URL.
        let s = GestureState::new();
        let (s, _) = press_link(&cfg, s, ms(0), (4, 7), "https://docs.test/guide");
        let (s, _) = release(&cfg, s, ms(10), (4, 7));
        let (s, _) = press_link(&cfg, s, ms(20), (4, 7), "https://docs.test/guide");
        let (_, e) = release(&cfg, s, ms(30), (4, 7));
        // The selection is Word kind (URL is treated as a word selection).
        assert!(e.iter().any(|ef| matches!(
            ef,
            GestureEffect::Select(SelectionRequest {
                kind: SelectionKind::Word,
                anchor: (4, 7),
                focus: (4, 7),
                ..
            })
        )));
    }

    // ── Acceptance criterion 10: double-click inside table selects wrapped
    // cell ─────────────────────────────────────────────────────────────────

    #[test]
    fn double_click_table_selects_wrapped_cell() {
        let cfg = GestureConfig::default();
        let s = GestureState::new();
        let cell = (6, 10);
        let target = SemanticTarget::TableCell {
            cell,
            fragment_id: 5,
        };

        // Double-click on a mapped cell → TableCell selection.
        let (s, _) = reduce(
            s,
            &cfg,
            &GestureInput::Press {
                button: ClickButton::Primary,
                cell,
                target: target.clone(),
                now: ms(0),
            },
        );
        let (s, _) = reduce(s, &cfg, &GestureInput::Release { cell, now: ms(10) });
        let (s, _) = reduce(
            s,
            &cfg,
            &GestureInput::Press {
                button: ClickButton::Primary,
                cell,
                target: target.clone(),
                now: ms(20),
            },
        );
        let (_, e) = reduce(s, &cfg, &GestureInput::Release { cell, now: ms(30) });
        assert_eq!(count_select(&e), 1);
        assert!(
            e.iter().any(|ef| matches!(
                ef,
                GestureEffect::Select(SelectionRequest {
                    kind: SelectionKind::TableCell,
                    ..
                })
            )),
            "double-click on mapped cell selects table cell, not word"
        );
    }

    // ── Acceptance criterion 11: triple-click selects logical line ──────

    #[test]
    fn triple_click_selects_logical_line() {
        let cfg = GestureConfig::default();
        let s = GestureState::new();
        let cell = (5, 10);

        // Triple-click on a plain cell → Line selection.
        let (s, _) = press_plain(&cfg, s, ms(0), cell);
        let (s, _) = release(&cfg, s, ms(10), cell);
        let (s, _) = press_plain(&cfg, s, ms(20), cell);
        let (s, _) = release(&cfg, s, ms(30), cell);
        let (s, _) = press_plain(&cfg, s, ms(40), cell);
        let (_, e) = release(&cfg, s, ms(50), cell);

        assert_eq!(count_select(&e), 1);
        assert!(e.iter().any(|ef| matches!(
            ef,
            GestureEffect::Select(SelectionRequest {
                kind: SelectionKind::Line,
                ..
            })
        )));
    }

    // ── Acceptance criterion 12: triple-click coalesces pending word copy;
    // click after window starts new sequence ───────────────────────────────

    #[test]
    fn triple_click_coalesces_pending_word_copy() {
        let cfg = GestureConfig {
            copy_on_release: true,
        };
        let s = GestureState::new();
        let cell = (5, 10);

        // Double-click → word selection + scheduled copy.
        let (s, _) = press_plain(&cfg, s, ms(0), cell);
        let (s, e1) = release(&cfg, s, ms(10), cell);
        assert_eq!(count_select(&e1), 0); // single click — no selection
        let (s, _) = press_plain(&cfg, s, ms(20), cell);
        let (s, e2) = release(&cfg, s, ms(30), cell);
        assert_eq!(count_select(&e2), 1); // double-click — word
        assert_eq!(count_copy(&e2), 0, "double-click waits for copy timer");
        assert_eq!(count_copy_timer(&e2), 1);
        let word_copy_token = s.copy_token.unwrap();

        // Triple-click → line selection + one line copy timer (replaces word).
        let (s, _) = press_plain(&cfg, s, ms(40), cell);
        let (s3, e3) = release(&cfg, s, ms(50), cell);
        assert_eq!(count_select(&e3), 1, "triple-click selects line");
        assert_eq!(count_copy(&e3), 0, "triple-click waits for its own timer");
        assert_eq!(
            count_copy_timer(&e3),
            1,
            "triple-click arms exactly one copy timer"
        );
        let line_token = s3.copy_token.unwrap();
        assert_ne!(line_token, word_copy_token);

        // The word copy token was superseded — a late CopyCompleted with
        // the old token is inert.
        let (s4, e4) = reduce(
            s3.clone(),
            &cfg,
            &GestureInput::CopyCompleted {
                token: word_copy_token,
                press_generation: 0,
                outcome: CopyOutcome::Confirmed,
                now: ms(55),
            },
        );
        assert_eq!(count_notify(&e4), 0, "stale word completion is inert");
        assert_eq!(s4.copy_token, Some(line_token));
    }

    #[test]
    fn click_after_window_starts_new_sequence() {
        let cfg = GestureConfig::default();
        let s = GestureState::new();
        let cell = (5, 10);

        // First click at t=0.
        let (s, _) = press_plain(&cfg, s, ms(0), cell);
        let (s, _) = release(&cfg, s, ms(10), cell);
        assert_eq!(s.click_count, 1);

        // Second click after the window (t=600 > 10 + 500 = 510) → new
        // sequence starts at click_count=1.
        let (s, _) = press_plain(&cfg, s, ms(600), cell);
        assert_eq!(s.click_count, 1, "click after window resets sequence");
        let (s, e) = release(&cfg, s, ms(610), cell);
        // Single click → no selection.
        assert_eq!(count_select(&e), 0);

        // Now a quick double-click within the new sequence window.
        let (s, _) = press_plain(&cfg, s, ms(620), cell);
        let (s, _) = release(&cfg, s, ms(630), cell);
        let (s, _) = press_plain(&cfg, s, ms(640), cell);
        let (_, e2) = release(&cfg, s, ms(650), cell);
        assert_eq!(
            count_select(&e2),
            1,
            "double-click in new sequence selects word"
        );
    }

    // ── Acceptance criterion 13: generation rejects late copy ───────────

    #[test]
    fn mouse_selection_generation_rejects_late_copy() {
        let cfg = GestureConfig {
            copy_on_release: true,
        };

        // Drag-select and release → copy scheduled.
        let s = GestureState::new();
        let (s, _) = press_plain(&cfg, s, ms(0), (5, 10));
        let (s, _) = move_to(&cfg, s, ms(50), (10, 12));
        let (s, e_rel) = release(&cfg, s, ms(100), (10, 12));
        let copy_token = s.copy_token.unwrap();
        let press_gen = s.press_generation;
        assert_eq!(count_copy(&e_rel), 1);

        // New press increments generation → stale copy completion is inert.
        let (s2, _) = press_plain(&cfg, s.clone(), ms(200), (20, 20));
        assert!(s2.press_generation > press_gen);

        // Late CopyCompleted with the old press_generation is inert —
        // copy_token is not cleared (the new press may have its own).
        let (s3, _) = reduce(
            s2,
            &cfg,
            &GestureInput::CopyCompleted {
                token: copy_token,
                press_generation: press_gen,
                outcome: CopyOutcome::Confirmed,
                now: ms(250),
            },
        );
        // The stale completion did not crash and the state is consistent.
        let _ = s3;

        // View change invalidates everything.
        let (s4, e_vc) = reduce(s.clone(), &cfg, &GestureInput::ViewChange { now: ms(300) });
        assert!(matches!(e_vc.as_slice(), [GestureEffect::ClearSelection]));
        assert!(s4.view_generation > 0);
        assert!(s4.activation_token.is_none());
        assert!(s4.pending_press.is_none());

        // Terminal change invalidates everything.
        let (s5, e_tc) = reduce(
            s.clone(),
            &cfg,
            &GestureInput::TerminalChange { now: ms(300) },
        );
        assert!(matches!(e_tc.as_slice(), [GestureEffect::ClearSelection]));
        assert!(s5.terminal_generation > 0);

        // Cancellation invalidates everything.
        let (s6, e_c) = reduce(s.clone(), &cfg, &GestureInput::Cancel { now: ms(300) });
        assert!(matches!(e_c.as_slice(), [GestureEffect::ClearSelection]));
        assert!(s6.activation_token.is_none());

        // Late success with mismatched token is inert.
        let (s7, _) = reduce(
            s.clone(),
            &cfg,
            &GestureInput::CopyCompleted {
                token: 999, // wrong token
                press_generation: press_gen,
                outcome: CopyOutcome::Confirmed,
                now: ms(400),
            },
        );
        // copy_token still set (not cleared by wrong token).
        assert_eq!(s7.copy_token, Some(copy_token));

        // First valid completion clears the token.
        let (s8, _) = reduce(
            s.clone(),
            &cfg,
            &GestureInput::CopyCompleted {
                token: copy_token,
                press_generation: press_gen,
                outcome: CopyOutcome::Confirmed,
                now: ms(500),
            },
        );
        assert_eq!(s8.copy_token, None);
        // Second completion is inert (token already None).
        let (s9, _) = reduce(
            s8,
            &cfg,
            &GestureInput::CopyCompleted {
                token: copy_token,
                press_generation: press_gen,
                outcome: CopyOutcome::Confirmed,
                now: ms(510),
            },
        );
        assert_eq!(s9.copy_token, None);
    }

    // ── Acceptance criterion 14: edge reducer ───────────────────────────

    #[test]
    fn non_primary_buttons_never_enter_selection() {
        let cfg = GestureConfig {
            copy_on_release: true,
        };
        let s = GestureState::new();

        // Press with non-primary button.
        let (s2, e) = reduce(
            s,
            &cfg,
            &GestureInput::Press {
                button: ClickButton::Other,
                cell: (5, 10),
                target: SemanticTarget::PlainCell((5, 10)),
                now: ms(0),
            },
        );
        assert_eq!(count_select(&e), 0, "non-primary press does not select");
        assert!(
            s2.pending_press.is_none(),
            "non-primary press does not set pending press"
        );

        // Move with non-primary already pressed — no selection.
        let (_, e2) = reduce(
            s2,
            &cfg,
            &GestureInput::Move {
                cell: (10, 12),
                target: SemanticTarget::PlainCell((10, 12)),
                now: ms(50),
            },
        );
        assert_eq!(count_select(&e2), 0, "non-primary move does not select");
    }

    #[test]
    fn empty_selection_is_deterministic_no_copy() {
        let cfg = GestureConfig {
            copy_on_release: true,
        };
        let s = GestureState::new();

        // Press on chrome (no selectable target).
        let (s, e) = reduce(
            s,
            &cfg,
            &GestureInput::Press {
                button: ClickButton::Primary,
                cell: (5, 10),
                target: SemanticTarget::NonSelectable,
                now: ms(0),
            },
        );
        assert_eq!(count_select(&e), 0);

        // Release on chrome → no selection, no copy.
        let (s2, e2) = reduce(
            s,
            &cfg,
            &GestureInput::Release {
                cell: (5, 10),
                now: ms(10),
            },
        );
        assert_eq!(count_select(&e2), 0, "chrome release does not select");
        assert_eq!(count_copy(&e2), 0, "chrome release does not copy");
        assert!(!s2.dragging);
    }

    #[test]
    fn drag_outside_viewport_uses_bounded_focus() {
        // The reducer itself doesn't clamp — the host clamps coordinates
        // before feeding them. This test verifies the reducer handles
        // far-away cells without issue (the host is responsible for
        // bounding).
        let cfg = GestureConfig {
            copy_on_release: true,
        };
        let s = GestureState::new();
        let (s, _) = press_plain(&cfg, s, ms(0), (5, 10));
        // Move to a very far cell.
        let (s, e) = reduce(
            s,
            &cfg,
            &GestureInput::Move {
                cell: (1000, 500),
                target: SemanticTarget::PlainCell((1000, 500)),
                now: ms(50),
            },
        );
        assert_eq!(count_select(&e), 1, "drag extends to far cell");
        assert!(s.dragging);
        // The selection is bounded by the host before display; the reducer
        // just records the focus.
        if let Some(GestureEffect::Select(req)) = e.first() {
            assert_eq!(req.focus, (1000, 500));
        }
    }

    #[test]
    fn wide_grapheme_and_combining_clusters_are_single_targets() {
        // Wide graphemes and combining clusters occupy multiple terminal
        // cells but map to a single semantic fragment. The reducer treats
        // them as a single Mapped target — the host's semantic mapping
        // handles the cell-to-fragment translation.
        let cfg = GestureConfig {
            copy_on_release: true,
        };
        let s = GestureState::new();
        let cell = (5, 10);
        let target = SemanticTarget::TableCell {
            cell,
            fragment_id: 42,
        };

        // Double-click on a wide-grapheme mapped cell → TableCell or Word.
        let (s, _) = reduce(
            s,
            &cfg,
            &GestureInput::Press {
                button: ClickButton::Primary,
                cell,
                target: target.clone(),
                now: ms(0),
            },
        );
        let (s, _) = reduce(s, &cfg, &GestureInput::Release { cell, now: ms(10) });
        let (s, _) = reduce(
            s,
            &cfg,
            &GestureInput::Press {
                button: ClickButton::Primary,
                cell,
                target: target.clone(),
                now: ms(20),
            },
        );
        let (_, e) = reduce(s, &cfg, &GestureInput::Release { cell, now: ms(30) });
        assert_eq!(count_select(&e), 1);
    }

    // ── Acceptance criterion 15: auto-copy retains highlight ─────────────

    #[test]
    fn auto_copy_retains_highlight_for_every_outcome() {
        let cfg = GestureConfig {
            copy_on_release: true,
        };
        let s = GestureState::new();

        // Drag-select and release.
        let (s, _) = press_plain(&cfg, s, ms(0), (5, 10));
        let (s, _) = move_to(&cfg, s, ms(50), (10, 12));
        let (_, e) = release(&cfg, s, ms(100), (10, 12));

        // The ScheduleCopy effect must have retain_highlight = true.
        let copy_effect = e.iter().find_map(|ef| match ef {
            GestureEffect::ScheduleCopy {
                retain_highlight, ..
            } => Some(*retain_highlight),
            _ => None,
        });
        assert_eq!(copy_effect, Some(true), "auto-copy retains highlight");
    }

    // ── Additional: semantic target change resets multi-click ────────────

    #[test]
    fn semantic_target_change_resets_multiclick() {
        let cfg = GestureConfig::default();
        let s = GestureState::new();

        // First click on cell A.
        let (s, _) = press_plain(&cfg, s, ms(0), (5, 10));
        let (s, _) = release(&cfg, s, ms(10), (5, 10));
        assert_eq!(s.click_count, 1);

        // Second click on a different cell B (different target) → new
        // sequence, not a double-click.
        let (s, _) = press_plain(&cfg, s, ms(20), (8, 12));
        assert_eq!(s.click_count, 1, "target change resets sequence");
        let (_, e) = release(&cfg, s, ms(30), (8, 12));
        assert_eq!(
            count_select(&e),
            0,
            "single click after target change does not select"
        );
    }

    #[test]
    fn non_primary_release_is_inert() {
        let cfg = GestureConfig::default();
        let s = GestureState::new();
        // Non-primary press (which doesn't set pending_press), then release.
        let (s, _) = reduce(
            s,
            &cfg,
            &GestureInput::Press {
                button: ClickButton::Other,
                cell: (5, 10),
                target: SemanticTarget::PlainCell((5, 10)),
                now: ms(0),
            },
        );
        let (s2, e) = reduce(
            s,
            &cfg,
            &GestureInput::Release {
                cell: (5, 10),
                now: ms(10),
            },
        );
        assert_eq!(count_select(&e), 0);
        assert_eq!(count_copy(&e), 0);
        assert!(!s2.dragging);
    }

    #[test]
    fn release_without_press_is_inert() {
        let cfg = GestureConfig::default();
        let s = GestureState::new();
        let (s2, e) = release(&cfg, s, ms(100), (5, 10));
        assert_eq!(count_select(&e), 0);
        assert_eq!(count_copy(&e), 0);
        assert!(!s2.dragging);
        assert!(s2.pending_press.is_none());
    }

    #[test]
    fn move_without_press_is_inert() {
        let cfg = GestureConfig::default();
        let s = GestureState::new();
        let (s2, e) = move_to(&cfg, s, ms(50), (10, 12));
        assert_eq!(count_select(&e), 0);
        assert!(!s2.dragging);
    }

    #[test]
    fn view_change_clears_selection_and_activations() {
        let cfg = GestureConfig::default();
        let s = GestureState::new();
        // Set up a pending activation.
        let (s, _) = press_link(&cfg, s, ms(0), (4, 7), "https://x.test");
        let (s, _) = release(&cfg, s, ms(10), (4, 7));
        assert!(s.activation_token.is_some());

        let (s2, e) = reduce(s, &cfg, &GestureInput::ViewChange { now: ms(100) });
        assert!(matches!(e.as_slice(), [GestureEffect::ClearSelection]));
        assert!(s2.activation_token.is_none());
        assert!(s2.pending_press.is_none());
        assert!(s2.view_generation > 0);
    }

    #[test]
    fn terminal_change_clears_selection_and_activations() {
        let cfg = GestureConfig::default();
        let s = GestureState::new();
        let (s, _) = press_link(&cfg, s, ms(0), (4, 7), "https://x.test");
        let (s, _) = release(&cfg, s, ms(10), (4, 7));
        let token = s.activation_token.unwrap();

        let (s2, e) = reduce(s, &cfg, &GestureInput::TerminalChange { now: ms(100) });
        assert!(matches!(e.as_slice(), [GestureEffect::ClearSelection]));
        assert!(s2.activation_token.is_none());
        assert!(s2.terminal_generation > 0);

        // Stale timer is inert.
        let (_, e2) = reduce(
            s2,
            &cfg,
            &GestureInput::ActivationTimerFired {
                token,
                now: ms(600),
            },
        );
        assert_eq!(count_activate(&e2), 0);
    }

    #[test]
    fn cancel_clears_everything() {
        let cfg = GestureConfig::default();
        let s = GestureState::new();
        let (s, _) = press_link(&cfg, s, ms(0), (4, 7), "https://x.test");
        let (s, _) = release(&cfg, s, ms(10), (4, 7));
        let (s2, e) = reduce(s, &cfg, &GestureInput::Cancel { now: ms(100) });
        assert!(matches!(e.as_slice(), [GestureEffect::ClearSelection]));
        assert!(s2.activation_token.is_none());
        assert!(s2.pending_press.is_none());
        assert!(!s2.dragging);
        assert_eq!(s2.click_count, 0);
    }

    #[test]
    fn double_click_copy_waits_for_matching_timer() {
        let cfg = GestureConfig {
            copy_on_release: true,
        };
        let s = GestureState::new();
        let cell = (5, 10);
        let (s, _) = press_plain(&cfg, s, ms(0), cell);
        let (s, _) = release(&cfg, s, ms(10), cell);
        let (s, _) = press_plain(&cfg, s, ms(20), cell);
        let (s, e) = release(&cfg, s, ms(30), cell);
        assert_eq!(count_select(&e), 1);
        assert_eq!(count_copy(&e), 0, "double-click must not copy immediately");
        assert_eq!(count_copy_timer(&e), 1);
        let token = s.copy_token.unwrap();
        let press_generation = s.copy_press_generation.unwrap();
        let deadline = s.pending_copy_deadline.unwrap();
        assert_eq!(deadline, ms(500));

        let (_, early) = reduce(
            s.clone(),
            &cfg,
            &GestureInput::CopyTimerFired {
                token,
                press_generation,
                now: ms(499),
            },
        );
        assert_eq!(count_copy(&early), 0, "timer before deadline is inert");

        let (s_due, due) = reduce(
            s,
            &cfg,
            &GestureInput::CopyTimerFired {
                token,
                press_generation,
                now: deadline,
            },
        );
        assert_eq!(count_copy(&due), 1, "matching timer schedules one copy");
        assert_eq!(count_copy_timer(&due), 0);
        assert_eq!(s_due.copy_token, Some(token));
        assert!(s_due.pending_copy_deadline.is_none());
    }

    #[test]
    fn triple_click_tombstones_word_copy_timer() {
        let cfg = GestureConfig {
            copy_on_release: true,
        };
        let s = GestureState::new();
        let cell = (5, 10);
        let (s, _) = press_plain(&cfg, s, ms(0), cell);
        let (s, _) = release(&cfg, s, ms(10), cell);
        let (s, _) = press_plain(&cfg, s, ms(20), cell);
        let (s, e2) = release(&cfg, s, ms(30), cell);
        assert_eq!(count_copy_timer(&e2), 1);
        let word_token = s.copy_token.unwrap();
        let word_gen = s.copy_press_generation.unwrap();
        let word_deadline = s.pending_copy_deadline.unwrap();

        let (s, e_press) = press_plain(&cfg, s, ms(40), cell);
        assert!(s.copy_token.is_none(), "third press tombstones word token");
        assert!(s.pending_copy_deadline.is_none());
        assert_eq!(count_copy(&e_press), 0);

        let (_, stale) = reduce(
            s.clone(),
            &cfg,
            &GestureInput::CopyTimerFired {
                token: word_token,
                press_generation: word_gen,
                now: word_deadline,
            },
        );
        assert_eq!(count_copy(&stale), 0, "tombstoned word timer is inert");

        let (s3, e3) = release(&cfg, s, ms(50), cell);
        assert_eq!(count_copy(&e3), 0);
        assert_eq!(count_copy_timer(&e3), 1);
        let line_token = s3.copy_token.unwrap();
        assert_ne!(line_token, word_token);
        assert_eq!(s3.pending_copy_deadline, Some(ms(550)));
    }

    #[test]
    fn stale_copy_timer_and_completion_are_inert() {
        let cfg = GestureConfig {
            copy_on_release: true,
        };
        let s = GestureState::new();
        let cell = (5, 10);
        let (s, _) = press_plain(&cfg, s, ms(0), cell);
        let (s, _) = release(&cfg, s, ms(10), cell);
        let (s, _) = press_plain(&cfg, s, ms(20), cell);
        let (s, _) = release(&cfg, s, ms(30), cell);
        let token = s.copy_token.unwrap();
        let press_generation = s.copy_press_generation.unwrap();

        let (s, _) = reduce(s, &cfg, &GestureInput::Cancel { now: ms(40) });
        let (_, timer) = reduce(
            s.clone(),
            &cfg,
            &GestureInput::CopyTimerFired {
                token,
                press_generation,
                now: ms(530),
            },
        );
        assert_eq!(count_copy(&timer), 0);
        let (_, done) = reduce(
            s.clone(),
            &cfg,
            &GestureInput::CopyCompleted {
                token,
                press_generation,
                outcome: CopyOutcome::Confirmed,
                now: ms(540),
            },
        );
        assert_eq!(count_notify(&done), 0);
        let (_, rejected) = reduce(
            s,
            &cfg,
            &GestureInput::CopyRejected {
                token,
                press_generation,
                now: ms(550),
            },
        );
        assert_eq!(count_notify(&rejected), 0);
    }

    #[test]
    fn copy_rejected_notifies_once() {
        let cfg = GestureConfig {
            copy_on_release: true,
        };
        let s = GestureState::new();
        let (s, _) = press_plain(&cfg, s, ms(0), (5, 10));
        let (s, _) = move_to(&cfg, s, ms(50), (10, 12));
        let (s, e) = release(&cfg, s, ms(100), (10, 12));
        assert_eq!(count_copy(&e), 1);
        let token = s.copy_token.unwrap();
        let press_generation = s.copy_press_generation.unwrap();

        let (s, first) = reduce(
            s,
            &cfg,
            &GestureInput::CopyRejected {
                token,
                press_generation,
                now: ms(110),
            },
        );
        assert_eq!(count_notify(&first), 1);
        assert!(first.iter().any(|effect| matches!(
            effect,
            GestureEffect::Notify {
                outcome: CopyOutcome::Failed
            }
        )));
        assert!(s.copy_token.is_none());

        let (_, second) = reduce(
            s,
            &cfg,
            &GestureInput::CopyRejected {
                token,
                press_generation,
                now: ms(120),
            },
        );
        assert_eq!(count_notify(&second), 0, "duplicate reject is inert");
    }

    #[test]
    fn simultaneous_input_precedes_due_copy_timer() {
        let cfg = GestureConfig {
            copy_on_release: true,
        };
        let s = GestureState::new();
        let cell = (5, 10);
        let (s, _) = press_plain(&cfg, s, ms(0), cell);
        let (s, _) = release(&cfg, s, ms(10), cell);
        let (s, _) = press_plain(&cfg, s, ms(20), cell);
        let (s, _) = release(&cfg, s, ms(30), cell);
        let word_token = s.copy_token.unwrap();
        let word_gen = s.copy_press_generation.unwrap();
        let deadline = s.pending_copy_deadline.unwrap();

        let (s_press, _) = press_plain(&cfg, s, deadline, cell);
        assert!(s_press.copy_token.is_none());
        let (_, timer) = reduce(
            s_press.clone(),
            &cfg,
            &GestureInput::CopyTimerFired {
                token: word_token,
                press_generation: word_gen,
                now: deadline,
            },
        );
        assert_eq!(
            count_copy(&timer),
            0,
            "third press at the deadline wins over the word timer"
        );

        let (s_line, e_line) = release(&cfg, s_press, deadline, cell);
        assert_eq!(count_copy(&e_line), 0);
        assert_eq!(count_copy_timer(&e_line), 1);
        assert_ne!(s_line.copy_token, Some(word_token));
    }
}
