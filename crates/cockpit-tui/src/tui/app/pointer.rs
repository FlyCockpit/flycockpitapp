//! The app's pointer model, in one place.
//!
//! - **Layer stack** ([`App::layer_stack`]): the painted layers, topmost
//!   first, in exactly the order [`App::render`] paints them. Pointer
//!   ownership ([`App::pointer_owner_at`]), key ownership
//!   ([`App::key_owner`]) and the floating-layer paint order all derive from
//!   it, so the layer the user sees on top is the layer that gets the input.
//! - **Pointer position** (`App::pointer`): the last position the terminal
//!   reported, recorded for every mouse event before routing
//!   ([`App::observe_pointer`]) and forgotten when it becomes meaningless
//!   ([`App::forget_pointer`]: resize, focus loss, mouse capture off).
//!   crossterm has no mouse-leave event, so a pointer that leaves the
//!   terminal stays at its last reported cell until one of those.
//! - **Hover** is never an independent fact: every hover store is resolved
//!   from the owned pointer against the frame just drawn
//!   ([`App::resolve_pointer_hover`]), and the frame is redrawn when that
//!   changed anything, so the presented frame hovers exactly what the owned
//!   pointer is over.
//! - **Captures** (a held press or drag whose release is still to come)
//!   belong to the layer that received the press. They end
//!   ([`App::end_pointer_captures`]) when a pointer event is routed to a
//!   different owner (including a move into a review box), after every
//!   release (whoever handled it — a release swallowed by an overlay inside
//!   the surface still ends the drag), when the top layer changes
//!   ([`App::sync_pointer_owner`]), and on resize, focus loss and mouse
//!   capture off. Completed actions are not captures and are never
//!   cancelled here.
//! - **Keys and paste** enter through the layer stack before any other
//!   stage: a floating layer on top takes them all, except the base's global
//!   quit/interrupt keys (see `App::is_base_global_key`).

use crossterm::event::{KeyModifiers, MouseEvent, MouseEventKind};
use ratatui::layout::{Position, Rect};

use super::{App, PointerInteractionEnd, StartupModal};

/// A painted layer, topmost first in [`App::layer_stack`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Layer {
    DaemonRestartPrompt,
    KeysOverlay,
    ContextMenu,
    RulesReview,
    PinsReview,
    WorkspaceTrust,
    Onboarding,
    /// The base surface: the chat and whatever dialog, overlay, pane or
    /// question it shows.
    Surface,
}

impl Layer {
    /// Floating layers paint over the base; exactly one base layer is last
    /// in the stack.
    pub(super) fn is_floating(self) -> bool {
        matches!(
            self,
            Layer::DaemonRestartPrompt
                | Layer::KeysOverlay
                | Layer::ContextMenu
                | Layer::RulesReview
                | Layer::PinsReview
        )
    }
}

impl App {
    /// The painted layers, topmost first — the reverse of paint order.
    pub(super) fn layer_stack(&self) -> Vec<Layer> {
        let mut stack = Vec::with_capacity(4);
        if self.daemon_restart_prompt.is_some() {
            stack.push(Layer::DaemonRestartPrompt);
        }
        if self.keys_overlay.is_some() {
            stack.push(Layer::KeysOverlay);
        }
        if self.context_menu.is_some() {
            stack.push(Layer::ContextMenu);
        }
        if self.rules_review.is_some() {
            stack.push(Layer::RulesReview);
        }
        if self.pins_review.is_some() {
            stack.push(Layer::PinsReview);
        }
        stack.push(self.base_layer());
        stack
    }

    /// The base layer the rest of the stack floats over.
    pub(super) fn base_layer(&self) -> Layer {
        if self.startup_modal_on_top() == Some(StartupModal::WorkspaceTrust) {
            Layer::WorkspaceTrust
        } else if self.onboarding_shell.is_some() {
            Layer::Onboarding
        } else {
            Layer::Surface
        }
    }

    /// The topmost layer.
    pub(super) fn top_layer(&self) -> Layer {
        self.layer_stack()[0]
    }

    /// The layer that receives keys: the topmost one. Every layer in the
    /// stack takes the keyboard while it is on top.
    pub(super) fn key_owner(&self) -> Layer {
        self.top_layer()
    }

    /// Where `layer` takes the pointer. The modal floating layers take all
    /// of it; the review boxes take the cells they painted; a base layer
    /// takes whatever no floating layer took.
    fn layer_takes_pointer_at(&self, layer: Layer, pos: Position) -> bool {
        match layer {
            Layer::DaemonRestartPrompt | Layer::KeysOverlay | Layer::ContextMenu => true,
            Layer::RulesReview => self
                .rules_review_rect
                .is_some_and(|rect| rect.contains(pos)),
            Layer::PinsReview => self.pins_review_rect.is_some_and(|rect| rect.contains(pos)),
            Layer::WorkspaceTrust | Layer::Onboarding | Layer::Surface => true,
        }
    }

    /// The layer that receives pointer input at `pos`: the topmost layer
    /// that takes the pointer there.
    pub(super) fn pointer_owner_at(&self, pos: Position) -> Layer {
        self.layer_stack()
            .into_iter()
            .find(|layer| self.layer_takes_pointer_at(*layer, pos))
            .unwrap_or(Layer::Surface)
    }

    /// The last reported pointer position if `layer` owns it there, else
    /// `None`. This is the only pointer a hover renderer may use.
    pub(super) fn owned_pointer(&self, layer: Layer) -> Option<Position> {
        self.pointer
            .filter(|pos| self.mouse_capture && self.pointer_owner_at(*pos) == layer)
    }

    /// Record the last reported pointer position. Called for every mouse
    /// event before routing, so every surface stays current even when
    /// another layer consumes the event. Surfaces with their own recorders
    /// (settings, onboarding) are fed here too, so the position they hold is
    /// never older than the last one the terminal reported.
    pub(super) fn observe_pointer(&mut self, column: u16, row: u16) {
        let pointer = Some(Position::new(column, row));
        self.pointer = pointer;
        self.dialog.observe_settings_pointer(pointer);
        if let Some(shell) = self.onboarding_shell.as_mut() {
            shell.observe_pointer(pointer);
        }
    }

    /// The pointer position is unknown (resize, focus loss, mouse capture
    /// turned off): every pointer-derived hover in the app is cleared, and
    /// stays cleared until the pointer is reported again.
    pub(super) fn forget_pointer(&mut self) {
        self.pointer = None;
        self.dialog.observe_settings_pointer(None);
        self.dialog.forget_settings_pointer();
        if let Some(shell) = self.onboarding_shell.as_mut() {
            shell.end_pointer_interactions();
        }
        self.resolve_surface_hover(None, false);
    }

    /// End every pointer capture — a press or drag whose release is still
    /// to come — because that release can no longer reach its owner. The
    /// complete list of captures in the TUI:
    /// - the link press (`link_pointer_gesture`) and the link hit generation;
    /// - the transcript press/drag (mouse gesture `EndCapture`) and the
    ///   performance-chip press;
    /// - the registered-button press (`button_registry`) and the session
    ///   rail's confirm-button press;
    /// - the pane-divider drag and the composer picker scrollbar drag;
    /// - settings: the pressed target and the button-registry press;
    /// - onboarding: the provider scrollbar drag.
    ///
    /// A settings page's armed confirmations are not captures: they drop
    /// only when settings loses the input to a layer above it, or the
    /// pointer's coordinates become void (resize, focus loss, capture off).
    ///
    /// Committed actions are **kept**, because the user already completed
    /// them: a link activation waiting out its multi-click window, a
    /// scheduled multi-click copy (its text captured when the click
    /// completed) or an in-flight copy, the primary-selection paste, a
    /// settings external-editor edit, an OAuth copy or setup operation, and
    /// the selection itself (except after a resize, when its coordinates are
    /// void).
    pub(super) fn end_pointer_captures(&mut self) {
        self.end_pointer_captures_clearing_selection(false);
    }

    fn end_pointer_captures_clearing_selection(&mut self, clear_selection: bool) {
        self.link_pointer_gesture.end_press();
        self.link_registry.invalidate_pointer_generation();
        self.button_registry.clear_pressed();
        self.session_rail.cancel_pointer_capture();
        self.dragging_divider = false;
        self.end_composer_picker_scroll_drag();
        self.dialog.end_settings_pointer_captures();
        if let Some(shell) = self.onboarding_shell.as_mut() {
            shell.cancel_pointer_capture();
        }
        self.pending_performance_chip_press = None;
        let now = self.event_loop_monotonic_now;
        self.reduce_mouse_gesture(super::mouse_gesture::GestureInput::EndCapture {
            clear_selection,
            now,
        });
    }

    /// The terminal was resized or lost focus: every capture ends and the
    /// pointer position is forgotten. A resize also voids the selection's
    /// coordinates.
    pub(super) fn end_pointer_interactions(&mut self, end: PointerInteractionEnd) {
        self.end_pointer_captures_clearing_selection(end == PointerInteractionEnd::Resize);
        self.dialog.cancel_settings_pointer_confirmations();
        self.forget_pointer();
    }

    /// Mouse capture was turned off (`/mouse off` or the settings toggle):
    /// no further mouse event will arrive, so every capture ends and the
    /// pointer is forgotten.
    pub(super) fn end_mouse_capture(&mut self) {
        self.end_pointer_captures();
        self.dialog.cancel_settings_pointer_confirmations();
        self.forget_pointer();
    }

    /// The single ownership-transition funnel: when the top layer differs
    /// from the one last seen, the old owner can no longer receive its
    /// capture's release, so every capture ends. Called before each mouse
    /// event is routed (so a layer that opened or mounted since — by key,
    /// daemon event or async completion — is accounted for before its first
    /// pointer event) and at the start of every render.
    pub(super) fn sync_pointer_owner(&mut self) {
        let top = self.top_layer();
        let previous = self.last_top_layer;
        if previous != Some(top) {
            if previous.is_some() {
                self.end_pointer_captures();
                // Consecutive clicks cannot straddle a change of top layer.
                self.note_interaction_above_onboarding();
                // A confirmation armed on the surface (a settings page's
                // reset/delete) is dropped only when the surface itself lost
                // the input to a layer above it — fail-safe, and never by a
                // change among layers it was already below.
                if previous == Some(Layer::Surface) && top != Layer::Surface {
                    self.dialog.cancel_settings_pointer_confirmations();
                }
            }
            self.last_top_layer = Some(top);
        }
    }

    /// Any interaction that does not reach the onboarding base — a press,
    /// scroll or key taken by a layer above it, or a change of top layer —
    /// breaks the base's pending two-click confirmation.
    pub(super) fn note_interaction_above_onboarding(&mut self) {
        if self.base_layer() == Layer::Onboarding
            && let Some(shell) = self.onboarding_shell.as_mut()
        {
            shell.cancel_pending_confirmation();
        }
    }

    /// Show the daemon restart prompt. It takes the pointer, so the
    /// ownership funnel ends every capture underneath at once.
    pub(super) fn open_daemon_restart_prompt(&mut self) {
        self.daemon_restart_prompt = Some(super::DaemonRestartPrompt::default());
        self.sync_pointer_owner();
    }

    /// Tell the renderers that derive hover at paint time (the onboarding
    /// shell, the settings help row) whether they own the pointer this
    /// frame, and hand the rail its owned pointer.
    pub(super) fn distribute_pointer_ownership(&mut self) {
        let onboarding_owns = self.owned_pointer(Layer::Onboarding).is_some();
        let surface_pointer = self.owned_pointer(Layer::Surface);
        if let Some(shell) = self.onboarding_shell.as_mut() {
            shell.set_pointer_owned(onboarding_owns);
        }
        self.dialog
            .set_settings_pointer_owned(surface_pointer.is_some());
    }

    /// Resolve every surface hover from the owned pointer against the frame
    /// just drawn. Returns whether any hover changed (the caller redraws).
    pub(super) fn resolve_pointer_hover(&mut self) -> bool {
        let before = self.surface_hover_snapshot();
        let pointer = self.owned_pointer(Layer::Surface);
        self.resolve_surface_hover(pointer, false);
        before != self.surface_hover_snapshot()
    }

    /// Resolve the surface hovers for `pointer` (`None`: nothing hovers).
    /// `motion` is set for a real `Moved` event, whose press-cancelling and
    /// picker-cursor side effects a redraw-time resolution must not repeat.
    pub(super) fn resolve_surface_hover(&mut self, pointer: Option<Position>, motion: bool) {
        let Some(pos) = pointer.filter(|_| self.mouse_capture) else {
            self.session_rail.set_pointer(None);
            self.button_registry.resolve_hover(None);
            self.queue_hover = None;
            self.link_registry.clear_hover();
            let _ = self.dialog.resolve_settings_hover(None);
            self.hovered_suggestion = None;
            self.hovered_control_chip = None;
            self.hovered_affordance = None;
            return;
        };
        let mouse = MouseEvent {
            kind: MouseEventKind::Moved,
            column: pos.x,
            row: pos.y,
            modifiers: KeyModifiers::NONE,
        };
        let pointer_in_composer_picker = self
            .composer_controls
            .picker_rect
            .is_some_and(|rect: Rect| rect.contains(pos));
        if !pointer_in_composer_picker && self.session_rail_owns_pointer(pos.x, pos.y) {
            self.link_registry.clear_hover();
            self.button_registry.resolve_hover(None);
            self.queue_hover = None;
            let _ = self.dialog.resolve_settings_hover(None);
            self.hovered_suggestion = None;
            self.hovered_control_chip = None;
            self.hovered_affordance = None;
            if motion {
                let _ = self.session_rail.handle_mouse(mouse);
            }
            self.session_rail.set_pointer(Some((pos.x, pos.y)));
            return;
        }
        self.session_rail.set_pointer(None);
        if motion {
            let _ = self.button_registry.handle_mouse(mouse);
            let hovered_picker_row =
                self.button_registry
                    .hit(pos.x, pos.y)
                    .and_then(|target| match &target.dispatch {
                        crate::tui::button::ButtonDispatch::ComposerPickerRow { index } => {
                            Some(*index)
                        }
                        _ => None,
                    });
            if let Some(index) = hovered_picker_row {
                self.hover_composer_picker_row(index);
            }
        } else {
            self.button_registry.resolve_hover(Some(pos));
        }
        self.update_queue_pointer(mouse);
        let _ = self.link_registry.update_hover(pos.x, pos.y);
        if self.link_registry.hovered().is_some() {
            let _ = self.dialog.resolve_settings_hover(None);
            self.hovered_suggestion = None;
            self.hovered_control_chip = None;
            self.hovered_affordance = None;
            return;
        }
        if self.dialog.resolve_settings_hover(Some(pos)) {
            self.hovered_suggestion = None;
            self.hovered_control_chip = None;
            self.hovered_affordance = None;
            return;
        }
        self.update_hovered_affordance(&mouse);
    }

    fn surface_hover_snapshot(&self) -> SurfaceHoverSnapshot {
        SurfaceHoverSnapshot {
            rail: self.session_rail.pointer(),
            rail_confirm: self.session_rail.confirm_hover(),
            button: self.button_registry.hover().cloned(),
            queue: self.queue_hover,
            link: self.link_registry.hovered().map(|link| link.url.clone()),
            settings: self.dialog.settings_hover_snapshot(),
            suggestion: self.hovered_suggestion,
            control_chip: self.hovered_control_chip,
            affordance: self.hovered_affordance,
        }
    }

    /// Draw a frame whose hover matches the pointer: draw, resolve hover
    /// against the geometry just drawn, and draw again if it changed. The
    /// second draw lands inside the same synchronized update.
    pub(super) fn draw_resolving_pointer<B: ratatui::backend::Backend>(
        &mut self,
        terminal: &mut ratatui::Terminal<B>,
    ) -> Result<(), B::Error> {
        self.link_registry.begin_frame();
        terminal.draw(|frame| self.render(frame))?;
        if self.resolve_pointer_hover() {
            self.link_registry.begin_frame();
            terminal.draw(|frame| self.render(frame))?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SurfaceHoverSnapshot {
    rail: Option<(u16, u16)>,
    rail_confirm: Option<crate::tui::button::ButtonId>,
    button: Option<crate::tui::button::ButtonId>,
    queue: Option<uuid::Uuid>,
    link: Option<String>,
    settings: Option<String>,
    suggestion: Option<super::SuggestionBoxTarget>,
    control_chip: Option<super::render::ControlChip>,
    affordance: Option<super::AffordanceTarget>,
}
