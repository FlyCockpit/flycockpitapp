use crossterm::event::{Event, MouseEvent};

use super::{App, ToastKind};
use crate::tui::primary_paste::{
    PrimaryPasteAccept, PrimaryPasteLayer, PrimaryPasteOutcome, PrimaryPasteViewEpoch,
};

impl App {
    pub(super) fn primary_paste_view_epoch(&self) -> PrimaryPasteViewEpoch {
        PrimaryPasteViewEpoch {
            terminal_generation: self.terminal_input_generation.unwrap_or_default(),
            draft_generation: self.draft_generation,
            mouse_capture: self.mouse_capture,
            pane_focused: self.pane_focused,
            composer_eligible: self.structured_paste_composer_eligible(),
        }
    }

    pub(super) fn invalidate_primary_paste(&mut self) {
        self.primary_paste.invalidate();
    }

    pub(super) fn primary_paste_layer_at(&self, mouse: &MouseEvent) -> PrimaryPasteLayer {
        // The layer that owns the pointer there, from the layer stack; only
        // the surface is resolved further.
        use super::pointer::Layer;
        match self.pointer_owner_at(ratatui::layout::Position::new(mouse.column, mouse.row)) {
            Layer::KeysOverlay => return PrimaryPasteLayer::KeysOverlay,
            Layer::ContextMenu => return PrimaryPasteLayer::ContextMenu,
            Layer::DaemonRestartPrompt
            | Layer::RulesReview
            | Layer::PinsReview
            | Layer::WorkspaceTrust
            | Layer::Onboarding => return PrimaryPasteLayer::Other,
            Layer::Surface => {}
        }
        if self.dialog.is_active() {
            return PrimaryPasteLayer::Settings;
        }
        if self.question_dialog.is_some() {
            return PrimaryPasteLayer::Dialog;
        }
        if self.overlay.is_open() {
            return PrimaryPasteLayer::Overlay;
        }
        if self.btw_pane.as_ref().is_some_and(|pane| pane.focused) {
            return PrimaryPasteLayer::BtwPane;
        }
        if self.pane_focused
            || self
                .pane_rect
                .is_some_and(|rect| super::mouse::point_in(rect, mouse.column, mouse.row))
        {
            return PrimaryPasteLayer::EmbeddedPane;
        }
        if self.mouse_capture
            && self
                .suggestion_box_area
                .is_some_and(|rect| super::mouse::point_in(rect, mouse.column, mouse.row))
        {
            return PrimaryPasteLayer::SuggestionBox;
        }
        if self
            .input_area
            .is_some_and(|rect| super::mouse::point_in(rect, mouse.column, mouse.row))
        {
            return PrimaryPasteLayer::Composer;
        }
        if self.mouse_in_chat_area(mouse) {
            return PrimaryPasteLayer::Chat;
        }
        if self
            .composer_controls
            .picker_rect
            .is_some_and(|rect| super::mouse::point_in(rect, mouse.column, mouse.row))
        {
            return PrimaryPasteLayer::Footer;
        }
        PrimaryPasteLayer::Other
    }

    pub(super) fn handle_primary_paste_middle_down(&mut self, mouse: &MouseEvent) {
        let layer = self.primary_paste_layer_at(mouse);
        let view = self.primary_paste_view_epoch();
        let Some((generation, immediate)) =
            self.primary_paste
                .consider_request(layer, self.mouse_capture, view)
        else {
            return;
        };
        if let Some(outcome) = immediate {
            self.apply_primary_paste_outcome(generation, outcome);
        }
    }

    pub(super) fn apply_primary_paste_outcome(
        &mut self,
        generation: u64,
        outcome: PrimaryPasteOutcome,
    ) {
        match self
            .primary_paste
            .accept_result(generation, outcome, self.primary_paste_view_epoch())
        {
            PrimaryPasteAccept::Enqueue {
                correlation_id,
                text,
            } => {
                let terminal_generation = self.terminal_input_generation.unwrap_or_default();
                let _ = self.handle_observed_terminal_event(
                    Event::Paste(text),
                    self.event_loop_monotonic_now,
                    terminal_generation,
                    Some(crate::tui::structured_paste::PasteSource::NativePaste),
                    Some(correlation_id),
                );
            }
            PrimaryPasteAccept::NoSelection => {
                self.show_toast("No selection", ToastKind::Info);
            }
            PrimaryPasteAccept::Failed => {
                self.show_toast("Paste unavailable", ToastKind::Error);
            }
            PrimaryPasteAccept::Inert => {}
        }
    }
}
