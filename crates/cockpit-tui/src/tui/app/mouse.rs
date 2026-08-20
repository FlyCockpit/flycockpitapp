use super::*;

fn resolve_inner_scroll_target(
    regions: &[AffordanceScrollRegion],
    row: usize,
    up: bool,
) -> Option<AffordanceTarget> {
    let region = regions
        .iter()
        .find(|region| row >= region.row_start && row <= region.row_end)?;
    let can_scroll = if up {
        region.offset > 0
    } else {
        region.offset < region.max_offset
    };
    can_scroll.then_some(region.target)
}

/// True when `(col, row)` falls inside `rect` (absolute coords).
pub(super) fn point_in(rect: Rect, col: u16, row: u16) -> bool {
    col >= rect.x && col < rect.x + rect.width && row >= rect.y && row < rect.y + rect.height
}

impl App {
    /// - left-down on a chat thinking-chip → toggle reasoning expansion;
    /// - left-down on a non-chip chat row → start drag-select (T8.f);
    /// - left-drag → extend the active drag-select;
    /// - left-up → finalize drag-select (selection persists for copy).
    pub(super) fn handle_mouse(&mut self, mouse: MouseEvent) {
        // Toast dismissal on "meaningful" mouse events — clicks and
        // wheels count, motion-only / drag-continuation / release
        // don't (those are part of an in-flight gesture and the
        // first event already dismissed).
        if self.toast.is_some()
            && matches!(
                mouse.kind,
                MouseEventKind::Down(_) | MouseEventKind::ScrollUp | MouseEventKind::ScrollDown
            )
        {
            self.toast = None;
        }
        // The keys overlay is visually topmost and therefore owns pointer
        // input before links or settings targets underneath it.
        if let Some(overlay) = self.keys_overlay.as_mut() {
            match mouse.kind {
                MouseEventKind::ScrollUp => overlay.scroll_up(),
                MouseEventKind::ScrollDown => overlay.scroll_down(),
                MouseEventKind::Down(_) => {
                    self.invalidate_mouse_gesture(
                        MouseGestureInvalidation::Cancel,
                        self.event_loop_monotonic_now,
                    );
                }
                _ => {}
            }
            return;
        }
        // A visible context menu is the next modal layer. It must preempt a
        // settings dialog that may still be rendered underneath it.
        if let Some(menu) = self.context_menu.clone() {
            match mouse.kind {
                MouseEventKind::Down(MouseButton::Left) => {
                    self.invalidate_mouse_gesture(
                        MouseGestureInvalidation::Cancel,
                        self.event_loop_monotonic_now,
                    );
                    let full = ratatui::layout::Rect::new(0, 0, u16::MAX, u16::MAX);
                    if let Some(action) = menu.hit_test(mouse.column, mouse.row, full) {
                        self.context_menu = None;
                        self.execute_context_menu_action(action, menu.clicked_chat_row);
                    } else {
                        self.context_menu = None;
                    }
                }
                MouseEventKind::Down(_) | MouseEventKind::ScrollUp | MouseEventKind::ScrollDown => {
                    self.invalidate_mouse_gesture(
                        MouseGestureInvalidation::Cancel,
                        self.event_loop_monotonic_now,
                    );
                    self.context_menu = None;
                }
                _ => {}
            }
            return;
        }
        if matches!(mouse.kind, MouseEventKind::Moved) {
            if self.mouse_capture {
                let _ = self.button_registry.handle_mouse(mouse);
                let _link_hover_changed = self.link_registry.update_hover(mouse.column, mouse.row);
            } else {
                self.link_registry.clear_hover();
            }
            if self.link_registry.hovered().is_some() {
                self.dialog.clear_settings_pointer_hover();
                self.hovered_suggestion = None;
                self.hovered_control_chip = None;
                self.hovered_affordance = None;
                self.hovered_footer_control = None;
                return;
            }
            if self.mouse_capture && self.dialog.handle_settings_pointer(mouse).is_some() {
                self.hovered_suggestion = None;
                self.hovered_control_chip = None;
                self.hovered_affordance = None;
                self.hovered_footer_control = None;
                return;
            }
            self.update_hovered_affordance(&mouse);
            if self.link_registry.hovered().is_some() {
                self.hovered_suggestion = None;
                self.hovered_control_chip = None;
                self.hovered_affordance = None;
                self.hovered_footer_control = None;
            }
            self.update_hovered_footer_control(mouse.column, mouse.row);
            return;
        }
        if !self.mouse_capture {
            self.link_pointer_gesture.cancel();
            self.pending_link_activation = None;
        }
        let hit_url = self
            .link_registry
            .at(mouse.column, mouse.row)
            .map(|link| link.url.clone());
        let link_outcome = if self.mouse_capture {
            self.link_pointer_gesture.handle(
                mouse.kind,
                mouse.column,
                mouse.row,
                hit_url.as_deref(),
                self.link_registry.generation(),
                std::time::Instant::now(),
            )
        } else {
            crate::tui::links::LinkGestureOutcome::Unhandled
        };
        if matches!(
            link_outcome,
            crate::tui::links::LinkGestureOutcome::Consumed
                | crate::tui::links::LinkGestureOutcome::SelectUrl(_)
        ) {
            self.invalidate_mouse_gesture(
                MouseGestureInvalidation::Cancel,
                self.event_loop_monotonic_now,
            );
            return;
        }
        // Scheduled activation: the host starts a timer; the actual
        // activation happens after the 500 ms multi-click window if the
        // token remains current. We store the pending activation so the
        // event loop can check it.
        if let crate::tui::links::LinkGestureOutcome::ScheduleActivation(pa) = &link_outcome {
            // Store the pending activation for the event loop to check.
            self.pending_link_activation = Some(pa.clone());
            return;
        }
        if let crate::tui::links::LinkGestureOutcome::Activate(url) = link_outcome {
            if cockpit_core::sysinfo::is_ssh() {
                match crate::clipboard::copy_plain(&url, self.clipboard_recovery) {
                    Ok(result) => {
                        let (msg, kind) = super::copy_actions::describe_delivered(
                            &result,
                            "Link copied (SSH session).".to_string(),
                        );
                        self.show_toast(msg, kind);
                    }
                    Err(error) => {
                        self.show_toast(format!("Copy failed: {error}"), ToastKind::Error)
                    }
                }
            } else {
                match crate::tui::links::open_browser(&url) {
                    Ok(()) => self.show_toast("Opened link in browser", ToastKind::Success),
                    Err(error) => {
                        self.show_toast(format!("Could not open link: {error}"), ToastKind::Error)
                    }
                }
            }
            return;
        }
        if self.mouse_capture
            && let Some(outcome) = self.button_registry.handle_mouse(mouse)
        {
            let consumed = matches!(
                &outcome,
                crate::tui::button::ButtonPointerOutcome::Activated(_)
                    | crate::tui::button::ButtonPointerOutcome::Pressed(_)
                    | crate::tui::button::ButtonPointerOutcome::Cancelled
            ) || self.button_registry.hit(mouse.column, mouse.row).is_some();
            if let crate::tui::button::ButtonPointerOutcome::Activated(dispatch) = outcome {
                self.dispatch_button(dispatch);
            }
            if consumed {
                return;
            }
        }
        if self.mouse_capture
            && let Some(outcome) = self.dialog.handle_settings_pointer(mouse)
        {
            if matches!(outcome, crate::tui::settings::SettingsPointerOutcome::Close) {
                let open_default_model_picker = self.dialog.take_pending_default_model_picker();
                if let Some(provider) = self.reopen_model_picker_after_settings.take() {
                    self.dialog = crate::tui::settings::Dialog::None;
                    self.invalidate_primary_paste();
                    self.sync_mouse_capture_from_dialog();
                    self.resync_config_after_local_write();
                    self.open_model_picker_for_provider(&provider);
                } else {
                    self.dialog = crate::tui::settings::Dialog::None;
                    self.invalidate_primary_paste();
                    self.sync_mouse_capture_from_dialog();
                    self.resync_config_after_local_write();
                }
                if open_default_model_picker {
                    self.open_default_model_picker_from_settings();
                }
            }
            return;
        }
        if self.mouse_capture
            && matches!(mouse.kind, MouseEventKind::Down(MouseButton::Left))
            && let Overlay::ModelPicker(picker) = &mut self.overlay
        {
            let should_close = picker.handle_mouse_row(mouse.row);
            if should_close {
                let accepted = picker.is_done();
                self.close_model_picker(accepted);
            }
            return;
        }
        if self.mouse_capture
            && matches!(mouse.kind, MouseEventKind::Down(MouseButton::Left))
            && (self.footer_agent_picker.is_some() || self.footer_mode_picker.is_some())
        {
            if let Some(hit) = self
                .footer_picker_row_hits
                .iter()
                .find(|hit| point_in(hit.rect, mouse.column, mouse.row))
                .cloned()
            {
                match hit.kind {
                    FooterPickerKind::Agent => {
                        let mut commit = None;
                        if let Some(picker) = self.footer_agent_picker.as_mut() {
                            picker.select(hit.index);
                            commit = Some(picker.clone());
                        }
                        if let Some(picker) = commit {
                            self.commit_footer_agent_picker(&picker);
                        }
                    }
                    FooterPickerKind::Mode => {
                        if let Some(mut picker) = self.footer_mode_picker {
                            picker.select(hit.index);
                            self.footer_mode_picker = None;
                            self.footer_selection = None;
                            self.set_footer_llm_mode(picker.selected_mode());
                        }
                    }
                }
            }
            return;
        }
        if matches!(self.overlay, Overlay::Sessions(_)) {
            let overlay = std::mem::take(&mut self.overlay);
            let Overlay::Sessions(mut pane) = overlay else {
                unreachable!();
            };
            let pointer = matches!(
                mouse.kind,
                MouseEventKind::Down(_) | MouseEventKind::Up(_) | MouseEventKind::Moved
            );
            let wheel = matches!(
                mouse.kind,
                MouseEventKind::ScrollUp | MouseEventKind::ScrollDown
            );
            let outcome = if wheel || (self.mouse_capture && pointer) {
                pane.handle_mouse(mouse)
            } else {
                None
            };
            match outcome {
                Some(crate::tui::sessions_pane::SessionsOutcome::Close) => {
                    // The overlay was taken above; leaving it unrestored closes it.
                }
                Some(crate::tui::sessions_pane::SessionsOutcome::Resume(session_id)) => {
                    self.resume_session(session_id);
                }
                Some(crate::tui::sessions_pane::SessionsOutcome::LoadList) => {
                    self.overlay = Overlay::Sessions(pane);
                    self.start_sessions_list_action();
                }
                Some(crate::tui::sessions_pane::SessionsOutcome::LoadPreview {
                    session_id,
                    before_seq,
                }) => {
                    self.overlay = Overlay::Sessions(pane);
                    self.start_sessions_preview_action(session_id, before_seq);
                }
                None => {
                    self.overlay = Overlay::Sessions(pane);
                }
            }
            return;
        }

        // The `/sealed` no-echo overlay is modal: a left-click dismisses it,
        // which cancels the pending write and drops the minted capability (or
        // hides a recover reveal). Handled before the `&mut self.overlay` match
        // so the dismiss can call back into `self` to send the cancel RPC.
        if matches!(self.overlay, Overlay::Sealed(_)) {
            if matches!(mouse.kind, MouseEventKind::Down(MouseButton::Left)) {
                self.dismiss_sealed_overlay_via_pointer();
            }
            return;
        }

        match &mut self.overlay {
            Overlay::Stats(pane) => {
                match mouse.kind {
                    MouseEventKind::ScrollUp => pane.scroll_up(),
                    MouseEventKind::ScrollDown => pane.scroll_down(),
                    _ => {}
                }
                return;
            }
            Overlay::Sessions(_) => return,
            Overlay::Tools(_) => return,
            Overlay::GoalSettings(_) => return,
            Overlay::Skills(pane) => {
                match mouse.kind {
                    MouseEventKind::ScrollUp => pane.scroll_up(),
                    MouseEventKind::ScrollDown => pane.scroll_down(),
                    _ => {}
                }
                return;
            }
            Overlay::Permissions(pane) => {
                match mouse.kind {
                    MouseEventKind::ScrollUp => pane.scroll_up(),
                    MouseEventKind::ScrollDown => pane.scroll_down(),
                    _ => {}
                }
                return;
            }
            Overlay::Context(_) => return,
            Overlay::Notes(pane) => {
                match mouse.kind {
                    MouseEventKind::ScrollUp => pane.scroll_up(),
                    MouseEventKind::ScrollDown => pane.scroll_down(),
                    _ => {}
                }
                return;
            }
            Overlay::Diff(pane) => {
                match mouse.kind {
                    MouseEventKind::ScrollUp => pane.scroll_up(),
                    MouseEventKind::ScrollDown => pane.scroll_down(),
                    _ => {}
                }
                return;
            }
            Overlay::Help(pane) => {
                match mouse.kind {
                    MouseEventKind::ScrollUp => pane.scroll_up(),
                    MouseEventKind::ScrollDown => pane.scroll_down(),
                    _ => {}
                }
                return;
            }
            Overlay::Leaks(_) => return,
            // Handled by the modal guard above; unreachable here.
            Overlay::Sealed(_) => return,
            Overlay::ModelPicker(_)
            | Overlay::Multireview(_)
            | Overlay::Usage(_)
            | Overlay::Resources(_)
            | Overlay::Quick(_) => return,
            Overlay::None => {}
        }
        if self.mouse_capture && self.handle_suggestion_box_mouse(&mouse) {
            return;
        }

        // Embedded pane (GOALS §1i/§1e): divider drag-resize, click-to-
        // focus, and PTY mouse forwarding. Consumes the event when it
        // lands on the divider or inside the pane so the chat handlers
        // below don't also see it.
        if self.pane.is_some() && self.handle_pane_mouse(&mouse) {
            return;
        }
        if matches!(mouse.kind, MouseEventKind::Down(MouseButton::Middle)) {
            self.handle_primary_paste_middle_down(&mouse);
            return;
        }
        if self.mouse_capture
            && matches!(mouse.kind, MouseEventKind::Down(MouseButton::Left))
            && let Some(hit) = self
                .footer_hit_areas
                .iter()
                .find(|hit| {
                    mouse.row >= hit.rect.y
                        && mouse.row < hit.rect.y + hit.rect.height
                        && mouse.column >= hit.rect.x
                        && mouse.column < hit.rect.x + hit.rect.width
                })
                .cloned()
        {
            self.cancel_mouse_gesture(self.event_loop_monotonic_now);
            let already_selected = self.footer_selection == Some(hit.control);
            self.footer_selection = Some(hit.control);
            self.footer_agent_picker = None;
            self.footer_mode_picker = None;
            if already_selected {
                match hit.control {
                    crate::tui::chrome::FooterControl::Agent => self.open_footer_agent_picker(),
                    crate::tui::chrome::FooterControl::Model => self.open_model_picker(),
                    crate::tui::chrome::FooterControl::Mode => self.open_footer_mode_picker(),
                }
            }
            return;
        }

        // Right-click in chat area opens the context menu.
        if matches!(mouse.kind, MouseEventKind::Down(MouseButton::Right))
            && self.mouse_in_chat_area(&mouse)
        {
            self.invalidate_mouse_gesture(
                MouseGestureInvalidation::Cancel,
                self.event_loop_monotonic_now,
            );
            let chat_row = self
                .chat_area
                .map(|a| (mouse.row.saturating_sub(a.y)) as usize)
                .unwrap_or(0);
            let diff_editor = std::env::var_os("EDITOR").is_some()
                && self
                    .chat_row_meta
                    .get(chat_row)
                    .is_some_and(|meta| meta.diff_path.is_some());
            let items = crate::tui::context_menu::ContextMenu::build_items(
                cockpit_core::sysinfo::is_ssh(),
                diff_editor,
            );
            self.context_menu = Some(crate::tui::context_menu::ContextMenu {
                preferred_origin: (mouse.column, mouse.row),
                clicked_chat_row: chat_row,
                cursor: 0,
                items,
            });
            return;
        }

        // Wheel: scroll the chat history. Wheel also clears any
        // active selection because the selection coords refer to
        // specific terminal rows, and a scroll changes what's at
        // each row.
        match mouse.kind {
            MouseEventKind::ScrollUp => {
                if let Some(area) = self.chat_area
                    && self.mouse_in_chat_area(&mouse)
                {
                    self.invalidate_mouse_gesture(
                        MouseGestureInvalidation::ViewChange,
                        self.event_loop_monotonic_now,
                    );
                    // A collapsed tool box under the cursor captures the
                    // wheel until it hits its top; then the transcript
                    // scrolls.
                    let rel = (mouse.row - area.y) as usize;
                    if !self.scroll_inner_region_at_row(rel, true) {
                        self.scroll_chat_up(3);
                    }
                }
                return;
            }
            MouseEventKind::ScrollDown => {
                if let Some(area) = self.chat_area
                    && self.mouse_in_chat_area(&mouse)
                {
                    self.invalidate_mouse_gesture(
                        MouseGestureInvalidation::ViewChange,
                        self.event_loop_monotonic_now,
                    );
                    let rel = (mouse.row - area.y) as usize;
                    if !self.scroll_inner_region_at_row(rel, false) {
                        self.scroll_chat_down(3);
                    }
                }
                return;
            }
            _ => {}
        }

        // Drag/release belong to the gesture reducer once a press is live.
        if matches!(mouse.kind, MouseEventKind::Drag(MouseButton::Left)) {
            if self.mouse_gesture_state.pending_press.is_some() {
                self.dispatch_chat_gesture(mouse);
            }
            return;
        }
        if matches!(mouse.kind, MouseEventKind::Up(MouseButton::Left)) {
            if self.mouse_gesture_state.pending_press.is_some() || self.mouse_gesture_state.dragging
            {
                self.dispatch_chat_gesture(mouse);
            }
            return;
        }

        if !matches!(mouse.kind, MouseEventKind::Down(MouseButton::Left)) {
            return;
        }

        // Composer first: clicks here position the cursor in the
        // input buffer (T8.d). The input rect is the *outer* rect
        // including the block border; we re-derive the inner rect
        // (1-cell border on each side, top border absent when the
        // queue is above) for hit-testing.
        if let Some(area) = self.input_area
            && let Some((line, col)) = self.composer_cursor_target_for_click(area, &mouse)
        {
            // Clicking into the composer dismisses any chat
            // selection — the user has switched contexts.
            self.cancel_mouse_gesture(self.event_loop_monotonic_now);
            self.composer.set_cursor_from_visual_position(
                line,
                col,
                input_prefix_width(),
                area.width.saturating_sub(2) as usize,
            );
            // Drop into Insert — clicking to place the cursor implies
            // they're about to type there.
            if self.composer.vim_enabled() {
                self.clear_vim_transient_state();
                self.composer.set_vim_mode(VimMode::Insert);
            }
            return;
        }

        let Some(area) = self.chat_area else {
            self.cancel_mouse_gesture(self.event_loop_monotonic_now);
            return;
        };
        // crossterm reports row/column as 0-indexed absolute terminal
        // coordinates. Translate to chat-area relative.
        if mouse.row < area.y || mouse.row >= area.y + area.height {
            self.cancel_mouse_gesture(self.event_loop_monotonic_now);
            return;
        }
        if mouse.column < area.x || mouse.column >= area.x + area.width {
            self.cancel_mouse_gesture(self.event_loop_monotonic_now);
            return;
        }
        let rel = (mouse.row - area.y) as usize;
        if let Some(entry_idx) = self
            .chat_row_meta
            .get(rel)
            .and_then(|meta| meta.subagent_target)
        {
            self.cancel_mouse_gesture(self.event_loop_monotonic_now);
            if self.open_subagent_view_for_history_index(entry_idx) {
                return;
            }
        }

        // Chip click wins over drag-select start: chip rows have a
        // single owning entry whose `expanded` flag we toggle.
        if let Some(entry_idx) = self
            .chat_row_meta
            .get(rel)
            .and_then(|meta| meta.chip_target)
        {
            self.cancel_mouse_gesture(self.event_loop_monotonic_now);
            match self.history.get_mut(entry_idx) {
                Some(HistoryEntry::Agent {
                    expanded,
                    reasoning_offset,
                    ..
                }) => {
                    *expanded = !*expanded;
                    if !*expanded {
                        *reasoning_offset = 0;
                    }
                }
                Some(HistoryEntry::Subagent { expanded, .. }) => {
                    *expanded = !*expanded;
                }
                // A preflighted user message: clicking the `⚙ preflighted`
                // chip reveals the original typed input / re-hides it
                // (implementation note).
                Some(HistoryEntry::User {
                    expanded,
                    cleaned: Some(_),
                    ..
                }) => {
                    *expanded = !*expanded;
                }
                Some(HistoryEntry::CompactBoundary {
                    expanded,
                    handoff: Some(handoff),
                    ..
                }) if !handoff.trim().is_empty() => {
                    *expanded = !*expanded;
                }
                Some(HistoryEntry::InferenceError { expanded, .. }) => {
                    *expanded = !*expanded;
                }
                _ => {}
            }
            return;
        }
        // Tool-call click wins before generic row selection: it toggles only
        // the call under the pointer; neighboring calls keep their state.
        if self
            .chat_row_meta
            .get(rel)
            .and_then(|meta| meta.tool_call_target)
            .is_some()
        {
            self.cancel_mouse_gesture(self.event_loop_monotonic_now);
            self.toggle_tool_call_at_row(rel);
            return;
        }
        self.dispatch_chat_gesture(mouse);
    }

    fn dispatch_button(&mut self, dispatch: crate::tui::button::ButtonDispatch) {
        match dispatch {
            crate::tui::button::ButtonDispatch::Footer(control) => {
                self.cancel_mouse_gesture(self.event_loop_monotonic_now);
                let already_selected = self.footer_selection == Some(control);
                self.footer_selection = Some(control);
                self.footer_agent_picker = None;
                self.footer_mode_picker = None;
                if already_selected {
                    match control {
                        crate::tui::chrome::FooterControl::Agent => self.open_footer_agent_picker(),
                        crate::tui::chrome::FooterControl::Model => self.open_model_picker(),
                        crate::tui::chrome::FooterControl::Mode => self.open_footer_mode_picker(),
                    }
                }
            }
            crate::tui::button::ButtonDispatch::PersistentNoticeCopy => {
                self.copy_persistent_notice_fix_command();
            }
            crate::tui::button::ButtonDispatch::PersistentNoticeSwitchModel => {
                self.open_model_picker();
            }
            crate::tui::button::ButtonDispatch::PersistentNoticeFixProvider => {
                self.open_auth_failure_provider();
            }
            crate::tui::button::ButtonDispatch::TranscriptPin { seq }
            | crate::tui::button::ButtonDispatch::TranscriptUnpin { seq } => {
                self.toggle_pin_for_seq(seq);
            }
            crate::tui::button::ButtonDispatch::TranscriptFork { seq } => {
                self.fork_for_seq(seq);
            }
            crate::tui::button::ButtonDispatch::SessionsConfirmArchive
            | crate::tui::button::ButtonDispatch::SessionsConfirmDelete
            | crate::tui::button::ButtonDispatch::SessionsConfirmCancel => {
                if let Overlay::Sessions(pane) = &mut self.overlay {
                    pane.pointer_activate_confirm(dispatch);
                }
            }
            crate::tui::button::ButtonDispatch::ResourcePromote { index } => {
                if let Overlay::Resources(pane) = &mut self.overlay {
                    pane.pointer_promote(index);
                }
            }
            crate::tui::button::ButtonDispatch::NoteNew => {
                if let Overlay::Notes(pane) = &mut self.overlay {
                    pane.pointer_new_note();
                }
            }
            crate::tui::button::ButtonDispatch::DaemonPrompt { index } => {
                if let Some(prompt) = self.daemon_prompt.as_mut() {
                    prompt.pointer_select(index);
                }
            }
            crate::tui::button::ButtonDispatch::QuestionAction { index } => {
                if let Some(dialog) = self.question_dialog.as_mut() {
                    let _ = (dialog, index);
                }
            }
            crate::tui::button::ButtonDispatch::OverlayAction { .. }
            | crate::tui::button::ButtonDispatch::DialogAction { .. }
            | crate::tui::button::ButtonDispatch::SettingsHeader(_)
            | crate::tui::button::ButtonDispatch::Settings(_) => {}
        }
    }

    fn update_hovered_footer_control(&mut self, column: u16, row: u16) {
        if !self.mouse_capture {
            self.hovered_footer_control = None;
            return;
        }
        self.hovered_footer_control = self
            .footer_hit_areas
            .iter()
            .find(|hit| {
                row >= hit.rect.y
                    && row < hit.rect.y + hit.rect.height
                    && column >= hit.rect.x
                    && column < hit.rect.x + hit.rect.width
            })
            .map(|hit| hit.control);
    }

    /// Route a mouse event to the embedded pane (GOALS §1i). Returns
    /// `true` when consumed: a divider drag-resize, a click that focuses
    /// the pane, or an event forwarded to the child's PTY. Returns
    /// `false` when the event missed the pane and divider, so the chat /
    /// composer handlers below get their normal turn (split mode).
    fn handle_pane_mouse(&mut self, mouse: &MouseEvent) -> bool {
        // Continue / end an in-progress divider drag wherever the mouse
        // goes (so dragging past the divider still tracks).
        if self.dragging_divider {
            match mouse.kind {
                MouseEventKind::Drag(MouseButton::Left) => {
                    self.resize_split_to(mouse.column, mouse.row);
                    return true;
                }
                MouseEventKind::Up(MouseButton::Left) => {
                    self.dragging_divider = false;
                    return true;
                }
                _ => return true,
            }
        }
        // Start a divider drag when a left-down lands on the divider.
        if let MouseEventKind::Down(MouseButton::Left) = mouse.kind
            && let Some((drect, _)) = self.divider
            && point_in(drect, mouse.column, mouse.row)
        {
            self.dragging_divider = true;
            return true;
        }
        // Inside the pane content rect: a click focuses it; mouse events
        // forward to the child when focused and it requested tracking.
        if let Some(prect) = self.pane_rect
            && point_in(prect, mouse.column, mouse.row)
        {
            if matches!(mouse.kind, MouseEventKind::Down(_)) {
                self.pane_focused = true;
            }
            if self.pane_focused
                && let Some(pane) = self.pane.as_mut()
            {
                pane.forward_mouse(mouse, prect);
            }
            return true;
        }
        false
    }

    /// Recompute the split ratio from a divider drag to `(col, row)`.
    fn resize_split_to(&mut self, col: u16, row: u16) {
        let Some(body) = self.pane_body else {
            return;
        };
        let ratio = match self.pane_side {
            PaneSide::Left => col.saturating_sub(body.x) as f32 / (body.width.max(1) as f32),
            PaneSide::Right => {
                (body.x + body.width).saturating_sub(col) as f32 / (body.width.max(1) as f32)
            }
            PaneSide::Top => row.saturating_sub(body.y) as f32 / (body.height.max(1) as f32),
            PaneSide::Bottom => {
                (body.y + body.height).saturating_sub(row) as f32 / (body.height.max(1) as f32)
            }
            PaneSide::Full => return,
        };
        self.pane_ratio = ratio.clamp(0.15, 0.85);
    }

    /// Check the pending delayed link activation. Called on every pump
    /// tick. If the deadline has passed and the token is still current,
    /// the link is activated (browser open or SSH copy). Returns `true`
    /// when the activation fired (so the pump knows to redraw).
    pub(super) fn check_pending_link_activation(&mut self) -> bool {
        let Some(pa) = self.pending_link_activation.clone() else {
            return false;
        };
        let now = std::time::Instant::now();
        if now < pa.deadline {
            return false;
        }
        // Check the token against the link gesture's current state.
        let outcome = self.link_pointer_gesture.check_activation(pa.token, now);
        self.pending_link_activation = None;
        if let crate::tui::links::LinkGestureOutcome::Activate(url) = outcome {
            if cockpit_core::sysinfo::is_ssh() {
                match crate::clipboard::copy_plain(&url, self.clipboard_recovery) {
                    Ok(result) => {
                        let (msg, kind) = super::copy_actions::describe_delivered(
                            &result,
                            "Link copied (SSH session).".to_string(),
                        );
                        self.show_toast(msg, kind);
                    }
                    Err(error) => {
                        self.show_toast(format!("Copy failed: {error}"), ToastKind::Error)
                    }
                }
            } else {
                match crate::tui::links::open_browser(&url) {
                    Ok(()) => self.show_toast("Opened link in browser", ToastKind::Success),
                    Err(error) => {
                        self.show_toast(format!("Could not open link: {error}"), ToastKind::Error)
                    }
                }
            }
            true
        } else {
            false
        }
    }

    /// Clamp `(col, row)` into the current chat area. Used while
    /// dragging — if the user drags past the edge of the pane we
    /// pin the focus to the nearest edge cell instead of dropping
    /// the event.
    pub(super) fn clamp_to_chat_area(&self, col: u16, row: u16) -> (u16, u16) {
        let Some(area) = self.chat_area else {
            return (col, row);
        };
        let clamped_col = col.max(area.x).min(area.x + area.width.saturating_sub(1));
        let clamped_row = row.max(area.y).min(area.y + area.height.saturating_sub(1));
        (clamped_col, clamped_row)
    }

    fn transcript_hover_suppressed(&self) -> bool {
        self.dialog.is_active()
            || self.question_dialog.is_some()
            || self.daemon_prompt.is_some()
            || self.context_menu.is_some()
            || self.keys_overlay.is_some()
            || matches!(self.overlay, Overlay::ModelPicker(_))
            || self.footer_agent_picker.is_some()
            || self.footer_mode_picker.is_some()
            || matches!(
                self.overlay,
                Overlay::Stats(_)
                    | Overlay::Sessions(_)
                    | Overlay::Skills(_)
                    | Overlay::Tools(_)
                    | Overlay::GoalSettings(_)
                    | Overlay::Permissions(_)
                    | Overlay::Context(_)
                    | Overlay::Notes(_)
                    | Overlay::Leaks(_)
                    | Overlay::Sealed(_)
                    | Overlay::Diff(_)
            )
            || self.pane.is_some()
    }

    fn control_chip_at_mouse(&self, mouse: &MouseEvent) -> Option<super::render::ControlChip> {
        if !self.mouse_capture
            || self.transcript_hover_suppressed()
            || !self.mouse_in_chat_area(mouse)
        {
            return None;
        }
        let area = self.chat_area?;
        let rel = (mouse.row - area.y) as usize;
        let rel_col = mouse.column - area.x;
        self.control_chip_at(rel, rel_col)
    }

    fn affordance_target_at_mouse(&self, mouse: &MouseEvent) -> Option<AffordanceTarget> {
        if !self.mouse_capture
            || self.transcript_hover_suppressed()
            || !self.mouse_in_chat_area(mouse)
        {
            return None;
        }
        let area = self.chat_area?;
        let rel = (mouse.row - area.y) as usize;
        self.chat_row_meta
            .get(rel)
            .and_then(crate::tui::app::render::affordance_target_for_row)
    }

    fn suggestion_target_at_mouse(&self, mouse: &MouseEvent) -> Option<super::SuggestionBoxTarget> {
        if !self.mouse_capture || !matches!(self.overlay, Overlay::None) {
            return None;
        }
        self.suggestion_row_hits
            .iter()
            .find(|hit| point_in(hit.rect, mouse.column, mouse.row))
            .map(|hit| hit.target)
    }

    fn mouse_in_suggestion_box(&self, mouse: &MouseEvent) -> bool {
        self.suggestion_box_area
            .is_some_and(|area| point_in(area, mouse.column, mouse.row))
    }

    fn update_hovered_affordance(&mut self, mouse: &MouseEvent) {
        self.hovered_suggestion = self.suggestion_target_at_mouse(mouse);
        if self.hovered_suggestion.is_some() {
            self.hovered_control_chip = None;
            self.hovered_affordance = None;
            return;
        }

        self.hovered_control_chip = self.control_chip_at_mouse(mouse);
        if self.hovered_control_chip.is_some() {
            self.hovered_affordance = None;
        } else {
            self.hovered_affordance = self.affordance_target_at_mouse(mouse);
        }
    }

    fn handle_suggestion_box_mouse(&mut self, mouse: &MouseEvent) -> bool {
        if !self.mouse_in_suggestion_box(mouse) {
            return false;
        }
        match mouse.kind {
            MouseEventKind::ScrollUp => {
                if self.at_popup_active() {
                    self.scroll_at_window_by(-1);
                } else if self.slash_query().is_some() {
                    self.scroll_slash_window_by(-1);
                }
                self.hovered_suggestion = None;
                true
            }
            MouseEventKind::ScrollDown => {
                if self.at_popup_active() {
                    self.scroll_at_window_by(1);
                } else if self.slash_query().is_some() {
                    self.scroll_slash_window_by(1);
                }
                self.hovered_suggestion = None;
                true
            }
            MouseEventKind::Down(MouseButton::Left) => {
                if let Some(target) = self.suggestion_target_at_mouse(mouse) {
                    self.cancel_mouse_gesture(self.event_loop_monotonic_now);
                    self.accept_suggestion_target(target);
                    self.hovered_suggestion = None;
                }
                true
            }
            _ => true,
        }
    }

    /// True when the mouse position is inside the chat area's last-
    /// rendered rect. Returns false when the chat area hasn't been
    /// rendered yet (e.g. a dialog is open).
    pub(super) fn mouse_in_chat_area(&self, mouse: &MouseEvent) -> bool {
        let Some(area) = self.chat_area else {
            return false;
        };
        mouse.row >= area.y
            && mouse.row < area.y + area.height
            && mouse.column >= area.x
            && mouse.column < area.x + area.width
    }

    /// Scroll the chat history up (further back in time) by `n`
    /// logical lines. Clamped to `chat_total_lines - chat_visible_lines`
    /// so the top of the buffer can sit at the top of the pane but
    /// no further.
    pub(super) fn scroll_chat_up(&mut self, n: usize) {
        let max_offset = self
            .chat_total_lines
            .saturating_sub(self.chat_visible_lines);
        self.set_chat_scroll_offset_from_interaction((self.chat_scroll_offset + n).min(max_offset));
    }

    /// Scroll the chat history down (toward the live tail) by `n`
    /// logical lines. Saturates at 0 (pinned to bottom = live).
    pub(super) fn scroll_chat_down(&mut self, n: usize) {
        self.set_chat_scroll_offset_from_interaction(self.chat_scroll_offset.saturating_sub(n));
    }

    pub(super) fn build_affordance_scroll_regions(&self) -> Vec<AffordanceScrollRegion> {
        let mut regions = Vec::new();

        let mut row = 0;
        while row < self.chat_row_meta.len() {
            let Some(scroll) = self.chat_row_meta[row].reasoning_window_scroll else {
                row += 1;
                continue;
            };
            let start = row;
            while row + 1 < self.chat_row_meta.len()
                && self.chat_row_meta[row + 1]
                    .reasoning_window_scroll
                    .is_some_and(|next| next.history_index == scroll.history_index)
            {
                row += 1;
            }
            regions.push(AffordanceScrollRegion {
                target: AffordanceTarget::ReasoningWindow {
                    history_index: scroll.history_index,
                },
                row_start: start,
                row_end: row,
                offset: scroll.offset,
                max_offset: scroll.max_offset,
            });
            row += 1;
        }

        let mut row = 0;
        while row < self.chat_row_meta.len() {
            let Some(scroll) = self.chat_row_meta[row].tool_result_scroll else {
                row += 1;
                continue;
            };
            let start = row;
            while row + 1 < self.chat_row_meta.len()
                && self.chat_row_meta[row + 1]
                    .tool_result_scroll
                    .is_some_and(|next| {
                        next.history_index == scroll.history_index
                            && next.call_index == scroll.call_index
                    })
            {
                row += 1;
            }
            regions.push(AffordanceScrollRegion {
                target: AffordanceTarget::ToolCall {
                    history_index: scroll.history_index,
                    call_index: scroll.call_index,
                },
                row_start: start,
                row_end: row,
                offset: scroll.offset,
                max_offset: scroll.max_offset,
            });
            row += 1;
        }

        let mut row = 0;
        while row < self.chat_row_meta.len() {
            let Some(idx) = self.chat_row_meta[row].tool_box_target else {
                row += 1;
                continue;
            };
            let start = row;
            while row + 1 < self.chat_row_meta.len()
                && self.chat_row_meta[row + 1].tool_box_target == Some(idx)
            {
                row += 1;
            }
            if let Some(HistoryEntry::ToolBox {
                calls,
                view_offset,
                follow,
            }) = self.history.get(idx)
                && !calls.iter().any(|call| call.expanded)
                && calls.len() > crate::tui::history::TOOLBOX_VISIBLE
            {
                let max_offset = calls.len() - crate::tui::history::TOOLBOX_VISIBLE;
                let offset = if *follow {
                    max_offset
                } else {
                    (*view_offset).min(max_offset)
                };
                regions.push(AffordanceScrollRegion {
                    target: AffordanceTarget::ToolBox { history_index: idx },
                    row_start: start,
                    row_end: row,
                    offset,
                    max_offset,
                });
            }
            row += 1;
        }
        regions
    }

    fn scroll_inner_region_at_row(&mut self, rel: usize, up: bool) -> bool {
        let Some(target) = resolve_inner_scroll_target(&self.affordance_scroll_regions, rel, up)
        else {
            return false;
        };
        match target {
            AffordanceTarget::ToolBox { history_index } => {
                self.scroll_box_target(history_index, up)
            }
            AffordanceTarget::ToolCall {
                history_index,
                call_index,
            } => self.scroll_tool_call_result(history_index, call_index, up),
            AffordanceTarget::ReasoningWindow { history_index } => {
                self.scroll_reasoning_window(history_index, up)
            }
            AffordanceTarget::Chip { .. } | AffordanceTarget::Subagent { .. } => false,
        }
    }

    fn scroll_reasoning_window(&mut self, idx: usize, up: bool) -> bool {
        let Some(HistoryEntry::Agent {
            expanded,
            reasoning,
            reasoning_offset,
            ..
        }) = self.history.get_mut(idx)
        else {
            return false;
        };
        if !*expanded || reasoning.trim().is_empty() {
            return false;
        }
        let max_offset = self
            .affordance_scroll_regions
            .iter()
            .find_map(|region| match region.target {
                AffordanceTarget::ReasoningWindow { history_index } if history_index == idx => {
                    Some(region.max_offset)
                }
                _ => None,
            })
            .unwrap_or(0);
        let cur = (*reasoning_offset).min(max_offset);
        if up {
            if cur == 0 {
                return false;
            }
            *reasoning_offset = cur - 1;
            true
        } else {
            if cur >= max_offset {
                *reasoning_offset = max_offset;
                return false;
            }
            *reasoning_offset = cur + 1;
            true
        }
    }

    fn scroll_tool_call_result(&mut self, idx: usize, call_index: usize, up: bool) -> bool {
        let (expanded, has_output, offset) = match self.history.get(idx) {
            Some(HistoryEntry::ToolBox { calls, .. }) => {
                let Some(call) = calls.get(call_index) else {
                    return false;
                };
                (
                    call.expanded,
                    !call.output.is_empty() && crate::tui::history::tool_shows_output(&call.tool),
                    call.result_offset,
                )
            }
            Some(HistoryEntry::CompactBoundary {
                expanded,
                handoff,
                result_offset,
                ..
            }) if call_index == 0 => (
                *expanded,
                handoff.as_deref().is_some_and(|s| !s.is_empty()),
                *result_offset,
            ),
            _ => return false,
        };
        if !expanded || !has_output {
            return false;
        }
        let max_offset = self
            .affordance_scroll_regions
            .iter()
            .find_map(|region| match region.target {
                AffordanceTarget::ToolCall {
                    history_index,
                    call_index: region_call,
                } if history_index == idx && region_call == call_index => Some(region.max_offset),
                _ => None,
            })
            .unwrap_or(0);
        let cur = offset.min(max_offset);
        let next = if up {
            cur.checked_sub(1)
        } else if cur < max_offset {
            Some(cur + 1)
        } else {
            None
        };
        let Some(next) = next else {
            return false;
        };
        match self.history.get_mut(idx) {
            Some(HistoryEntry::ToolBox { calls, .. }) => calls[call_index].result_offset = next,
            Some(HistoryEntry::CompactBoundary { result_offset, .. }) => *result_offset = next,
            _ => return false,
        }
        true
    }

    fn scroll_box_target(&mut self, idx: usize, up: bool) -> bool {
        let Some(HistoryEntry::ToolBox {
            calls,
            view_offset,
            follow,
        }) = self.history.get_mut(idx)
        else {
            return false;
        };
        if calls.iter().any(|call| call.expanded) {
            return false;
        }
        let n = calls.len();
        if n <= crate::tui::history::TOOLBOX_VISIBLE {
            return false;
        }
        let max_offset = n - crate::tui::history::TOOLBOX_VISIBLE;
        let cur = if *follow {
            max_offset
        } else {
            (*view_offset).min(max_offset)
        };
        if up {
            if cur == 0 {
                return false;
            }
            *follow = false;
            *view_offset = cur - 1;
            true
        } else {
            if *follow {
                return false;
            }
            let next = cur + 1;
            if next >= max_offset {
                *view_offset = max_offset;
                *follow = true;
            } else {
                *view_offset = next;
            }
            true
        }
    }

    /// Toggle the expansion of the tool call under chat-relative row `rel`.
    /// Returns whether a call was toggled.
    pub(super) fn toggle_tool_call_at_row(&mut self, rel: usize) -> bool {
        let Some((idx, call_index)) = self
            .chat_row_meta
            .get(rel)
            .and_then(|meta| meta.tool_call_target)
        else {
            return false;
        };
        if let Some(HistoryEntry::ToolBox { calls, follow, .. }) = self.history.get_mut(idx)
            && let Some(call) = calls.get_mut(call_index)
        {
            call.expanded = !call.expanded;
            if !call.expanded {
                call.result_offset = 0;
                *follow = true;
            }
            return true;
        }
        if call_index == 0
            && let Some(HistoryEntry::CompactBoundary {
                expanded,
                result_offset,
                ..
            }) = self.history.get_mut(idx)
        {
            *expanded = !*expanded;
            if !*expanded {
                *result_offset = 0;
            }
            return true;
        }
        false
    }

    /// Translate an absolute mouse position into a `(line, col)` in
    /// the composer's text buffer, or `None` if the click landed
    /// outside the input area. The inner-rect calculation mirrors
    /// the render path: a 1-cell border on every side. When the queue
    /// strip is above, the input top border is overlapped by the queue
    /// bottom border but still occupies the input rect's first row.
    /// Continuation lines render with `prefix_width` spaces of indent
    /// so the click-to-col math is uniform across lines.
    pub(super) fn composer_cursor_target_for_click(
        &self,
        outer: Rect,
        mouse: &MouseEvent,
    ) -> Option<(usize, usize)> {
        if mouse.row < outer.y || mouse.row >= outer.y + outer.height {
            return None;
        }
        if mouse.column < outer.x || mouse.column >= outer.x + outer.width {
            return None;
        }
        let top_border: u16 = 1;
        let bottom_border: u16 = 1;
        let inner_top = outer.y.saturating_add(top_border);
        let inner_bottom = outer.y + outer.height.saturating_sub(bottom_border);
        let inner_left = outer.x.saturating_add(1);
        let inner_right = outer.x + outer.width.saturating_sub(1);
        if mouse.row < inner_top || mouse.row >= inner_bottom {
            return None;
        }
        if mouse.column < inner_left || mouse.column >= inner_right {
            return None;
        }
        let row_rel = (mouse.row - inner_top) as usize;
        // Every visible row (first or continuation) has the prefix /
        // indent at the left edge of the inner rect.
        let col_rel = (mouse.column - inner_left) as usize;
        Some((row_rel, col_rel))
    }

    pub(super) fn next_mouse_gesture_deadline(&self) -> Option<std::time::Duration> {
        self.mouse_gesture_state.next_deadline()
    }

    pub(super) async fn drain_ready_terminal_input_before_gesture_timer(
        &mut self,
        terminal_input: &mut crate::tui::input_source::TerminalInput,
    ) -> anyhow::Result<bool> {
        terminal_input
            .drain_ready(crate::tui::input_source::MAX_DRAIN_PER_PASS, |item| {
                self.handle_event_stream_item(item)
            })
            .await
    }

    pub(super) fn service_due_mouse_gesture_timers(&mut self, now: std::time::Duration) {
        self.event_loop_monotonic_now = now;
        let Some(deadline) = self.mouse_gesture_state.pending_copy_deadline else {
            return;
        };
        if now < deadline {
            return;
        }
        let Some(token) = self.mouse_gesture_state.copy_token else {
            return;
        };
        let Some(press_generation) = self.mouse_gesture_state.copy_press_generation else {
            return;
        };
        self.reduce_mouse_gesture(mouse_gesture::GestureInput::CopyTimerFired {
            token,
            press_generation,
            now,
        });
    }

    pub(super) fn invalidate_mouse_gesture(
        &mut self,
        reason: MouseGestureInvalidation,
        now: std::time::Duration,
    ) {
        let input = match reason {
            MouseGestureInvalidation::Cancel => mouse_gesture::GestureInput::Cancel { now },
            MouseGestureInvalidation::ViewChange => mouse_gesture::GestureInput::ViewChange { now },
            MouseGestureInvalidation::TerminalChange => {
                mouse_gesture::GestureInput::TerminalChange { now }
            }
        };
        self.reduce_mouse_gesture(input);
        self.abort_pending_mouse_copies();
        self.invalidate_primary_paste();
    }

    pub(super) fn cancel_mouse_gesture(&mut self, now: std::time::Duration) {
        self.invalidate_mouse_gesture(MouseGestureInvalidation::Cancel, now);
    }

    pub(super) fn abort_pending_mouse_copies(&mut self) {
        let ids: Vec<_> = self
            .pending_mouse_copies
            .drain()
            .map(|(id, _)| id)
            .collect();
        for id in ids {
            self.async_actions.abort_id(id);
        }
    }

    pub(super) fn drop_mouse_copy_ui_ownership(&mut self) {
        self.pending_mouse_copies.clear();
        self.mouse_gesture_state.invalidate_copy();
    }

    pub(super) fn tombstone_cancelled_mouse_copies(&mut self, cancelled: &[AsyncActionResult]) {
        for result in cancelled {
            if matches!(
                result.kind,
                crate::tui::async_action::AsyncActionKind::Blocking("mouse.copy")
            ) {
                self.pending_mouse_copies.remove(&result.id);
            }
        }
    }

    pub(super) fn chat_semantic_target_at(
        &self,
        cell: mouse_gesture::Cell,
    ) -> mouse_gesture::SemanticTarget {
        let Some(area) = self.chat_area else {
            return mouse_gesture::SemanticTarget::NonSelectable;
        };
        if cell.0 < area.x
            || cell.0 >= area.x.saturating_add(area.width)
            || cell.1 < area.y
            || cell.1 >= area.y.saturating_add(area.height)
        {
            return mouse_gesture::SemanticTarget::NonSelectable;
        }
        let rel_row = cell.1.saturating_sub(area.y) as usize;
        let rel_col = cell.0.saturating_sub(area.x) as usize;
        let Some(meta) = self.chat_row_meta.get(rel_row) else {
            return mouse_gesture::SemanticTarget::NonSelectable;
        };
        if !meta.selectable
            || matches!(
                meta.row_kind,
                super::render::ChatRowKind::Padding
                    | super::render::ChatRowKind::Banner
                    | super::render::ChatRowKind::Chip
            )
        {
            return mouse_gesture::SemanticTarget::NonSelectable;
        }
        if let Some(frag_id) = meta.copy_cells.get(rel_col).copied().flatten() {
            if let Some(frag) = meta.copy_fragments.get(frag_id as usize)
                && frag.table_cell.is_some()
            {
                return mouse_gesture::SemanticTarget::TableCell {
                    cell,
                    fragment_id: frag_id,
                };
            }
            return mouse_gesture::SemanticTarget::PlainCell(cell);
        }
        if !meta.copy_cells.is_empty() {
            return mouse_gesture::SemanticTarget::NonSelectable;
        }
        mouse_gesture::SemanticTarget::PlainCell(cell)
    }

    fn materialize_gesture_selection(
        &mut self,
        request: mouse_gesture::SelectionRequest,
    ) -> Option<Selection> {
        match request.kind {
            mouse_gesture::SelectionKind::Drag => {
                self.selection_spans = None;
                Some(Selection {
                    anchor: request.anchor,
                    focus: request.focus,
                    active: request.active,
                })
            }
            mouse_gesture::SelectionKind::Word => {
                let spans = self.word_spans_at(request.anchor);
                self.selection_spans = (!spans.is_empty()).then_some(spans.clone());
                Some(selection_from_spans(&spans, request.anchor, false))
            }
            mouse_gesture::SelectionKind::Line => {
                let spans = self.line_spans_at(request.anchor);
                self.selection_spans = (!spans.is_empty()).then_some(spans.clone());
                Some(selection_from_spans(&spans, request.anchor, false))
            }
            mouse_gesture::SelectionKind::TableCell => {
                let spans = self.table_cell_spans_at(request.anchor);
                self.selection_spans = (!spans.is_empty()).then_some(spans.clone());
                Some(selection_from_spans(&spans, request.anchor, false))
            }
        }
    }

    fn word_spans_at(&self, cell: (u16, u16)) -> Vec<SelectionSpan> {
        let Some(area) = self.chat_area else {
            return vec![SelectionSpan {
                row: cell.1,
                start_col: cell.0,
                end_col: cell.0,
            }];
        };
        let rel_row = cell.1.saturating_sub(area.y) as usize;
        let rel_col = cell.0.saturating_sub(area.x) as usize;
        let Some(row) = self.chat_text_grid.get(rel_row) else {
            return vec![SelectionSpan {
                row: cell.1,
                start_col: cell.0,
                end_col: cell.0,
            }];
        };
        if row.is_empty() {
            return Vec::new();
        }
        let col = rel_col.min(row.len().saturating_sub(1));
        let wordy = row.get(col).is_some_and(|cell| is_word_cell(cell));
        let mut start = col;
        let mut end = col;
        while start > 0
            && row
                .get(start - 1)
                .is_some_and(|c| is_word_cell(c) == wordy && !c.chars().all(char::is_whitespace))
        {
            start -= 1;
        }
        while end + 1 < row.len()
            && row
                .get(end + 1)
                .is_some_and(|c| is_word_cell(c) == wordy && !c.chars().all(char::is_whitespace))
        {
            end += 1;
        }
        if row
            .get(col)
            .is_some_and(|c| c.chars().all(char::is_whitespace))
        {
            return Vec::new();
        }
        vec![SelectionSpan {
            row: cell.1,
            start_col: area.x.saturating_add(start as u16),
            end_col: area.x.saturating_add(end as u16),
        }]
    }

    fn line_spans_at(&self, cell: (u16, u16)) -> Vec<SelectionSpan> {
        let Some(area) = self.chat_area else {
            return Vec::new();
        };
        let rel_row = cell.1.saturating_sub(area.y) as usize;
        if rel_row >= self.chat_row_meta.len() {
            return Vec::new();
        }
        let mut first = rel_row;
        while first > 0
            && self
                .chat_row_meta
                .get(first)
                .is_some_and(|meta| meta.continuation)
        {
            first -= 1;
        }
        let mut last = rel_row;
        while last + 1 < self.chat_row_meta.len()
            && self
                .chat_row_meta
                .get(last + 1)
                .is_some_and(|meta| meta.continuation)
        {
            last += 1;
        }
        (first..=last)
            .filter_map(|row| {
                let grid = self.chat_text_grid.get(row)?;
                let (start, end) = content_col_bounds(grid)?;
                Some(SelectionSpan {
                    row: area.y.saturating_add(row as u16),
                    start_col: area.x.saturating_add(start as u16),
                    end_col: area.x.saturating_add(end as u16),
                })
            })
            .collect()
    }

    fn table_cell_spans_at(&self, cell: (u16, u16)) -> Vec<SelectionSpan> {
        let Some(area) = self.chat_area else {
            return Vec::new();
        };
        let rel_row = cell.1.saturating_sub(area.y) as usize;
        let rel_col = cell.0.saturating_sub(area.x) as usize;
        let Some(meta) = self.chat_row_meta.get(rel_row) else {
            return Vec::new();
        };
        let Some(frag_id) = meta.copy_cells.get(rel_col).copied().flatten() else {
            return self.word_spans_at(cell);
        };
        let Some(fragment) = meta.copy_fragments.get(frag_id as usize) else {
            return self.word_spans_at(cell);
        };
        let Some(table_cell) = fragment.table_cell else {
            return self.word_spans_at(cell);
        };
        let history_index = meta.history_index;
        let mut spans = Vec::new();
        for (row_i, row_meta) in self.chat_row_meta.iter().enumerate() {
            if row_meta.history_index != history_index {
                continue;
            }
            let mut start = None;
            let mut end = None;
            let flush =
                |spans: &mut Vec<SelectionSpan>, start: Option<usize>, end: Option<usize>| {
                    if let (Some(start), Some(end)) = (start, end) {
                        spans.push(SelectionSpan {
                            row: area.y.saturating_add(row_i as u16),
                            start_col: area.x.saturating_add(start as u16),
                            end_col: area.x.saturating_add(end as u16),
                        });
                    }
                };
            for (col_i, cell_frag) in row_meta.copy_cells.iter().enumerate() {
                let matches_cell = cell_frag
                    .and_then(|id| row_meta.copy_fragments.get(id as usize))
                    .is_some_and(|frag| frag.table_cell == Some(table_cell));
                if matches_cell {
                    if start.is_none() {
                        start = Some(col_i);
                    }
                    end = Some(col_i);
                } else if start.is_some() {
                    flush(&mut spans, start, end);
                    start = None;
                    end = None;
                }
            }
            flush(&mut spans, start, end);
        }
        spans
    }

    fn dispatch_chat_gesture(&mut self, mouse: MouseEvent) {
        let now = self.event_loop_monotonic_now;
        let cell = self.clamp_to_chat_area(mouse.column, mouse.row);
        let target = self.chat_semantic_target_at(cell);
        let input = match mouse.kind {
            MouseEventKind::Down(MouseButton::Left) => mouse_gesture::GestureInput::Press {
                button: mouse_gesture::ClickButton::Primary,
                cell,
                target,
                now,
            },
            MouseEventKind::Down(_) => mouse_gesture::GestureInput::Press {
                button: mouse_gesture::ClickButton::Other,
                cell,
                target,
                now,
            },
            MouseEventKind::Drag(MouseButton::Left) => {
                mouse_gesture::GestureInput::Move { cell, target, now }
            }
            MouseEventKind::Up(MouseButton::Left) => {
                mouse_gesture::GestureInput::Release { cell, now }
            }
            _ => return,
        };
        self.reduce_mouse_gesture(input);
    }

    fn reduce_mouse_gesture(
        &mut self,
        input: mouse_gesture::GestureInput,
    ) -> Vec<mouse_gesture::GestureEffect> {
        let cfg = mouse_gesture::GestureConfig {
            copy_on_release: self.copy_on_release,
        };
        let state = std::mem::take(&mut self.mouse_gesture_state);
        let (next, effects) = mouse_gesture::reduce(state, &cfg, &input);
        self.mouse_gesture_state = next;
        self.apply_gesture_effects(&effects);
        effects
    }

    fn apply_gesture_effects(&mut self, effects: &[mouse_gesture::GestureEffect]) {
        for effect in effects {
            match effect {
                mouse_gesture::GestureEffect::None
                | mouse_gesture::GestureEffect::ScheduleActivation { .. }
                | mouse_gesture::GestureEffect::CancelActivation { .. }
                | mouse_gesture::GestureEffect::Activate { .. }
                | mouse_gesture::GestureEffect::Notify { .. }
                | mouse_gesture::GestureEffect::ScheduleCopyTimer { .. } => {}
                mouse_gesture::GestureEffect::Select(request) => {
                    self.selection = self.materialize_gesture_selection(*request);
                }
                mouse_gesture::GestureEffect::ClearSelection => {
                    self.selection = None;
                    self.selection_spans = None;
                }
                mouse_gesture::GestureEffect::ScheduleCopy {
                    token,
                    press_generation,
                    ..
                } => {
                    self.schedule_mouse_copy(*token, *press_generation);
                }
            }
        }
    }

    pub(super) fn snapshot_selection_text(&self) -> String {
        let Some(sel) = self.selection else {
            return String::new();
        };
        let Some(area) = self.chat_area else {
            return String::new();
        };
        if self.chat_text_grid.len() != area.height as usize
            || self
                .chat_text_grid
                .iter()
                .any(|row| row.len() != area.width as usize)
        {
            return String::new();
        }
        extract_selection_semantic_shaped(
            &self.chat_row_meta,
            area,
            sel,
            self.selection_spans.as_deref(),
        )
        .unwrap_or_else(|| {
            extract_selection_plaintext_shaped(
                &self.chat_text_grid,
                &self.chat_row_meta,
                area,
                sel,
                self.selection_spans.as_deref(),
            )
        })
    }

    fn schedule_mouse_copy(&mut self, token: u64, press_generation: u64) {
        let text = self.snapshot_selection_text();
        let char_count = text.chars().count();
        #[cfg(test)]
        if self.arm_controllable_mouse_copy {
            self.start_controllable_mouse_copy(token, press_generation, char_count);
            return;
        }
        let start = if text.is_empty() {
            self.async_actions.start(
                crate::tui::async_action::AsyncActionKind::Blocking("mouse.copy"),
                crate::tui::async_action::AsyncActionPolicy::Dedupe(
                    crate::tui::async_action::AsyncActionKey::new("mouse.copy"),
                ),
                async move {
                    Ok(crate::tui::async_action::AsyncActionPayload::MouseCopy(
                        crate::tui::async_action::MouseCopyResult::Empty,
                    ))
                },
            )
        } else {
            let recovery = self.clipboard_recovery;
            self.async_actions.start_blocking(
                crate::tui::async_action::AsyncActionKind::Blocking("mouse.copy"),
                crate::tui::async_action::AsyncActionPolicy::Dedupe(
                    crate::tui::async_action::AsyncActionKey::new("mouse.copy"),
                ),
                move || {
                    Ok(crate::tui::async_action::AsyncActionPayload::MouseCopy(
                        map_delivery_to_mouse_copy(&text, recovery),
                    ))
                },
            )
        };
        self.own_started_mouse_copy(start, token, press_generation, char_count);
    }

    fn own_started_mouse_copy(
        &mut self,
        start: crate::tui::async_action::AsyncActionStart,
        token: u64,
        press_generation: u64,
        char_count: usize,
    ) {
        match start {
            crate::tui::async_action::AsyncActionStart::Started(id) => {
                self.pending_mouse_copies.insert(
                    id,
                    PendingMouseCopy {
                        token,
                        press_generation,
                        char_count,
                    },
                );
            }
            crate::tui::async_action::AsyncActionStart::Existing(_) => {
                let effects =
                    self.reduce_mouse_gesture(mouse_gesture::GestureInput::CopyRejected {
                        token,
                        press_generation,
                        now: self.event_loop_monotonic_now,
                    });
                if effects
                    .iter()
                    .any(|effect| matches!(effect, mouse_gesture::GestureEffect::Notify { .. }))
                {
                    self.show_mouse_copy_toast(
                        crate::tui::async_action::MouseCopyResult::Failed,
                        char_count,
                    );
                }
            }
        }
    }

    #[cfg(test)]
    pub(super) fn start_controllable_mouse_copy(
        &mut self,
        token: u64,
        press_generation: u64,
        char_count: usize,
    ) -> Option<crate::tui::async_action::AsyncActionId> {
        let (start, runner) = self.async_actions.start_controllable_mouse_copy();
        match start {
            crate::tui::async_action::AsyncActionStart::Started(id) => {
                self.pending_mouse_copies.insert(
                    id,
                    PendingMouseCopy {
                        token,
                        press_generation,
                        char_count,
                    },
                );
                self.controllable_mouse_copy = Some(runner);
                Some(id)
            }
            crate::tui::async_action::AsyncActionStart::Existing(_) => {
                self.reduce_mouse_gesture(mouse_gesture::GestureInput::CopyRejected {
                    token,
                    press_generation,
                    now: self.event_loop_monotonic_now,
                });
                None
            }
        }
    }

    pub(super) fn apply_mouse_copy_action_result(&mut self, result: AsyncActionResult) {
        let Some(pending) = self.pending_mouse_copies.remove(&result.id) else {
            return;
        };
        let now = self.event_loop_monotonic_now;
        match result.payload {
            Ok(crate::tui::async_action::AsyncActionPayload::MouseCopy(copy_result)) => {
                let outcome = match copy_result {
                    crate::tui::async_action::MouseCopyResult::Confirmed => {
                        mouse_gesture::CopyOutcome::Confirmed
                    }
                    crate::tui::async_action::MouseCopyResult::Unverified => {
                        mouse_gesture::CopyOutcome::Unverified
                    }
                    crate::tui::async_action::MouseCopyResult::TooLarge => {
                        mouse_gesture::CopyOutcome::TooLarge
                    }
                    crate::tui::async_action::MouseCopyResult::Failed => {
                        mouse_gesture::CopyOutcome::Failed
                    }
                    crate::tui::async_action::MouseCopyResult::Empty => {
                        mouse_gesture::CopyOutcome::Empty
                    }
                };
                let effects =
                    self.reduce_mouse_gesture(mouse_gesture::GestureInput::CopyCompleted {
                        token: pending.token,
                        press_generation: pending.press_generation,
                        outcome,
                        now,
                    });
                if effects
                    .iter()
                    .any(|effect| matches!(effect, mouse_gesture::GestureEffect::Notify { .. }))
                {
                    self.show_mouse_copy_toast(copy_result, pending.char_count);
                }
            }
            Ok(_) | Err(_) => {
                let effects =
                    self.reduce_mouse_gesture(mouse_gesture::GestureInput::CopyRejected {
                        token: pending.token,
                        press_generation: pending.press_generation,
                        now,
                    });
                if effects
                    .iter()
                    .any(|effect| matches!(effect, mouse_gesture::GestureEffect::Notify { .. }))
                {
                    self.show_mouse_copy_toast(
                        crate::tui::async_action::MouseCopyResult::Failed,
                        pending.char_count,
                    );
                }
            }
        }
    }

    fn show_mouse_copy_toast(
        &mut self,
        result: crate::tui::async_action::MouseCopyResult,
        char_count: usize,
    ) {
        match result {
            crate::tui::async_action::MouseCopyResult::Confirmed => self.show_toast(
                format!("Copied {char_count} chars to clipboard."),
                ToastKind::Success,
            ),
            crate::tui::async_action::MouseCopyResult::Unverified => self.show_toast(
                format!(
                    "Copied {char_count} chars to clipboard. (unverified — could not confirm delivery)"
                ),
                ToastKind::Warning,
            ),
            crate::tui::async_action::MouseCopyResult::TooLarge => self.show_toast(
                "Selection too large to copy (max sequence size) — copy a smaller range.",
                ToastKind::Error,
            ),
            crate::tui::async_action::MouseCopyResult::Failed => {
                self.show_toast("Copy failed.", ToastKind::Error)
            }
            crate::tui::async_action::MouseCopyResult::Empty => {}
        }
    }
}

fn map_delivery_to_mouse_copy(
    text: &str,
    recovery: crate::clipboard::ClipboardRecovery,
) -> crate::tui::async_action::MouseCopyResult {
    match crate::clipboard::copy_plain(text, recovery) {
        Ok(result) => match result.confidence {
            crate::clipboard::Confidence::Confirmed => {
                crate::tui::async_action::MouseCopyResult::Confirmed
            }
            crate::clipboard::Confidence::Unverified => {
                crate::tui::async_action::MouseCopyResult::Unverified
            }
            crate::clipboard::Confidence::Failed => {
                crate::tui::async_action::MouseCopyResult::Failed
            }
        },
        Err(crate::clipboard::CopyError::TooLarge { .. }) => {
            crate::tui::async_action::MouseCopyResult::TooLarge
        }
        Err(crate::clipboard::CopyError::Empty) => crate::tui::async_action::MouseCopyResult::Empty,
        Err(_) => crate::tui::async_action::MouseCopyResult::Failed,
    }
}

fn is_word_cell(cell: &str) -> bool {
    cell.chars()
        .any(|ch| ch.is_alphanumeric() || ch == '_' || ch == '-')
}

fn content_col_bounds(row: &[String]) -> Option<(usize, usize)> {
    let first = row
        .iter()
        .position(|c| !c.chars().all(|ch| ch.is_whitespace()))?;
    let last = row
        .iter()
        .rposition(|c| !c.chars().all(|ch| ch.is_whitespace()))?;
    Some((first, last))
}

fn selection_from_spans(spans: &[SelectionSpan], fallback: (u16, u16), active: bool) -> Selection {
    match (spans.first(), spans.last()) {
        (Some(first), Some(last)) => Selection {
            anchor: (first.start_col, first.row),
            focus: (last.end_col, last.row),
            active,
        },
        _ => Selection {
            anchor: fallback,
            focus: fallback,
            active,
        },
    }
}

pub(super) fn extract_selection_plaintext_shaped(
    grid: &[Vec<String>],
    row_meta: &[super::render::ChatRowMeta],
    area: Rect,
    sel: Selection,
    spans: Option<&[SelectionSpan]>,
) -> String {
    if let Some(spans) = spans.filter(|spans| !spans.is_empty()) {
        return extract_selection_plaintext_from_spans(grid, row_meta, area, spans);
    }
    extract_selection_plaintext(grid, row_meta, area, sel)
}

fn extract_selection_plaintext_from_spans(
    grid: &[Vec<String>],
    row_meta: &[super::render::ChatRowMeta],
    area: Rect,
    spans: &[SelectionSpan],
) -> String {
    use crate::tui::history::AGENT_INDENT;
    let mut out = String::new();
    let mut first_emitted = true;
    for span in spans {
        let grid_row = span.row.saturating_sub(area.y) as usize;
        let Some(meta) = row_meta.get(grid_row) else {
            continue;
        };
        if !meta.selectable {
            continue;
        }
        let Some(row) = grid.get(grid_row) else {
            continue;
        };
        let first_col = span.start_col.saturating_sub(area.x) as usize;
        let last_col = span.end_col.saturating_sub(area.x) as usize;
        let mut line = String::new();
        for col in first_col..=last_col.min(row.len().saturating_sub(1)) {
            if let Some(symbol) = row.get(col) {
                line.push_str(symbol);
            }
        }
        let trimmed = line.trim_end_matches(' ').to_string();
        let leading_spaces = trimmed.chars().take_while(|c| *c == ' ').count();
        let strip = leading_spaces.min(AGENT_INDENT);
        let stripped: String = trimmed.chars().skip(strip).collect();
        if first_emitted {
            first_emitted = false;
        } else {
            out.push(if meta.continuation { ' ' } else { '\n' });
        }
        out.push_str(&stripped);
    }
    out
}

pub(super) fn extract_selection_semantic_shaped(
    row_meta: &[super::render::ChatRowMeta],
    area: Rect,
    sel: Selection,
    spans: Option<&[SelectionSpan]>,
) -> Option<String> {
    if let Some(spans) = spans.filter(|spans| !spans.is_empty()) {
        return extract_selection_semantic_from_spans(row_meta, area, spans);
    }
    extract_selection_semantic(row_meta, area, sel)
}

fn extract_selection_semantic_from_spans(
    row_meta: &[super::render::ChatRowMeta],
    area: Rect,
    spans: &[SelectionSpan],
) -> Option<String> {
    let mut out = String::new();
    let mut last_identity: Option<(Option<usize>, usize)> = None;
    let mut last_message = None;
    let mut emitted_row = false;
    let mut saw_semantic_row = false;
    for span in spans {
        let row_index = span.row.saturating_sub(area.y) as usize;
        let meta = row_meta.get(row_index)?;
        if meta.copy_target.is_some() {
            if !meta.copy_provenance_present {
                return None;
            }
            saw_semantic_row = true;
        } else if meta.selectable {
            return None;
        }
        let first_col = span.start_col.saturating_sub(area.x) as usize;
        let last_col = span.end_col.saturating_sub(area.x) as usize;
        let mut row_emitted = false;
        let mut row_table_cell = None;
        for fragment_id in meta
            .copy_cells
            .get(first_col..=last_col.min(meta.copy_cells.len().saturating_sub(1)))
            .unwrap_or_default()
            .iter()
            .flatten()
        {
            let fragment = meta.copy_fragments.get(*fragment_id as usize)?;
            let identity = (meta.history_index, fragment.id);
            if last_identity == Some(identity) {
                continue;
            }
            if !row_emitted && emitted_row {
                let cross_message = usize::from(last_message != meta.history_index);
                for _ in 0..meta.copy_newlines_before.max(cross_message) {
                    out.push('\n');
                }
            }
            if row_emitted
                && let (Some(previous), Some(current)) = (row_table_cell, fragment.table_cell)
                && previous != current
            {
                out.push('\t');
            }
            out.push_str(&fragment.text);
            last_identity = Some(identity);
            row_emitted = true;
            emitted_row = true;
            last_message = meta.history_index;
            row_table_cell = fragment.table_cell.or(row_table_cell);
        }
        if meta.copy_fallback_if_unmapped {
            return None;
        }
    }
    saw_semantic_row.then_some(out)
}

#[cfg(test)]
mod affordance_hover_tests {
    use super::{
        AUTOCOMPLETE_ROWS, AffordanceScrollRegion, AffordanceTarget, App, SuggestionBoxKind,
        SuggestionBoxRowHit, SuggestionBoxTarget, resolve_inner_scroll_target,
    };
    use crate::tui::app::render::{
        ChatRowKind, ChatRowMeta, ControlChip, PinHit, ReasoningScrollMeta, ToolResultScrollMeta,
    };
    use crate::tui::history::{HistoryEntry, ToolCall, ToolCallState};
    use crate::tui::settings::Dialog;
    use crossterm::event::{KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
    use ratatui::layout::Rect;

    async fn await_at_suggestions(app: &mut App) {
        let kind = app.autocomplete_blocking_operation().action_kind();
        while app.async_actions.has_pending_kind(&kind) {
            let notify = app.async_actions.notifier();
            let notified = notify.notified();
            app.drain_async_actions();
            if !app.async_actions.has_pending_kind(&kind) {
                break;
            }
            notified.await;
        }
    }

    fn meta(
        chip_target: Option<usize>,
        tool_box_target: Option<usize>,
        tool_call_target: Option<(usize, usize)>,
        reasoning_window_target: Option<usize>,
    ) -> ChatRowMeta {
        ChatRowMeta {
            history_index: None,
            row_kind: ChatRowKind::Other,
            copy_target: None,
            chip_target,
            subagent_target: None,
            tool_box_target,
            tool_call_target,
            tool_result_scroll: None,
            reasoning_window_scroll: None,
            reasoning_window_target,
            diff_path: None,
            pin_hit: None,
            fork_hit: None,
            continuation: false,
            selectable: false,
            copy_cells: Vec::new(),
            copy_fragments: std::rc::Rc::new(Vec::new()),
            copy_newlines_before: 0,
            copy_fallback_if_unmapped: false,
            copy_provenance_present: false,
        }
    }

    fn tool_call(call_id: &str) -> ToolCall {
        ToolCall {
            call_id: call_id.to_string(),
            tool: "bash".to_string(),
            summary: call_id.to_string(),
            full_input: call_id.to_string(),
            output: String::new(),
            expanded: false,
            result_offset: 0,
            state: ToolCallState::Success,
            hint: None,
            progress: None,
            mcp_child: None,
        }
    }

    fn reasoning_agent(offset: usize) -> HistoryEntry {
        HistoryEntry::Agent {
            name: "agent".to_string(),
            text: "answer".to_string(),
            reasoning: "thinking".to_string(),
            timestamp: chrono::Local::now(),
            expanded: true,
            reasoning_offset: offset,
            think_duration: None,
            seq: None,
            performance: None,
            performance_expanded: false,
        }
    }

    fn moved(row: u16) -> MouseEvent {
        MouseEvent {
            kind: MouseEventKind::Moved,
            column: 6,
            row,
            modifiers: KeyModifiers::empty(),
        }
    }

    #[test]
    fn moved_mouse_resolves_chat_rows_to_affordance_targets() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        app.mouse_capture = true;
        app.daemon_prompt = None;
        app.dialog = Dialog::None;
        app.chat_area = Some(Rect::new(5, 10, 20, 5));
        app.chat_row_meta = vec![
            meta(Some(1), None, None, None),
            meta(None, Some(2), None, None),
            meta(None, Some(3), Some((3, 4)), None),
            meta(None, None, None, Some(5)),
            meta(None, None, None, None),
        ];

        app.handle_mouse(moved(10));
        assert_eq!(
            app.hovered_affordance,
            Some(AffordanceTarget::Chip { history_index: 1 })
        );
        app.handle_mouse(moved(11));
        assert_eq!(
            app.hovered_affordance,
            Some(AffordanceTarget::ToolBox { history_index: 2 })
        );
        app.handle_mouse(moved(12));
        assert_eq!(
            app.hovered_affordance,
            Some(AffordanceTarget::ToolCall {
                history_index: 3,
                call_index: 4,
            })
        );
        app.handle_mouse(moved(13));
        assert_eq!(
            app.hovered_affordance,
            Some(AffordanceTarget::ReasoningWindow { history_index: 5 })
        );
        app.handle_mouse(moved(14));
        assert_eq!(app.hovered_affordance, None);
    }

    #[test]
    fn moved_mouse_clears_hover_when_capture_is_off() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        app.mouse_capture = false;
        app.hovered_affordance = Some(AffordanceTarget::Chip { history_index: 1 });
        app.hovered_control_chip = Some(ControlChip::Fork { seq: 42 });
        app.chat_area = Some(Rect::new(5, 10, 20, 1));
        app.chat_row_meta = vec![meta(Some(1), None, None, None)];

        app.handle_mouse(moved(10));

        assert_eq!(app.hovered_affordance, None);
        assert_eq!(app.hovered_control_chip, None);
    }

    #[test]
    fn moved_mouse_resolves_control_chip_by_column_before_row_hover() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        app.mouse_capture = true;
        app.daemon_prompt = None;
        app.dialog = Dialog::None;
        app.chat_area = Some(Rect::new(5, 10, 40, 1));
        let mut row = meta(Some(7), None, None, None);
        row.fork_hit = Some(PinHit {
            seq: 42,
            col_start: 8,
            col_end: 14,
        });
        row.pin_hit = Some(PinHit {
            seq: 42,
            col_start: 15,
            col_end: 20,
        });
        app.chat_row_meta = vec![row];
        let mouse_at = |column| MouseEvent {
            kind: MouseEventKind::Moved,
            column,
            row: 10,
            modifiers: KeyModifiers::empty(),
        };

        app.handle_mouse(mouse_at(5 + 9));
        assert_eq!(
            app.hovered_control_chip,
            Some(ControlChip::Fork { seq: 42 })
        );
        assert_eq!(app.hovered_affordance, None);

        app.handle_mouse(mouse_at(5 + 16));
        assert_eq!(app.hovered_control_chip, Some(ControlChip::Pin { seq: 42 }));
        assert_eq!(app.hovered_affordance, None);

        app.handle_mouse(mouse_at(5 + 14));
        assert_eq!(app.hovered_control_chip, None);
        assert_eq!(
            app.hovered_affordance,
            Some(AffordanceTarget::Chip { history_index: 7 })
        );
    }

    fn suggestion_target(kind: SuggestionBoxKind, index: usize) -> SuggestionBoxTarget {
        SuggestionBoxTarget { kind, index }
    }

    fn suggestion_click(row: u16) -> MouseEvent {
        MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: 6,
            row,
            modifiers: KeyModifiers::empty(),
        }
    }

    #[test]
    fn suggestion_hover_tracks_rows_and_clears_on_leave() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        app.mouse_capture = true;
        app.suggestion_box_area = Some(Rect::new(0, 5, 40, 4));
        app.suggestion_row_hits = vec![SuggestionBoxRowHit {
            target: suggestion_target(SuggestionBoxKind::Slash, 2),
            rect: Rect::new(2, 6, 36, 1),
        }];

        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::Moved,
            column: 6,
            row: 6,
            modifiers: KeyModifiers::empty(),
        });
        assert_eq!(
            app.hovered_suggestion,
            Some(suggestion_target(SuggestionBoxKind::Slash, 2))
        );

        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::Moved,
            column: 6,
            row: 9,
            modifiers: KeyModifiers::empty(),
        });
        assert_eq!(app.hovered_suggestion, None);
    }

    #[test]
    fn wheel_over_slash_suggestions_scrolls_window_not_selection() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        app.mouse_capture = true;
        app.composer.set("/".to_string());
        app.reset_slash_window();
        assert!(app.slash_suggestions().len() > AUTOCOMPLETE_ROWS as usize);
        app.suggestion_box_area = Some(Rect::new(0, 5, 80, 8));

        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::ScrollDown,
            column: 6,
            row: 6,
            modifiers: KeyModifiers::empty(),
        });

        assert_eq!(app.slash_selected, 0);
        assert_eq!(app.slash_scroll, 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn wheel_over_at_suggestions_scrolls_window_not_selection() {
        let tmp = tempfile::tempdir().unwrap();
        for name in [
            "alpha.rs",
            "beta.rs",
            "gamma.rs",
            "delta.rs",
            "epsilon.rs",
            "zeta.rs",
            "eta.rs",
            "theta.rs",
            "iota.rs",
        ] {
            std::fs::write(tmp.path().join(name), "").unwrap();
        }
        let mut app = App::new(Some(tmp.path()), false);
        app.mouse_capture = true;
        app.composer.set("@".to_string());
        app.reset_at_window();
        await_at_suggestions(&mut app).await;
        assert!(app.at_suggestions().len() > AUTOCOMPLETE_ROWS as usize);
        app.suggestion_box_area = Some(Rect::new(0, 5, 80, 8));

        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::ScrollDown,
            column: 6,
            row: 6,
            modifiers: KeyModifiers::empty(),
        });

        assert_eq!(app.at_selected, 0);
        assert_eq!(app.at_scroll, 1);
    }

    #[test]
    fn click_slash_suggestion_completes_without_dispatching() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        app.mouse_capture = true;
        app.composer.set("/".to_string());
        app.reset_slash_window();
        let expected = app.slash_suggestions()[1].completion_text();
        app.suggestion_box_area = Some(Rect::new(0, 5, 80, 8));
        app.suggestion_row_hits = vec![SuggestionBoxRowHit {
            target: suggestion_target(SuggestionBoxKind::Slash, 1),
            rect: Rect::new(2, 6, 76, 1),
        }];

        app.handle_mouse(suggestion_click(6));

        assert_eq!(app.composer.text(), expected);
        assert!(app.history.is_empty());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn click_at_file_finalizes_and_click_at_dir_descends() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("alpha.rs"), "").unwrap();
        std::fs::create_dir(tmp.path().join("beta")).unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        app.mouse_capture = true;
        app.composer.set("@alpha".to_string());
        app.reset_at_window();
        await_at_suggestions(&mut app).await;
        let file_index = app
            .at_suggestions()
            .iter()
            .position(|s| s.display == "alpha.rs")
            .unwrap();
        app.suggestion_box_area = Some(Rect::new(0, 5, 80, 4));
        app.suggestion_row_hits = vec![SuggestionBoxRowHit {
            target: suggestion_target(SuggestionBoxKind::At, file_index),
            rect: Rect::new(2, 6, 76, 1),
        }];

        app.handle_mouse(suggestion_click(6));
        assert_eq!(app.composer.text(), "@alpha.rs ");
        assert!(app.at_dismissed);

        app.composer.set("@beta".to_string());
        app.at_dismissed = false;
        app.reset_at_window();
        await_at_suggestions(&mut app).await;
        let dir_index = app
            .at_suggestions()
            .iter()
            .position(|s| s.display == "beta/")
            .unwrap();
        app.suggestion_row_hits = vec![SuggestionBoxRowHit {
            target: suggestion_target(SuggestionBoxKind::At, dir_index),
            rect: Rect::new(2, 6, 76, 1),
        }];

        app.handle_mouse(suggestion_click(6));
        assert_eq!(app.composer.text(), "@beta/");
        assert!(!app.at_dismissed);
    }

    #[test]
    fn click_toggles_only_targeted_tool_call() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        app.history = vec![HistoryEntry::ToolBox {
            calls: vec![tool_call("first"), tool_call("second")],
            view_offset: 0,
            follow: true,
        }]
        .into();
        app.chat_row_meta = vec![
            meta(None, Some(0), Some((0, 0)), None),
            meta(None, Some(0), Some((0, 1)), None),
        ];

        assert!(app.toggle_tool_call_at_row(1));
        match &app.history[0] {
            HistoryEntry::ToolBox { calls, .. } => {
                assert!(!calls[0].expanded);
                assert!(calls[1].expanded);
            }
            other => panic!("expected toolbox, got {other:?}"),
        }

        assert!(app.toggle_tool_call_at_row(1));
        match &app.history[0] {
            HistoryEntry::ToolBox { calls, .. } => {
                assert!(!calls[0].expanded);
                assert!(!calls[1].expanded);
            }
            other => panic!("expected toolbox, got {other:?}"),
        }
    }

    #[test]
    fn result_scroll_regions_are_registered_before_box_regions() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        let mut row = meta(None, Some(0), Some((0, 0)), None);
        row.tool_result_scroll = Some(ToolResultScrollMeta {
            history_index: 0,
            call_index: 0,
            offset: 1,
            max_offset: 4,
        });
        app.chat_row_meta = vec![row];
        app.history = vec![HistoryEntry::ToolBox {
            calls: vec![tool_call("first")],
            view_offset: 0,
            follow: true,
        }]
        .into();

        let regions = app.build_affordance_scroll_regions();
        assert_eq!(
            regions.first().map(|region| region.target),
            Some(AffordanceTarget::ToolCall {
                history_index: 0,
                call_index: 0,
            })
        );
    }

    #[test]
    fn inner_scroll_resolver_uses_registration_order_for_overlaps() {
        let tool_call = AffordanceTarget::ToolCall {
            history_index: 1,
            call_index: 2,
        };
        let tool_box = AffordanceTarget::ToolBox { history_index: 1 };
        let regions = [
            AffordanceScrollRegion {
                target: tool_call,
                row_start: 4,
                row_end: 4,
                offset: 1,
                max_offset: 3,
            },
            AffordanceScrollRegion {
                target: tool_box,
                row_start: 4,
                row_end: 4,
                offset: 1,
                max_offset: 3,
            },
        ];

        assert_eq!(
            resolve_inner_scroll_target(&regions, 4, true),
            Some(tool_call)
        );
    }

    #[test]
    fn reasoning_window_scrolls_until_both_edges() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        app.history = vec![reasoning_agent(0)].into();
        app.affordance_scroll_regions = vec![AffordanceScrollRegion {
            target: AffordanceTarget::ReasoningWindow { history_index: 0 },
            row_start: 2,
            row_end: 4,
            offset: 0,
            max_offset: 2,
        }];

        assert!(!app.scroll_inner_region_at_row(3, true));
        assert!(app.scroll_inner_region_at_row(3, false));
        match &app.history[0] {
            HistoryEntry::Agent {
                reasoning_offset, ..
            } => assert_eq!(*reasoning_offset, 1),
            other => panic!("expected agent, got {other:?}"),
        }

        app.affordance_scroll_regions[0].offset = 1;
        assert!(app.scroll_inner_region_at_row(3, false));
        match &app.history[0] {
            HistoryEntry::Agent {
                reasoning_offset, ..
            } => assert_eq!(*reasoning_offset, 2),
            other => panic!("expected agent, got {other:?}"),
        }

        app.affordance_scroll_regions[0].offset = 2;
        assert!(!app.scroll_inner_region_at_row(3, false));
    }

    #[test]
    fn reasoning_window_regions_register_with_shared_resolver() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        let mut row = meta(None, None, None, Some(0));
        row.reasoning_window_scroll = Some(ReasoningScrollMeta {
            history_index: 0,
            offset: 1,
            max_offset: 3,
        });
        app.chat_row_meta = vec![row];
        app.history = vec![reasoning_agent(1)].into();

        let regions = app.build_affordance_scroll_regions();
        assert_eq!(
            regions.first().map(|region| region.target),
            Some(AffordanceTarget::ReasoningWindow { history_index: 0 })
        );
        assert_eq!(regions.first().map(|region| region.offset), Some(1));
        assert_eq!(regions.first().map(|region| region.max_offset), Some(3));
    }

    #[test]
    fn inner_scroll_resolver_falls_through_at_both_edges() {
        let target = AffordanceTarget::ReasoningWindow { history_index: 7 };
        let top = [AffordanceScrollRegion {
            target,
            row_start: 3,
            row_end: 5,
            offset: 0,
            max_offset: 4,
        }];
        assert_eq!(resolve_inner_scroll_target(&top, 4, true), None);
        assert_eq!(resolve_inner_scroll_target(&top, 4, false), Some(target));

        let bottom = [AffordanceScrollRegion {
            target,
            row_start: 3,
            row_end: 5,
            offset: 4,
            max_offset: 4,
        }];
        assert_eq!(resolve_inner_scroll_target(&bottom, 4, true), Some(target));
        assert_eq!(resolve_inner_scroll_target(&bottom, 4, false), None);
        assert_eq!(resolve_inner_scroll_target(&bottom, 8, true), None);
    }
}

#[cfg(test)]
mod terminal_mode_guard_tests {
    use super::{
        DISABLE_ANY_MOUSE_MOTION, ENABLE_ANY_MOUSE_MOTION, TerminalCleanupCommand,
        TerminalModeGuard, TerminalModeSink, keyboard_enhancement_flags,
    };
    use anyhow::Result;
    use crossterm::event::KeyboardEnhancementFlags;
    use std::cell::RefCell;
    use std::rc::Rc;
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;

    #[test]
    fn any_motion_escape_sequences_are_paired() {
        assert_eq!(ENABLE_ANY_MOUSE_MOTION, "\x1b[?1003h");
        assert_eq!(DISABLE_ANY_MOUSE_MOTION, "\x1b[?1003l");
    }

    #[derive(Clone, Default)]
    struct RecordingSink {
        commands: Rc<RefCell<Vec<TerminalCleanupCommand>>>,
    }

    impl RecordingSink {
        fn commands(&self) -> Vec<TerminalCleanupCommand> {
            self.commands.borrow().clone()
        }
    }

    impl TerminalModeSink for RecordingSink {
        fn apply(&mut self, command: TerminalCleanupCommand) -> Result<()> {
            self.commands.borrow_mut().push(command);
            Ok(())
        }
    }

    #[test]
    fn guard_enabled_all_modes_cleans_every_mode_on_drop() {
        let sink = RecordingSink::default();
        let observed = sink.clone();
        {
            let mut guard = TerminalModeGuard::with_sink(sink);
            guard.mark_mouse_capture_enabled();
            guard.mark_bracketed_paste_enabled();
            guard.mark_keyboard_enhancement_pushed();
        }

        assert_eq!(
            observed.commands(),
            vec![
                TerminalCleanupCommand::DisableMouseCapture,
                TerminalCleanupCommand::DisableBracketedPaste,
                TerminalCleanupCommand::PopKeyboardEnhancementFlags,
                TerminalCleanupCommand::RestoreDefaultCursorShape,
                TerminalCleanupCommand::RestoreTerminalTitle { pushed: false },
                TerminalCleanupCommand::RestoreRatatui,
            ]
        );
    }

    #[test]
    fn requested_keyboard_enhancement_flags_match_crossterm_enhanced_event_set() {
        let flags = keyboard_enhancement_flags();
        assert!(flags.contains(KeyboardEnhancementFlags::DISAMBIGUATE_ESCAPE_CODES));
        assert!(flags.contains(KeyboardEnhancementFlags::REPORT_ALL_KEYS_AS_ESCAPE_CODES));
        assert!(flags.contains(KeyboardEnhancementFlags::REPORT_ALTERNATE_KEYS));
        assert!(flags.contains(KeyboardEnhancementFlags::REPORT_EVENT_TYPES));
    }

    #[test]
    fn guard_without_keyboard_enhancement_push_does_not_pop() {
        let sink = RecordingSink::default();
        let observed = sink.clone();
        {
            let mut guard = TerminalModeGuard::with_sink(sink);
            guard.mark_mouse_capture_enabled();
            guard.mark_bracketed_paste_enabled();
        }

        assert_eq!(
            observed.commands(),
            vec![
                TerminalCleanupCommand::DisableMouseCapture,
                TerminalCleanupCommand::DisableBracketedPaste,
                TerminalCleanupCommand::RestoreDefaultCursorShape,
                TerminalCleanupCommand::RestoreTerminalTitle { pushed: false },
                TerminalCleanupCommand::RestoreRatatui,
            ]
        );
    }

    #[test]
    fn terminal_title_cleanup_pops_when_marker_pushed() {
        let sink = RecordingSink::default();
        let observed = sink.clone();
        {
            let pushed = Arc::new(AtomicBool::new(true));
            let _guard = TerminalModeGuard::with_sink_and_title_state(sink, pushed);
        }

        assert_eq!(
            observed.commands(),
            vec![
                TerminalCleanupCommand::RestoreDefaultCursorShape,
                TerminalCleanupCommand::RestoreTerminalTitle { pushed: true },
                TerminalCleanupCommand::RestoreRatatui,
            ]
        );
    }

    #[test]
    fn explicit_cleanup_then_drop_is_idempotent() {
        let sink = RecordingSink::default();
        let observed = sink.clone();
        {
            let mut guard = TerminalModeGuard::with_sink(sink);
            guard.mark_mouse_capture_enabled();
            guard.mark_bracketed_paste_enabled();
            guard.mark_keyboard_enhancement_pushed();
            guard.cleanup().unwrap();
        }

        assert_eq!(
            observed.commands(),
            vec![
                TerminalCleanupCommand::DisableMouseCapture,
                TerminalCleanupCommand::DisableBracketedPaste,
                TerminalCleanupCommand::PopKeyboardEnhancementFlags,
                TerminalCleanupCommand::RestoreDefaultCursorShape,
                TerminalCleanupCommand::RestoreTerminalTitle { pushed: false },
                TerminalCleanupCommand::RestoreRatatui,
            ]
        );
    }

    #[test]
    fn mouse_capture_cleanup_follows_enabled_state() {
        let sink = RecordingSink::default();
        let observed = sink.clone();
        {
            let mut guard = TerminalModeGuard::with_sink(sink);
            guard.mark_bracketed_paste_enabled();
        }

        assert_eq!(
            observed.commands(),
            vec![
                TerminalCleanupCommand::DisableBracketedPaste,
                TerminalCleanupCommand::RestoreDefaultCursorShape,
                TerminalCleanupCommand::RestoreTerminalTitle { pushed: false },
                TerminalCleanupCommand::RestoreRatatui,
            ]
        );
    }
}
