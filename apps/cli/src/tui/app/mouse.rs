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
fn point_in(rect: Rect, col: u16, row: u16) -> bool {
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
        if matches!(mouse.kind, MouseEventKind::Moved) {
            if self.mouse_capture {
                let _link_hover_changed = self.link_registry.update_hover(mouse.column, mouse.row);
            } else {
                self.link_registry.clear_hover();
            }
            self.update_hovered_affordance(&mouse);
            if self.link_registry.hovered().is_some() {
                self.hovered_suggestion = None;
                self.hovered_control_chip = None;
                self.hovered_affordance = None;
            }
            return;
        }
        if self.mouse_capture
            && matches!(mouse.kind, MouseEventKind::Down(MouseButton::Left))
            && let Some(url) = self
                .link_registry
                .at(mouse.column, mouse.row)
                .map(|link| link.url.clone())
        {
            if crate::clipboard::is_ssh() {
                match crate::clipboard::copy_plain(&url) {
                    Ok(_) => self.show_toast("Link copied (SSH session)", ToastKind::Success),
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
            && matches!(mouse.kind, MouseEventKind::Down(MouseButton::Left))
            && self
                .sandbox_notice_copy_rect
                .is_some_and(|rect| point_in(rect, mouse.column, mouse.row))
        {
            self.copy_sandbox_fix_command();
            return;
        }
        if self.mouse_capture
            && matches!(mouse.kind, MouseEventKind::Down(MouseButton::Left))
            && self.auth_failure_notice.is_some()
            && self
                .auth_notice_switch_rect
                .is_some_and(|rect| point_in(rect, mouse.column, mouse.row))
        {
            self.open_model_picker();
            return;
        }
        if self.mouse_capture
            && matches!(mouse.kind, MouseEventKind::Down(MouseButton::Left))
            && self.auth_failure_notice.is_some()
            && self
                .auth_notice_fix_rect
                .is_some_and(|rect| point_in(rect, mouse.column, mouse.row))
        {
            self.open_auth_failure_provider();
            return;
        }
        // Which-key overlay (`which-key-overlay.md`): rendered on top of every
        // pane, so it intercepts the wheel first. Wheel scrolls it; every other
        // mouse event is eaten so nothing reaches the pane/chat underneath.
        if let Some(overlay) = self.keys_overlay.as_mut() {
            match mouse.kind {
                MouseEventKind::ScrollUp => overlay.scroll_up(),
                MouseEventKind::ScrollDown => overlay.scroll_down(),
                _ => {}
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
            let click = matches!(mouse.kind, MouseEventKind::Down(_));
            let wheel = matches!(
                mouse.kind,
                MouseEventKind::ScrollUp | MouseEventKind::ScrollDown
            );
            let outcome = if wheel || (self.mouse_capture && click) {
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
        // Context menu is modal too — clicks either hit an item or
        // dismiss. Wheel events while it's open are eaten so we don't
        // accidentally scroll chat underneath.
        if let Some(menu) = self.context_menu.clone() {
            match mouse.kind {
                MouseEventKind::Down(MouseButton::Left) => {
                    let full = ratatui::layout::Rect::new(0, 0, u16::MAX, u16::MAX);
                    if let Some(action) = menu.hit_test(mouse.column, mouse.row, full) {
                        self.context_menu = None;
                        self.execute_context_menu_action(action, menu.clicked_chat_row);
                    } else {
                        // Click outside the menu dismisses it without
                        // executing anything.
                        self.context_menu = None;
                    }
                }
                MouseEventKind::Down(_) | MouseEventKind::ScrollUp | MouseEventKind::ScrollDown => {
                    self.context_menu = None;
                }
                _ => {}
            }
            return;
        }

        if self.mouse_capture
            && matches!(mouse.kind, MouseEventKind::Down(MouseButton::Left))
            && let Some(hit) = self.footer_hit_areas.iter().find(|hit| {
                mouse.row >= hit.rect.y
                    && mouse.row < hit.rect.y + hit.rect.height
                    && mouse.column >= hit.rect.x
                    && mouse.column < hit.rect.x + hit.rect.width
            })
        {
            self.selection = None;
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
                crate::clipboard::is_ssh(),
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
                    self.selection = None;
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
                    self.selection = None;
                    let rel = (mouse.row - area.y) as usize;
                    if !self.scroll_inner_region_at_row(rel, false) {
                        self.scroll_chat_down(3);
                    }
                }
                return;
            }
            _ => {}
        }

        // Drag extends an in-flight selection. We only follow Left
        // drags; other button drags are ignored.
        if matches!(mouse.kind, MouseEventKind::Drag(MouseButton::Left)) {
            let clamped = self.clamp_to_chat_area(mouse.column, mouse.row);
            if let Some(sel) = self.selection.as_mut()
                && sel.active
            {
                sel.focus = clamped;
            }
            return;
        }

        // Release finalizes the selection. It persists in
        // `self.selection` until cleared (Esc, new click outside chat,
        // wheel scroll).
        if matches!(mouse.kind, MouseEventKind::Up(MouseButton::Left)) {
            if let Some(sel) = self.selection.as_mut() {
                sel.active = false;
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
            self.selection = None;
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
            self.selection = None;
            return;
        };
        // crossterm reports row/column as 0-indexed absolute terminal
        // coordinates. Translate to chat-area relative.
        if mouse.row < area.y || mouse.row >= area.y + area.height {
            self.selection = None;
            return;
        }
        if mouse.column < area.x || mouse.column >= area.x + area.width {
            self.selection = None;
            return;
        }
        let rel = (mouse.row - area.y) as usize;
        let rel_col = mouse.column - area.x;
        // Mouse control chips win (`pinned-messages` / fork-chip): the
        // `[fork]` and `[pin]`/`[unpin]` controls ride the message's own first
        // content line or top-right user-bubble border. Hit regions are exact
        // recorded column ranges, so fork, pin, and reasoning-chip clicks stay
        // distinct on a shared row.
        if self.mouse_capture
            && let Some(chip) = self.control_chip_at(rel, rel_col)
        {
            self.selection = None;
            match chip {
                super::render::ControlChip::Fork { seq } => self.fork_for_seq(seq),
                super::render::ControlChip::Pin { seq } => self.toggle_pin_for_seq(seq),
            }
            return;
        }
        if let Some(entry_idx) = self
            .chat_row_meta
            .get(rel)
            .and_then(|meta| meta.subagent_target)
        {
            self.selection = None;
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
            self.selection = None;
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
            self.selection = None;
            self.toggle_tool_call_at_row(rel);
            return;
        }
        // Non-chip chat row + left-down: start a fresh drag-select.
        // Anchor = focus = click point; mouse-drag will extend the
        // focus from here.
        self.selection = Some(Selection {
            anchor: (mouse.column, mouse.row),
            focus: (mouse.column, mouse.row),
            active: true,
        });
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
                    | Overlay::Permissions(_)
                    | Overlay::Context(_)
                    | Overlay::Notes(_)
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
                    self.selection = None;
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
        self.chat_scroll_offset = (self.chat_scroll_offset + n).min(max_offset);
    }

    /// Scroll the chat history down (toward the live tail) by `n`
    /// logical lines. Saturates at 0 (pinned to bottom = live).
    pub(super) fn scroll_chat_down(&mut self, n: usize) {
        self.chat_scroll_offset = self.chat_scroll_offset.saturating_sub(n);
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

    #[test]
    fn wheel_over_at_suggestions_scrolls_window_not_selection() {
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

    #[test]
    fn click_at_file_finalizes_and_click_at_dir_descends() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("alpha.rs"), "").unwrap();
        std::fs::create_dir(tmp.path().join("beta")).unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        app.mouse_capture = true;
        app.composer.set("@alpha".to_string());
        app.reset_at_window();
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
        }];
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
        }];

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
        app.history = vec![reasoning_agent(0)];
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
        app.history = vec![reasoning_agent(1)];

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
