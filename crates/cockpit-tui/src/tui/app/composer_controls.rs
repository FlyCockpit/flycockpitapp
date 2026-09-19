//! App wiring for the composer bottom-border control deck: state assembly,
//! picker lifecycle, generation fencing, and the empty-Enter queue ladder.

use super::input::is_modifier_only;
use super::*;
use crate::tui::composer_controls::{
    ComposerControlKind, ComposerControlLayout, ComposerControlState, ComposerLabelTier,
    plan_composer_controls, send_label,
};
use cockpit_client::presentation::ControlRequestId;
use cockpit_config::extended::ApprovalMode;
use cockpit_config::providers::{ActiveModelRef, ActiveReasoningEffort, ThinkingMode};
use cockpit_core::daemon::session_worker::{sandbox_mode_available, sandbox_mode_selectable};
use cockpit_proto::SandboxMode;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Clear, Paragraph};
use uuid::Uuid;

const ADD_MODEL_ITEM_ID: &str = "\u{0}add-model";

fn point_in(rect: Rect, col: u16, row: u16) -> bool {
    col >= rect.x && col < rect.x + rect.width && row >= rect.y && row < rect.y + rect.height
}

/// `Enter` commits. `Ctrl+M` is kept as the CR alias: under the kitty
/// keyboard protocol a literal `Ctrl+M` press is reported as
/// `Char('m')` + CONTROL instead of `KeyCode::Enter`, and it is bound
/// nowhere else. `Ctrl+J` is deliberately absent — it is the
/// session-rail focus chord (`is_session_rail_focus_chord`) and must
/// reach it while a picker is open.
fn is_picker_enter(key: &KeyEvent) -> bool {
    key.code == KeyCode::Enter
        || (key.code == KeyCode::Char('m') && key.modifiers == KeyModifiers::CONTROL)
}

/// Plain vim-style motion characters (`j`/`k`/`h`/`l`) only: the letter
/// without a chord modifier. `Ctrl+J` (rail focus) and any other
/// CONTROL/ALT combination must fall through to its chord owner instead
/// of moving a picker cursor or cycling a pill.
fn is_plain_motion(key: &KeyEvent) -> bool {
    !key.modifiers
        .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
}

fn scroll_from_track(track: Rect, row: u16, max: usize) -> usize {
    if track.height <= 1 || max == 0 {
        return 0;
    }
    let relative = row.saturating_sub(track.y).min(track.height - 1) as usize;
    let span = usize::from(track.height - 1);
    (relative * max + span / 2) / span
}

#[derive(Debug, Clone, Default)]
pub(super) struct ComposerControlUi {
    pub generation: u64,
    pub selection: Option<ComposerControlKind>,
    pub picker: Option<ComposerPicker>,
    pub layout: Option<ComposerControlLayout>,
    pub picker_rect: Option<Rect>,
    pub picker_scrollbar_rect: Option<Rect>,
    pub picker_scroll: usize,
    pub picker_view: usize,
    pub picker_scroll_drag: bool,
    pub pending: Option<PendingComposerMutation>,
    /// Set while a composer commit is dispatching so `send_daemon_request`
    /// binds the originating `ControlRequestId` and failure paths refuse
    /// this pending mutation instead of an unrelated in-flight request.
    pub dispatch_armed: bool,
}

#[derive(Debug, Clone)]
pub(super) struct PendingComposerMutation {
    pub generation: u64,
    pub session_id: Option<Uuid>,
    pub attachment_epoch: u64,
    pub kind: ComposerControlKind,
    pub request_id: Option<ControlRequestId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ComposerPickerStatus {
    Loading,
    Ready,
    Unavailable,
    Refused,
    Confirmed,
}

#[derive(Debug, Clone, Default)]
pub(super) struct ComposerPickerItem {
    pub id: String,
    pub label: String,
    pub hint: String,
    pub selectable: bool,
    pub favorite: bool,
    pub usage_count: u64,
    pub reasoning_effort: Option<cockpit_config::providers::ReasoningEffortCapability>,
    pub thinking_modes: Vec<ThinkingMode>,
    pub config_target: bool,
    pub selected_reasoning_effort: Option<cockpit_config::providers::ActiveReasoningEffort>,
    pub selected_thinking_mode: Option<ThinkingMode>,
    pub selected_prompt_cache_retention: Option<cockpit_config::providers::PromptCacheRetention>,
}

#[derive(Debug, Clone)]
pub(super) struct ComposerPickerCategory {
    pub id: String,
    pub label: String,
    pub hint: String,
    pub items: Vec<ComposerPickerItem>,
}

#[derive(Debug, Clone)]
pub(super) struct ComposerPicker {
    pub generation: u64,
    pub session_id: Option<Uuid>,
    pub attachment_epoch: u64,
    pub kind: ComposerControlKind,
    /// 0 = category list, 1 = items of `category`.
    pub level: u8,
    pub category: usize,
    pub cursor: usize,
    pub categories: Vec<ComposerPickerCategory>,
    pub status: ComposerPickerStatus,
    pub status_text: Option<String>,
}

impl ComposerPicker {
    fn current_rows(&self) -> Vec<(String, String, bool)> {
        if self.level == 0 {
            return self
                .categories
                .iter()
                .map(|c| {
                    (
                        c.label.clone(),
                        if c.hint.is_empty() {
                            "›".to_string()
                        } else {
                            c.hint.clone()
                        },
                        true,
                    )
                })
                .collect();
        }
        self.categories
            .get(self.category)
            .map(|c| {
                c.items
                    .iter()
                    .map(|item| (item.label.clone(), item.hint.clone(), item.selectable))
                    .collect()
            })
            .unwrap_or_default()
    }

    fn row_count(&self) -> usize {
        self.current_rows().len()
    }

    fn move_cursor(&mut self, delta: isize) {
        let len = self.row_count();
        if len == 0 {
            self.cursor = 0;
            return;
        }
        self.cursor = if delta < 0 {
            crate::tui::nav::wrap_prev(self.cursor, len)
        } else {
            crate::tui::nav::wrap_next(self.cursor, len)
        };
    }
}

impl App {
    /// Fence composer picker/pending UI ownership.
    ///
    /// A pending composer mutation is the picker's claim to show Applying /
    /// Confirmed. The bound `pending_control_requests` entry uniquely owns
    /// correlated in-flight slots (`pending_model_selection`, tokenizer
    /// confirm) and must stay until the outcome is observed: dropping it
    /// would orphan those slots on Rejected/NotDelivered. Every close,
    /// reconnect, session-generation, reset, terminal, and timeout path
    /// must call this so a later receipt cannot confirm the picker. The
    /// correlation is marked `fenced` rather than removed. When
    /// `refresh_if_fenced` is set and an in-flight request was fenced,
    /// displayed pills reconverge from daemon state instead of the
    /// discarded completion. Applied model selections are released
    /// independently by `ModelSelectionResult`.
    pub(super) fn invalidate_composer_control_ownership(
        &mut self,
        clear_selection: bool,
        refresh_if_fenced: bool,
    ) {
        let request_id = self
            .composer_controls
            .pending
            .take()
            .and_then(|pending| pending.request_id);
        self.composer_controls.dispatch_armed = false;
        self.composer_controls.generation = self.composer_controls.generation.wrapping_add(1);
        self.composer_controls.picker = None;
        self.composer_controls.picker_rect = None;
        self.composer_controls.picker_scrollbar_rect = None;
        self.composer_controls.picker_scroll = 0;
        self.composer_controls.picker_view = 0;
        self.composer_controls.picker_scroll_drag = false;
        if clear_selection {
            self.composer_controls.selection = None;
        }
        if let Some(request_id) = request_id {
            self.fence_pending_control_request(request_id);
            if refresh_if_fenced {
                self.request_session_setup_snapshot_refresh();
            }
        }
    }

    /// Test-only ownership fence: force a generation bump so a test can
    /// prove stale pickers/pendings are dropped across the boundary.
    #[cfg(test)]
    pub(super) fn bump_composer_control_generation(&mut self) {
        self.invalidate_composer_control_ownership(true, true);
    }

    fn composer_mutation_matches(&self, pending: &PendingComposerMutation) -> bool {
        pending.generation == self.composer_controls.generation
            && pending.session_id == self.launch.session_id
            && pending.attachment_epoch == self.visible_attachment_epoch
    }

    pub(super) fn composer_control_state(&self) -> ComposerControlState {
        let agent = if self.agent_path.is_empty() {
            crate::tui::history::agent_display_label(&self.launch.agent_name).to_string()
        } else {
            self.agent_path
                .iter()
                .map(|name| crate::tui::history::agent_display_label(name).to_string())
                .collect::<Vec<_>>()
                .join(" › ")
        };
        let compact_agent = self
            .agent_path
            .last()
            .map(|name| crate::tui::history::agent_display_label(name).to_string())
            .unwrap_or_else(|| {
                crate::tui::history::agent_display_label(&self.launch.agent_name).to_string()
            });
        let (model_full, model_compact) = match &self.launch.active_model {
            Some((provider, model)) => (format!("{provider}/{model}"), model.clone()),
            None => ("model".to_string(), "model".to_string()),
        };
        let effort = self
            .active_model_selection
            .as_ref()
            .and_then(|active| {
                active
                    .reasoning_effort
                    .as_ref()
                    .map(|effort| effort.value.clone())
                    .or_else(|| active.thinking_mode.map(|mode| mode.as_str().to_string()))
            })
            .unwrap_or_else(|| "effort".to_string());
        let approval = self.approval_mode.as_str().to_string();
        let sandbox = slash::sandbox_mode_label(self.sandbox_mode).to_string();
        ComposerControlState {
            agent_label: agent,
            model_label: model_full,
            effort_label: effort.clone(),
            approval_label: format!("permissions: {approval}"),
            sandbox_label: format!("sandbox: {sandbox}"),
            compact_agent,
            compact_model: model_compact,
            compact_effort: effort,
            compact_approval: approval,
            compact_sandbox: sandbox,
            working: self.busy,
        }
    }

    pub(super) fn paint_composer_control_deck(
        &mut self,
        frame: &mut Frame<'_>,
        area: Rect,
        border_style: Style,
    ) {
        if area.width < 2 || area.height == 0 {
            self.composer_controls.layout = None;
            return;
        }
        let state = self.composer_control_state();
        let layout = plan_composer_controls(&state, area);
        let y = layout.bottom_row();
        let buf = frame.buffer_mut();
        let dashes = "─".repeat(usize::from(area.width.saturating_sub(2)));
        buf.set_string(area.x, y, format!("╰{dashes}"), border_style);
        if area.width >= 1 {
            buf.set_string(
                area.x.saturating_add(area.width.saturating_sub(1)),
                y,
                "╯",
                border_style,
            );
        }

        use crate::tui::button::{ButtonDispatch, ButtonId, ButtonSpec};
        let selected = self.composer_controls.selection;
        let labels = match layout.tier {
            ComposerLabelTier::Full => state.full_labels_owned(),
            ComposerLabelTier::Compact => state.compact_labels_owned(),
            ComposerLabelTier::Glyph => ComposerControlKind::ALL
                .iter()
                .map(|kind| kind.glyph_label().to_string())
                .collect(),
        };
        for (kind, rect) in &layout.pill_buttons {
            let idx = ComposerControlKind::ALL
                .iter()
                .position(|k| k == kind)
                .unwrap_or(0);
            let label = labels
                .get(idx)
                .cloned()
                .unwrap_or_else(|| kind.as_str().to_string());
            let spec = ButtonSpec::new(
                ButtonId::ComposerPill(*kind),
                label,
                ButtonDispatch::ComposerPill(*kind),
            )
            .focused(selected == Some(*kind));
            let _ = self
                .button_registry
                .paint(frame, rect.x, rect.y, rect.width, spec);
        }
        if let Some(send) = layout.send_button {
            let spec = ButtonSpec::new(
                ButtonId::ComposerSend,
                send_label(state.working),
                ButtonDispatch::ComposerSend,
            );
            let _ = self
                .button_registry
                .paint(frame, send.x, send.y, send.width, spec);
        }
        self.composer_controls.layout = Some(layout);
    }

    pub(super) fn paint_composer_picker(&mut self, frame: &mut Frame<'_>) {
        self.composer_controls.picker_rect = None;
        self.composer_controls.picker_scrollbar_rect = None;
        self.composer_controls.picker_view = 0;
        if !self.composer_chrome_interactive() {
            return;
        }
        let Some(picker) = self.composer_controls.picker.clone() else {
            return;
        };
        if picker.generation != self.composer_controls.generation
            || picker.session_id != self.launch.session_id
            || picker.attachment_epoch != self.visible_attachment_epoch
        {
            self.composer_controls.picker = None;
            return;
        }
        let Some(layout) = self.composer_controls.layout.clone() else {
            return;
        };
        let Some(anchor) = layout.pill_rect(picker.kind).or(layout.send_button) else {
            return;
        };
        let rows = picker.current_rows();
        let status_line = picker_status_line(&picker);
        let inner_w = rows
            .iter()
            .map(|(label, hint, _)| {
                crate::tui::button::display_width(label)
                    .saturating_add(4)
                    .saturating_add(crate::tui::button::display_width(hint))
            })
            .max()
            .unwrap_or(16)
            .max(crate::tui::button::display_width(
                status_line.as_deref().unwrap_or(""),
            ))
            .max(44);
        let width = inner_w
            .saturating_add(3)
            .min(layout.area.width.max(16))
            .max(16);
        let body_rows = rows.len().max(1) as u16;
        let status_h = u16::from(status_line.is_some());
        let footer_h = 1;
        let height = body_rows
            .saturating_add(2)
            .saturating_add(status_h)
            .saturating_add(footer_h)
            .min(16);
        let screen = frame.area();
        let popover = crate::tui::chrome::place_popover(
            anchor,
            width,
            height,
            screen,
            crate::tui::chrome::PopoverSide::Above,
        );
        frame.render_widget(Clear, popover);
        let title = match picker.level {
            0 => format!(" {} ", picker.kind.as_str()),
            _ => picker
                .categories
                .get(picker.category)
                .map(|c| format!(" {} ", c.label))
                .unwrap_or_else(|| format!(" {} ", picker.kind.as_str())),
        };
        let block = crate::tui::chrome::rounded_block(title, true);
        let inner = block.inner(popover);
        frame.render_widget(block, popover);
        let mut row_y = inner.y;
        if let Some(status) = status_line {
            frame.render_widget(
                Paragraph::new(ratatui::text::Line::from(Span::styled(
                    status,
                    Style::default().fg(crate::tui::theme::MUTED_TEXT),
                ))),
                Rect {
                    x: inner.x,
                    y: row_y,
                    width: inner.width,
                    height: 1,
                },
            );
            row_y = row_y.saturating_add(1);
        }
        let body_height = inner
            .bottom()
            .saturating_sub(row_y)
            .saturating_sub(footer_h);
        let body = Rect::new(inner.x, row_y, inner.width, body_height);
        let view = usize::from(body.height);
        self.composer_controls.picker_view = view;
        let max_scroll = rows.len().saturating_sub(view);
        let mut scroll = self.composer_controls.picker_scroll.min(max_scroll);
        if picker.cursor < scroll {
            scroll = picker.cursor;
        } else if view > 0 && picker.cursor >= scroll.saturating_add(view) {
            scroll = picker.cursor + 1 - view;
        }
        self.composer_controls.picker_scroll = scroll;
        let content = crate::tui::chrome::scrollbar(frame, body, rows.len(), view, scroll);
        if rows.len() > view {
            self.composer_controls.picker_scrollbar_rect =
                Some(crate::tui::chrome::scrollbar_track(body));
        }

        use crate::tui::button::{ButtonDispatch, ButtonId, ButtonSpec};
        if rows.is_empty() {
            frame.render_widget(
                Paragraph::new(ratatui::text::Line::from(Span::styled(
                    "(none)",
                    Style::default().fg(crate::tui::theme::MUTED_TEXT),
                ))),
                Rect {
                    x: content.x,
                    y: body.y,
                    width: content.width,
                    height: 1,
                },
            );
        } else {
            for (index, (label, hint, selectable)) in
                rows.iter().enumerate().skip(scroll).take(view)
            {
                let y = body.y.saturating_add((index - scroll) as u16);
                let selected = picker.cursor == index;
                let item = (picker.level > 0)
                    .then(|| picker.categories.get(picker.category)?.items.get(index))
                    .flatten();
                let favorite = item.is_some_and(|item| item.favorite);
                let prefix = if selected {
                    crate::tui::chrome::selection_highlight_symbol()
                } else {
                    "  "
                };
                let label = if favorite {
                    format!("★ {label}")
                } else {
                    label.clone()
                };
                let base = if selected {
                    crate::tui::chrome::selection_style()
                } else {
                    Style::default()
                };
                let label_style = if selected {
                    base
                } else if favorite {
                    Style::default().fg(crate::tui::theme::FAVORITE_MODEL)
                } else {
                    Style::default().fg(crate::tui::theme::INK_ANSI)
                };
                let hint_style = if selected {
                    base
                } else {
                    Style::default().fg(crate::tui::theme::FOG_ANSI)
                };
                let disabled = !*selectable;
                let line = Line::from(vec![
                    Span::styled(prefix, base),
                    Span::styled(
                        label.clone(),
                        if disabled {
                            label_style.add_modifier(Modifier::DIM)
                        } else {
                            label_style
                        },
                    ),
                    Span::styled(
                        if hint.is_empty() {
                            String::new()
                        } else {
                            format!("  {hint}")
                        },
                        if disabled {
                            hint_style.add_modifier(Modifier::DIM)
                        } else {
                            hint_style
                        },
                    ),
                ]);
                let rect = Rect::new(content.x, y, content.width, 1);
                frame.render_widget(Paragraph::new(line).style(base), rect);
                let spec = ButtonSpec::new(
                    ButtonId::ComposerPickerRow { index },
                    label,
                    ButtonDispatch::ComposerPickerRow { index },
                )
                .focused(selected)
                .enabled(*selectable);
                self.button_registry.register(rect, spec);
            }
        }
        let footer = match picker.kind {
            ComposerControlKind::Model => "↑/↓ move · enter choose · ctrl+enter default · esc back",
            _ => "↑/↓ move · enter choose · esc back",
        };
        let footer_y = inner.bottom().saturating_sub(1);
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                footer,
                Style::default().fg(crate::tui::theme::FOG_ANSI),
            ))),
            Rect::new(inner.x, footer_y, inner.width, 1),
        );
        self.composer_controls.picker_rect = Some(popover);
    }

    pub(super) fn composer_chrome_interactive(&self) -> bool {
        matches!(self.overlay, Overlay::None) && self.composer_chords_available()
    }

    /// Whether the excoc-adopted global chords (`Ctrl+P/E/B/N`, `Alt+↑/↓`)
    /// may act right now. They outrank overlay panes — excoc routes its
    /// Ctrl and Alt chords before overlay and slash handling
    /// (`reference/example-tui/src/tui.rs:157-201`), so an open
    /// [`Overlay`] pane does not block them (a picker chord replaces the
    /// pane; the session chords act underneath it). Cockpit-only decision
    /// surfaces — the question/approval dialogs, transcript pick modes,
    /// transcript find (where `Ctrl+P` stays find-previous), and the
    /// which-key overlay — still swallow keys while they are up. The
    /// embedded pane is excluded by the caller.
    pub(super) fn composer_chords_available(&self) -> bool {
        self.question_dialog.is_none()
            && !self.dialog.is_active()
            && self.pin_pick.is_none()
            && self.fork_pick.is_none()
            && self.copy_pick.is_none()
            && self.pins_review.is_none()
            && self.rules_review.is_none()
            && self.transcript_find.is_none()
            && self.keys_overlay.is_none()
    }

    pub(super) fn close_composer_picker_on_outside_press(&mut self, column: u16, row: u16) -> bool {
        if self.composer_controls.picker.is_none() {
            return false;
        }
        let inside_picker = self
            .composer_controls
            .picker_rect
            .is_some_and(|rect| point_in(rect, column, row));
        let inside_pills = self
            .composer_controls
            .layout
            .as_ref()
            .is_some_and(|layout| {
                layout
                    .pill_buttons
                    .iter()
                    .any(|(_, rect)| point_in(*rect, column, row))
                    || layout
                        .send_button
                        .is_some_and(|rect| point_in(rect, column, row))
            });
        if !inside_picker && !inside_pills {
            self.close_composer_picker();
            return true;
        }
        false
    }

    pub(super) fn close_composer_picker(&mut self) {
        self.invalidate_composer_control_ownership(false, true);
    }

    pub(super) fn activate_composer_pill(&mut self, kind: ComposerControlKind) {
        if !self.composer_chrome_interactive() {
            self.composer_controls.selection = None;
            self.close_composer_picker();
            return;
        }
        self.composer_controls.selection = Some(kind);
        if self
            .composer_controls
            .picker
            .as_ref()
            .is_some_and(|picker| picker.kind == kind)
        {
            self.close_composer_picker();
            return;
        }
        self.open_composer_picker(kind);
        if kind == ComposerControlKind::Model {
            self.request_session_setup_snapshot_refresh();
        }
    }

    pub(super) fn open_composer_picker_from_chord(&mut self, kind: ComposerControlKind) {
        if !self.composer_chords_available() {
            return;
        }
        // The chord outranks any open overlay pane: excoc's `Ctrl+P` /
        // `Ctrl+E` replace the current overlay (`reference/example-tui/
        // src/tui.rs:172` / `:178`), and the popover anchors to the
        // composer, which a full-screen pane would cover.
        self.overlay = Overlay::None;
        self.composer_controls.selection = Some(kind);
        self.open_composer_picker(kind);
        if kind == ComposerControlKind::Model {
            self.request_session_setup_snapshot_refresh();
        }
    }

    pub(super) fn activate_composer_send(&mut self) {
        self.close_composer_picker();
        let _ = self.submit_input();
    }

    pub(super) fn open_composer_picker(&mut self, kind: ComposerControlKind) {
        // The picker is modal for arrows and Enter. Relinquish any queue-row
        // focus at the shared open funnel so keyboard, slash, auth-recovery,
        // and pill-click entry paths cannot leave two controls owning them.
        self.blur_queue_focus();
        if self.composer_controls.pending.is_some() {
            self.invalidate_composer_control_ownership(false, true);
        }
        let mut picker = ComposerPicker {
            generation: self.composer_controls.generation,
            session_id: self.launch.session_id,
            attachment_epoch: self.visible_attachment_epoch,
            kind,
            level: 0,
            category: 0,
            cursor: 0,
            categories: Vec::new(),
            status: ComposerPickerStatus::Ready,
            status_text: None,
        };
        match kind {
            ComposerControlKind::Agent => self.fill_agent_picker(&mut picker),
            ComposerControlKind::Model => self.fill_model_picker(&mut picker),
            ComposerControlKind::Effort => self.fill_effort_picker(&mut picker),
            ComposerControlKind::Approval => self.fill_approval_picker(&mut picker),
            ComposerControlKind::Sandbox => self.fill_sandbox_picker(&mut picker),
        }
        if kind == ComposerControlKind::Model
            && let Some((provider, _)) = self.launch.active_model.as_ref()
        {
            picker.cursor = picker
                .categories
                .iter()
                .position(|category| category.id == *provider && category.label != "Config drift")
                .unwrap_or(0);
        }
        if picker.categories.len() == 1 && kind != ComposerControlKind::Model {
            picker.level = 1;
            picker.cursor = picker
                .categories
                .first()
                .and_then(|c| {
                    c.items
                        .iter()
                        .position(|item| item.id == current_id_for(kind, self))
                })
                .unwrap_or(0);
        }
        self.composer_controls.picker_scroll = 0;
        self.composer_controls.picker_scroll_drag = false;
        self.composer_controls.picker = Some(picker);
    }

    pub(super) fn move_open_composer_picker(&mut self, delta: isize) -> bool {
        let Some(picker) = self.composer_controls.picker.as_mut() else {
            return false;
        };
        picker.move_cursor(delta);
        true
    }

    pub(super) fn hover_composer_picker_row(&mut self, index: usize) {
        if let Some(picker) = self.composer_controls.picker.as_mut()
            && index < picker.row_count()
        {
            picker.cursor = index;
        }
    }

    pub(super) fn begin_composer_picker_scroll_drag(&mut self, column: u16, row: u16) -> bool {
        let Some(track) = self.composer_controls.picker_scrollbar_rect else {
            return false;
        };
        if !point_in(track, column, row) {
            return false;
        }
        self.composer_controls.picker_scroll_drag = true;
        self.drag_composer_picker_scrollbar(row);
        true
    }

    pub(super) fn drag_composer_picker_scrollbar(&mut self, row: u16) {
        if !self.composer_controls.picker_scroll_drag {
            return;
        }
        let Some(track) = self.composer_controls.picker_scrollbar_rect else {
            return;
        };
        let total = self
            .composer_controls
            .picker
            .as_ref()
            .map(ComposerPicker::row_count)
            .unwrap_or(0);
        let max = total.saturating_sub(self.composer_controls.picker_view.max(1));
        let scroll = scroll_from_track(track, row, max);
        let cursor = scroll_from_track(track, row, total.saturating_sub(1));
        self.composer_controls.picker_scroll = scroll;
        if let Some(picker) = self.composer_controls.picker.as_mut() {
            picker.cursor = cursor;
        }
    }

    pub(super) fn end_composer_picker_scroll_drag(&mut self) {
        self.composer_controls.picker_scroll_drag = false;
    }

    fn fill_agent_picker(&self, picker: &mut ComposerPicker) {
        if self.agent_path.len() > 1 {
            picker.status = ComposerPickerStatus::Unavailable;
            picker.status_text = Some(
                "Agent switch is disabled while an interactive subagent is active.".to_string(),
            );
        }
        let current = self
            .agent_path
            .first()
            .map(String::as_str)
            .unwrap_or(self.launch.agent_name.as_str());
        let mut items: Vec<ComposerPickerItem> = self
            .inventory_agent_names()
            .into_iter()
            .map(|name| ComposerPickerItem {
                hint: String::new(),
                selectable: self.agent_path.len() <= 1,
                id: name.clone(),
                label: name,
                ..Default::default()
            })
            .collect();
        if items.is_empty() {
            items.push(ComposerPickerItem {
                id: current.to_string(),
                label: current.to_string(),
                hint: String::new(),
                selectable: self.agent_path.len() <= 1,
                ..Default::default()
            });
        }
        picker.categories.push(ComposerPickerCategory {
            id: "agents".to_string(),
            label: "Agents".to_string(),
            hint: format!("{} agents", items.len()),
            items,
        });
        if self.agent_path.len() > 1 {
            picker.categories.push(ComposerPickerCategory {
                id: "focused".to_string(),
                label: "Focused path".to_string(),
                hint: "current".to_string(),
                items: self
                    .agent_path
                    .iter()
                    .skip(1)
                    .map(|name| ComposerPickerItem {
                        id: name.clone(),
                        label: name.clone(),
                        hint: "child".to_string(),
                        selectable: false,
                        ..Default::default()
                    })
                    .collect(),
            });
        }
    }

    fn fill_model_picker(&self, picker: &mut ComposerPicker) {
        let current = self.launch.active_model.clone();
        let mut by_provider: std::collections::BTreeMap<String, Vec<ComposerPickerItem>> =
            std::collections::BTreeMap::new();
        for (provider_id, entry) in &self.config_snapshot.providers.providers {
            for model in &entry.models {
                let usage_count = self
                    .usage_models
                    .get(&format!("{provider_id}/{}", model.id))
                    .copied()
                    .unwrap_or(0);
                by_provider
                    .entry(provider_id.clone())
                    .or_default()
                    .push(ComposerPickerItem {
                        id: model.id.clone(),
                        label: model
                            .name
                            .clone()
                            .filter(|name| !name.is_empty())
                            .unwrap_or_else(|| model.id.clone()),
                        hint: String::new(),
                        selectable: true,
                        favorite: model.favorite,
                        usage_count,
                        reasoning_effort: model.capabilities.reasoning_effort.clone(),
                        thinking_modes: model.thinking_modes.clone(),
                        ..Default::default()
                    });
            }
        }
        for model in self.inventory_models() {
            let items = by_provider.entry(model.provider.clone()).or_default();
            if let Some(item) = items.iter_mut().find(|item| item.id == model.id) {
                item.favorite |= model.favorite;
                item.usage_count = self
                    .usage_models
                    .get(&format!("{}/{}", model.provider, model.id))
                    .copied()
                    .unwrap_or(item.usage_count);
                if item.reasoning_effort.is_none() {
                    item.reasoning_effort = model.reasoning_effort.clone();
                }
                if item.thinking_modes.is_empty() {
                    item.thinking_modes = model.thinking_modes.clone();
                }
                continue;
            }
            items.push(ComposerPickerItem {
                id: model.id.clone(),
                label: model
                    .display_name
                    .clone()
                    .filter(|name| !name.is_empty())
                    .unwrap_or_else(|| model.id.clone()),
                hint: String::new(),
                selectable: true,
                favorite: model.favorite,
                usage_count: self
                    .usage_models
                    .get(&format!("{}/{}", model.provider, model.id))
                    .copied()
                    .unwrap_or(0),
                reasoning_effort: model.reasoning_effort.clone(),
                thinking_modes: model.thinking_modes.clone(),
                ..Default::default()
            });
        }
        if by_provider.is_empty() {
            picker.status = ComposerPickerStatus::Loading;
            picker.status_text = Some("Loading models…".to_string());
            return;
        }
        let now = chrono::Utc::now().timestamp();
        let slot_models = &self.prepared_slot_models;
        let slot_default = self.prepared_slot_default.as_ref();
        let mut categories = Vec::new();
        for (provider, mut items) in by_provider {
            items.sort_by(|a, b| {
                let a_slot = slot_models
                    .iter()
                    .position(|(slot_provider, slot_model)| {
                        slot_provider == &provider && slot_model == &a.id
                    })
                    .unwrap_or(usize::MAX);
                let b_slot = slot_models
                    .iter()
                    .position(|(slot_provider, slot_model)| {
                        slot_provider == &provider && slot_model == &b.id
                    })
                    .unwrap_or(usize::MAX);
                a_slot
                    .cmp(&b_slot)
                    .then_with(|| b.favorite.cmp(&a.favorite))
                    .then_with(|| b.usage_count.cmp(&a.usage_count))
                    .then_with(|| a.id.cmp(&b.id))
            });
            for item in &mut items {
                let mut annotations = Vec::new();
                if current
                    .as_ref()
                    .is_some_and(|(active_provider, active_model)| {
                        active_provider == &provider && active_model == &item.id
                    })
                {
                    annotations.push("current".to_string());
                }
                if slot_default.is_some_and(|(default_provider, default_model)| {
                    default_provider == &provider && default_model == &item.id
                }) {
                    annotations.push("default".to_string());
                }
                if item.usage_count > 0 {
                    annotations.push(format!("{} uses", item.usage_count));
                }
                if let Some(failure) = self
                    .auth_failure_annotations
                    .get(&(provider.clone(), item.id.clone()))
                {
                    annotations.push(crate::tui::auth_failure::annotation_suffix(failure, now));
                }
                item.hint = annotations.join(" · ");
            }
            let count = items.len();
            let favorite_count = items.iter().filter(|item| item.favorite).count();
            items.push(ComposerPickerItem {
                id: ADD_MODEL_ITEM_ID.to_string(),
                label: "Add model…".to_string(),
                hint: format!("configure {provider}"),
                selectable: true,
                ..Default::default()
            });
            categories.push(ComposerPickerCategory {
                id: provider.clone(),
                label: provider,
                hint: if favorite_count > 0 {
                    format!("{count} models · {favorite_count} favorite  ›")
                } else {
                    format!("{count} models  ›")
                },
                items,
            });
        }
        categories.sort_by(|a, b| {
            let slot_rank = |category: &ComposerPickerCategory| {
                slot_models
                    .iter()
                    .position(|(provider, _)| provider == &category.id)
                    .unwrap_or(usize::MAX)
            };
            slot_rank(a)
                .cmp(&slot_rank(b))
                .then_with(|| {
                    b.items
                        .iter()
                        .any(|item| item.favorite)
                        .cmp(&a.items.iter().any(|item| item.favorite))
                })
                .then_with(|| {
                    b.items
                        .iter()
                        .map(|item| item.usage_count)
                        .max()
                        .unwrap_or(0)
                        .cmp(
                            &a.items
                                .iter()
                                .map(|item| item.usage_count)
                                .max()
                                .unwrap_or(0),
                        )
                })
                .then_with(|| a.id.cmp(&b.id))
        });
        if let Some(drift) = self.model_picker_drift() {
            picker.status_text = Some(format!(
                "Session: {} · config: {}",
                drift.session_label, drift.config_label
            ));
            if let Some(active) = drift.config_model {
                let provider = active.provider;
                let model = active.model;
                categories.insert(
                    0,
                    ComposerPickerCategory {
                        id: provider.clone(),
                        label: "Config drift".to_string(),
                        hint: "switch to configured model  ›".to_string(),
                        items: vec![ComposerPickerItem {
                            id: model.clone(),
                            label: format!("{provider}/{model}"),
                            hint: "configured default".to_string(),
                            selectable: true,
                            config_target: true,
                            selected_reasoning_effort: active.reasoning_effort,
                            selected_thinking_mode: active.thinking_mode,
                            selected_prompt_cache_retention: active.prompt_cache_retention,
                            ..Default::default()
                        }],
                    },
                );
            }
        }
        picker.categories = categories;
    }

    pub(super) fn refresh_open_composer_model_picker(&mut self) {
        let Some(previous) = self
            .composer_controls
            .picker
            .as_ref()
            .filter(|picker| picker.kind == ComposerControlKind::Model)
            .cloned()
        else {
            return;
        };
        if self.composer_controls.pending.is_some() {
            return;
        }
        // At provider level the cursor, not `category`, is authoritative.
        // `category` still names the last drilled-in provider and may be zero
        // while config drift has inserted a synthetic row ahead of the active
        // provider.  An async snapshot refresh must preserve the highlighted
        // provider or Enter can unexpectedly drill into the drift action.
        let category_index = if previous.level == 0 {
            previous.cursor
        } else {
            previous.category
        };
        let category_identity = previous
            .categories
            .get(category_index)
            .map(|category| (category.id.clone(), category.label.clone()));
        let item_id = (previous.level > 0)
            .then(|| {
                previous
                    .categories
                    .get(previous.category)?
                    .items
                    .get(previous.cursor)
                    .map(|item| item.id.clone())
            })
            .flatten();
        let mut refreshed = ComposerPicker {
            categories: Vec::new(),
            status: ComposerPickerStatus::Ready,
            status_text: None,
            ..previous
        };
        self.fill_model_picker(&mut refreshed);
        if let Some((category_id, category_label)) = category_identity
            && let Some(category) = refreshed
                .categories
                .iter()
                .position(|category| category.id == category_id && category.label == category_label)
        {
            refreshed.category = category;
            if refreshed.level == 0 {
                refreshed.cursor = category;
            } else if let Some(item_id) = item_id {
                refreshed.cursor = refreshed.categories[category]
                    .items
                    .iter()
                    .position(|item| item.id == item_id)
                    .unwrap_or(0);
            }
        }
        if refreshed.categories.len() == 1 && refreshed.kind != ComposerControlKind::Model {
            refreshed.level = 1;
            refreshed.category = 0;
        }
        self.composer_controls.picker = Some(refreshed);
    }

    pub(super) fn reopen_composer_model_picker_after_provider_settings(&mut self) -> bool {
        let Some(provider) = self.reopen_composer_model_picker_after_settings.take() else {
            return false;
        };
        self.open_composer_picker_from_chord(ComposerControlKind::Model);
        let current = current_id_for(ComposerControlKind::Model, self);
        if let Some(picker) = self.composer_controls.picker.as_mut()
            && let Some(category) = picker
                .categories
                .iter()
                .position(|category| category.id == provider)
        {
            picker.level = 1;
            picker.category = category;
            picker.cursor = picker.categories[category]
                .items
                .iter()
                .position(|item| item.id == current)
                .unwrap_or(0);
        }
        true
    }

    fn fill_effort_picker(&self, picker: &mut ComposerPicker) {
        let Some((provider, model)) = self.launch.active_model.clone() else {
            picker.status = ComposerPickerStatus::Unavailable;
            picker.status_text = Some("No active model.".to_string());
            return;
        };
        let entry = self
            .config_snapshot
            .providers
            .providers
            .get(&provider)
            .and_then(|entry| entry.models.iter().find(|m| m.id == model));
        let mut effort_items = Vec::new();
        if let Some(capability) = entry.and_then(|m| m.capabilities.reasoning_effort.as_ref()) {
            for value in &capability.values {
                effort_items.push(ComposerPickerItem {
                    id: format!("effort:{}", value.value),
                    label: value
                        .label
                        .clone()
                        .filter(|label| !label.is_empty())
                        .unwrap_or_else(|| value.value.clone()),
                    hint: value.description.clone().unwrap_or_default(),
                    selectable: true,
                    ..Default::default()
                });
            }
        }
        let mut thinking_items = Vec::new();
        if let Some(modes) = entry.map(|m| &m.thinking_modes)
            && !modes.is_empty()
        {
            for mode in modes {
                thinking_items.push(ComposerPickerItem {
                    id: format!("thinking:{}", mode.as_str()),
                    label: mode.as_str().to_string(),
                    hint: String::new(),
                    selectable: true,
                    ..Default::default()
                });
            }
        }
        if effort_items.is_empty() && thinking_items.is_empty() {
            picker.status = ComposerPickerStatus::Unavailable;
            picker.status_text =
                Some("This model does not expose effort or thinking levels.".to_string());
            return;
        }
        let effort_count = effort_items.len();
        let thinking_count = thinking_items.len();
        effort_items.extend(thinking_items);
        let hint = match (effort_count, thinking_count) {
            (effort, 0) => format!("{effort} reasoning levels"),
            (0, thinking) => format!("{thinking} thinking modes"),
            (effort, thinking) => {
                format!("{effort} reasoning levels · {thinking} legacy thinking modes")
            }
        };
        picker.categories.push(ComposerPickerCategory {
            id: "effort".to_string(),
            label: "Effort".to_string(),
            hint,
            items: effort_items,
        });
    }

    fn fill_approval_picker(&self, picker: &mut ComposerPicker) {
        let trust =
            cockpit_config::trust::current_workspace_trust_policy().map(|policy| policy.mode);
        let items = [ApprovalMode::Manual, ApprovalMode::Auto, ApprovalMode::Yolo]
            .into_iter()
            .map(|mode| {
                let selectable = mode.session_set_allowed(trust);
                let hint = if !selectable {
                    mode.session_set_block_reason(trust)
                        .unwrap_or_else(|| "requires workspace trust".to_string())
                } else if mode == self.approval_mode {
                    "current".to_string()
                } else {
                    String::new()
                };
                ComposerPickerItem {
                    id: mode.as_str().to_string(),
                    label: mode.as_str().to_string(),
                    hint,
                    selectable,
                    ..Default::default()
                }
            })
            .collect();
        picker.categories.push(ComposerPickerCategory {
            id: "permissions".to_string(),
            label: "Permissions".to_string(),
            hint: String::new(),
            items,
        });
    }

    fn fill_sandbox_picker(&self, picker: &mut ComposerPicker) {
        if self.sandbox_mode == SandboxMode::Refuse {
            picker.status = ComposerPickerStatus::Unavailable;
            picker.status_text =
                Some("Sandbox refused by host policy; no local bypass is available.".to_string());
        }
        let modes = [
            SandboxMode::Off,
            SandboxMode::Sandbox,
            SandboxMode::Container,
            SandboxMode::ContainerReadonly,
        ];
        let items = modes
            .into_iter()
            .map(|mode| {
                let selectable = sandbox_mode_selectable(mode, &self.host_capabilities);
                let available = sandbox_mode_available(mode, &self.host_capabilities);
                let hint = if !selectable || !available {
                    crate::tui::capability_gate::feature_row(
                        &self.host_capabilities,
                        match mode {
                            SandboxMode::Sandbox => {
                                cockpit_core::host_capabilities::FEATURE_SANDBOX_HOST
                            }
                            SandboxMode::Container | SandboxMode::ContainerReadonly => {
                                cockpit_core::host_capabilities::FEATURE_SANDBOX_CONTAINER
                            }
                            _ => "",
                        },
                    )
                    .map(|row| row.reason.clone())
                    .unwrap_or_else(|| "unavailable".to_string())
                } else if mode == self.sandbox_mode {
                    "current".to_string()
                } else {
                    String::new()
                };
                ComposerPickerItem {
                    id: slash::sandbox_mode_label(mode).to_string(),
                    label: slash::sandbox_mode_label(mode).to_string(),
                    hint,
                    selectable: selectable && available && self.sandbox_mode != SandboxMode::Refuse,
                    ..Default::default()
                }
            })
            .collect();
        picker.categories.push(ComposerPickerCategory {
            id: "sandbox".to_string(),
            label: "Sandbox".to_string(),
            hint: String::new(),
            items,
        });
    }

    pub(super) fn handle_composer_control_key(&mut self, key: KeyEvent) -> bool {
        if !self.composer_chrome_interactive() {
            return false;
        }
        if let Some(mut picker) = self.composer_controls.picker.take() {
            match key.code {
                KeyCode::Esc => {
                    if picker.level > 0
                        && (picker.kind == ComposerControlKind::Model
                            || picker.categories.len() > 1)
                    {
                        picker.level = 0;
                        picker.cursor = picker.category;
                        self.composer_controls.picker = Some(picker);
                    } else {
                        self.close_composer_picker();
                        self.composer_controls.selection = None;
                    }
                    return true;
                }
                _ if is_picker_enter(&key) => {
                    let persist =
                        key.code == KeyCode::Enter && key.modifiers.contains(KeyModifiers::CONTROL);
                    self.commit_composer_picker(picker, persist);
                    return true;
                }
                KeyCode::Up => {
                    picker.move_cursor(-1);
                    self.composer_controls.picker = Some(picker);
                    return true;
                }
                KeyCode::Down => {
                    picker.move_cursor(1);
                    self.composer_controls.picker = Some(picker);
                    return true;
                }
                KeyCode::Char('k') if is_plain_motion(&key) => {
                    picker.move_cursor(-1);
                    self.composer_controls.picker = Some(picker);
                    return true;
                }
                KeyCode::Char('j') if is_plain_motion(&key) => {
                    picker.move_cursor(1);
                    self.composer_controls.picker = Some(picker);
                    return true;
                }
                _ if !is_modifier_only(&key) => {
                    self.close_composer_picker();
                    self.composer_controls.selection = None;
                    return false;
                }
                _ => {
                    self.composer_controls.picker = Some(picker);
                    return true;
                }
            }
        }
        let Some(selected) = self.composer_controls.selection else {
            return false;
        };
        match key.code {
            KeyCode::Esc => {
                self.composer_controls.selection = None;
                true
            }
            KeyCode::Left => {
                self.cycle_composer_pill(selected, -1);
                true
            }
            KeyCode::Right => {
                self.cycle_composer_pill(selected, 1);
                true
            }
            KeyCode::Char('h') if is_plain_motion(&key) => {
                self.cycle_composer_pill(selected, -1);
                true
            }
            KeyCode::Char('l') if is_plain_motion(&key) => {
                self.cycle_composer_pill(selected, 1);
                true
            }
            _ if is_picker_enter(&key) => {
                self.activate_composer_pill(selected);
                true
            }
            _ if !is_modifier_only(&key) => {
                self.composer_controls.selection = None;
                false
            }
            _ => true,
        }
    }

    fn cycle_composer_pill(&mut self, current: ComposerControlKind, delta: i32) {
        let Some(kinds) = self
            .composer_controls
            .layout
            .as_ref()
            .map(ComposerControlLayout::active_kinds)
        else {
            self.composer_controls.selection = None;
            return;
        };
        if kinds.is_empty() {
            self.composer_controls.selection = None;
            return;
        }
        let Some(pos) = kinds.iter().position(|kind| *kind == current) else {
            self.composer_controls.selection = None;
            return;
        };
        let next = if delta < 0 {
            crate::tui::nav::wrap_prev(pos, kinds.len())
        } else {
            crate::tui::nav::wrap_next(pos, kinds.len())
        };
        self.composer_controls.selection = Some(kinds[next]);
    }

    pub(super) fn commit_composer_picker_row(&mut self, index: usize) {
        let Some(mut picker) = self.composer_controls.picker.take() else {
            return;
        };
        picker.cursor = index;
        self.commit_composer_picker(picker, false);
    }

    fn commit_composer_picker(&mut self, mut picker: ComposerPicker, persist_as_default: bool) {
        if picker.generation != self.composer_controls.generation
            || picker.session_id != self.launch.session_id
            || picker.attachment_epoch != self.visible_attachment_epoch
        {
            return;
        }
        if picker.status == ComposerPickerStatus::Unavailable
            || picker.status == ComposerPickerStatus::Refused
        {
            self.composer_controls.picker = Some(picker);
            return;
        }
        if picker.level == 0 {
            if picker.categories.get(picker.cursor).is_none() {
                self.composer_controls.picker = Some(picker);
                return;
            }
            picker.category = picker.cursor;
            picker.level = 1;
            picker.cursor = picker
                .categories
                .get(picker.category)
                .and_then(|category| {
                    category
                        .items
                        .iter()
                        .position(|item| item.id == current_id_for(picker.kind, self))
                })
                .unwrap_or(0);
            self.composer_controls.picker_scroll = 0;
            self.composer_controls.picker = Some(picker);
            return;
        }
        let Some(category) = picker.categories.get(picker.category).cloned() else {
            self.composer_controls.picker = Some(picker);
            return;
        };
        let Some(item) = category.items.get(picker.cursor).cloned() else {
            self.composer_controls.picker = Some(picker);
            return;
        };
        if !item.selectable {
            picker.status = ComposerPickerStatus::Unavailable;
            picker.status_text = Some(if item.hint.is_empty() {
                "This option is not available.".to_string()
            } else {
                item.hint.clone()
            });
            self.composer_controls.picker = Some(picker);
            return;
        }
        if picker.kind == ComposerControlKind::Model && item.id == ADD_MODEL_ITEM_ID {
            self.composer_controls.selection = None;
            self.composer_controls.picker = None;
            self.reopen_composer_model_picker_after_settings = Some(category.id.clone());
            self.dialog =
                crate::tui::settings::Dialog::open_provider_models(&self.launch.cwd, &category.id);
            return;
        }
        picker.status = ComposerPickerStatus::Loading;
        picker.status_text = Some("Applying…".to_string());
        let kind = picker.kind;
        self.composer_controls.pending = Some(PendingComposerMutation {
            generation: picker.generation,
            session_id: picker.session_id,
            attachment_epoch: picker.attachment_epoch,
            kind,
            request_id: None,
        });
        self.composer_controls.dispatch_armed = true;
        self.composer_controls.picker = Some(picker);
        match kind {
            ComposerControlKind::Agent => {
                self.swap_primary_agent(&item.id);
            }
            ComposerControlKind::Model => {
                let (reasoning_effort, thinking_mode, prompt_cache_retention) =
                    if item.config_target {
                        (
                            item.selected_reasoning_effort,
                            item.selected_thinking_mode,
                            item.selected_prompt_cache_retention,
                        )
                    } else {
                        let retained_reasoning = self
                            .active_model_selection
                            .as_ref()
                            .and_then(|current| current.reasoning_effort.clone())
                            .filter(|effort| {
                                item.reasoning_effort.as_ref().is_some_and(|capability| {
                                    capability
                                        .values
                                        .iter()
                                        .any(|candidate| candidate.value == effort.value)
                                })
                            });
                        let retained_thinking = self
                            .active_model_selection
                            .as_ref()
                            .and_then(|current| current.thinking_mode)
                            .filter(|mode| item.thinking_modes.contains(mode));
                        let retained_cache = self
                            .active_model_selection
                            .as_ref()
                            .and_then(|current| current.prompt_cache_retention)
                            .filter(|retention| {
                                retention.is_default()
                                    || self
                                        .config_snapshot
                                        .providers
                                        .resolve_prompt_cache_retention(
                                            &category.id,
                                            &item.id,
                                            Some(*retention),
                                        )
                                        .is_some()
                            });
                        (retained_reasoning, retained_thinking, retained_cache)
                    };
                let active = ActiveModelRef {
                    provider: category.id,
                    model: item.id,
                    reasoning_effort,
                    thinking_mode,
                    prompt_cache_retention,
                };
                let _ = self.notify_active_model_selected(
                    active,
                    persist_as_default,
                    cockpit_proto::ActiveModelSwitchTrigger::Picker,
                );
            }
            ComposerControlKind::Effort => self.commit_effort_item(&item.id),
            ComposerControlKind::Approval => {
                if let Ok(mode) = item.id.parse::<ApprovalModeParse>() {
                    let trust = cockpit_config::trust::current_workspace_trust_policy()
                        .map(|policy| policy.mode);
                    if let Some(reason) = mode.0.session_set_block_reason(trust) {
                        self.refuse_unbound_composer_control(
                            &reason,
                            ComposerPickerStatus::Unavailable,
                        );
                    } else {
                        self.send_daemon_request(
                            "approval",
                            cockpit_proto::Request::SetApprovalMode { mode: mode.0 },
                            ControlApplied::None,
                        );
                    }
                }
            }
            ComposerControlKind::Sandbox => {
                let mode = sandbox_from_label(&item.id);
                match crate::tui::capability_gate::apply_sandbox_choice(
                    mode,
                    &self.host_capabilities,
                    || self.host_capabilities.clone(),
                ) {
                    crate::tui::capability_gate::RecheckApply::Applied(mode) => {
                        self.send_daemon_request(
                            "sandbox",
                            cockpit_proto::Request::SetSandbox {
                                mode: Some(mode),
                                container_network_enabled: None,
                            },
                            ControlApplied::None,
                        );
                    }
                    crate::tui::capability_gate::RecheckApply::Instruct(instruct) => {
                        if let Some(picker) = self.composer_controls.picker.as_mut() {
                            picker.status = ComposerPickerStatus::Unavailable;
                            picker.status_text = Some(instruct.display());
                        }
                        self.composer_controls.pending = None;
                        self.composer_controls.dispatch_armed = false;
                    }
                }
            }
        }
        self.finish_composer_control_dispatch();
    }

    fn commit_effort_item(&mut self, id: &str) {
        let Some(mut active) = self.active_model_selection.clone().or_else(|| {
            self.launch
                .active_model
                .as_ref()
                .map(|(provider, model)| ActiveModelRef {
                    provider: provider.clone(),
                    model: model.clone(),
                    reasoning_effort: None,
                    thinking_mode: None,
                    prompt_cache_retention: None,
                })
        }) else {
            if let Some(picker) = self.composer_controls.picker.as_mut() {
                picker.status = ComposerPickerStatus::Unavailable;
                picker.status_text = Some("No active model.".to_string());
            }
            self.composer_controls.pending = None;
            return;
        };
        if let Some(value) = id.strip_prefix("effort:") {
            active.reasoning_effort = Some(ActiveReasoningEffort {
                value: value.to_string(),
            });
            active.thinking_mode = None;
        } else if let Some(value) = id.strip_prefix("thinking:") {
            active.reasoning_effort = None;
            active.thinking_mode = match value {
                "off" => Some(ThinkingMode::Off),
                "low" => Some(ThinkingMode::Low),
                "medium" => Some(ThinkingMode::Medium),
                "high" => Some(ThinkingMode::High),
                _ => None,
            };
        }
        let _ = self.notify_active_model_selected(
            active,
            false,
            cockpit_proto::ActiveModelSwitchTrigger::Picker,
        );
    }

    pub(super) fn bind_composer_control_request(&mut self, request_id: ControlRequestId) {
        if !self.composer_controls.dispatch_armed {
            return;
        }
        if let Some(pending) = self.composer_controls.pending.as_mut()
            && pending.request_id.is_none()
        {
            pending.request_id = Some(request_id);
        }
        self.composer_controls.dispatch_armed = false;
    }

    pub(super) fn refuse_composer_control_for_request(
        &mut self,
        request_id: ControlRequestId,
        message: &str,
        status: ComposerPickerStatus,
    ) {
        let matches = self
            .composer_controls
            .pending
            .as_ref()
            .is_some_and(|pending| pending.request_id == Some(request_id));
        if matches || self.composer_controls.dispatch_armed {
            self.refuse_unbound_composer_control(message, status);
        }
    }

    pub(super) fn refuse_unbound_composer_control(
        &mut self,
        message: &str,
        status: ComposerPickerStatus,
    ) {
        self.composer_controls.dispatch_armed = false;
        self.composer_controls.pending = None;
        if let Some(picker) = self.composer_controls.picker.as_mut() {
            picker.status = status;
            picker.status_text = Some(message.to_string());
        }
    }

    fn finish_composer_control_dispatch(&mut self) {
        if !self.composer_controls.dispatch_armed {
            return;
        }
        self.composer_controls.dispatch_armed = false;
        if self
            .composer_controls
            .pending
            .as_ref()
            .is_some_and(|pending| pending.request_id.is_none())
        {
            self.refuse_unbound_composer_control(
                "Control request was not delivered.",
                ComposerPickerStatus::Unavailable,
            );
        }
    }

    /// True when this receipt still sits in `composer_controls.pending` but
    /// its generation/session/epoch no longer match. Callers must not apply
    /// confirmation side-effects; displayed state reconverges from daemon.
    pub(super) fn discard_stale_composer_control_receipt(
        &mut self,
        request_id: ControlRequestId,
    ) -> bool {
        let stale = self
            .composer_controls
            .pending
            .as_ref()
            .is_some_and(|pending| {
                pending.request_id == Some(request_id) && !self.composer_mutation_matches(pending)
            });
        if !stale {
            return false;
        }
        self.composer_controls.pending = None;
        self.composer_controls.dispatch_armed = false;
        if let Some(picker) = self.composer_controls.picker.as_mut() {
            picker.status = ComposerPickerStatus::Ready;
            picker.status_text = Some("Stale result discarded.".to_string());
        }
        self.request_session_setup_snapshot_refresh();
        true
    }

    pub(super) fn apply_composer_control_outcome(
        &mut self,
        request_id: ControlRequestId,
        rejected: Option<&str>,
        unavailable: bool,
    ) {
        let matches_request = self
            .composer_controls
            .pending
            .as_ref()
            .is_some_and(|pending| pending.request_id == Some(request_id));
        if !matches_request {
            return;
        }
        let Some(pending) = self.composer_controls.pending.take() else {
            return;
        };
        if !self.composer_mutation_matches(&pending)
            || self
                .composer_controls
                .picker
                .as_ref()
                .is_some_and(|picker| picker.kind != pending.kind)
        {
            if let Some(picker) = self.composer_controls.picker.as_mut() {
                picker.status = ComposerPickerStatus::Ready;
                picker.status_text = Some("Stale result discarded.".to_string());
            }
            return;
        }
        if let Some(error) = rejected {
            if let Some(picker) = self.composer_controls.picker.as_mut() {
                picker.status = if unavailable {
                    ComposerPickerStatus::Unavailable
                } else {
                    ComposerPickerStatus::Refused
                };
                picker.status_text = Some(error.to_string());
            }
            return;
        }
        if let Some(picker) = self.composer_controls.picker.as_mut() {
            picker.status = ComposerPickerStatus::Confirmed;
            picker.status_text = None;
        }
        self.composer_controls.picker = None;
        self.composer_controls.selection = None;
    }

    /// Empty composer Enter: never submits text. Empty queue is a no-op.
    /// Otherwise promote every Held item to Steering first; only a
    /// steering-only queue then requests transient Send now.
    pub(super) fn handle_empty_composer_enter(&mut self) {
        if self.queue.is_empty() {
            return;
        }
        if self.queue_has_held() {
            self.queue_promote_all(cockpit_proto::QueueDeliveryClass::Steering);
            return;
        }
        self.queue_action_send_now(None);
    }
}

impl ComposerControlState {
    fn full_labels_owned(&self) -> Vec<String> {
        vec![
            self.agent_label.clone(),
            self.model_label.clone(),
            self.effort_label.clone(),
            self.approval_label.clone(),
            self.sandbox_label.clone(),
        ]
    }

    fn compact_labels_owned(&self) -> Vec<String> {
        vec![
            self.compact_agent.clone(),
            self.compact_model.clone(),
            self.compact_effort.clone(),
            self.compact_approval.clone(),
            self.compact_sandbox.clone(),
        ]
    }
}

fn picker_status_line(picker: &ComposerPicker) -> Option<String> {
    match picker.status {
        ComposerPickerStatus::Loading => Some(
            picker
                .status_text
                .clone()
                .unwrap_or_else(|| "Loading…".to_string()),
        ),
        ComposerPickerStatus::Unavailable | ComposerPickerStatus::Refused => {
            picker.status_text.clone()
        }
        ComposerPickerStatus::Confirmed => Some("Applied.".to_string()),
        ComposerPickerStatus::Ready => picker.status_text.clone(),
    }
}

fn current_id_for(kind: ComposerControlKind, app: &App) -> String {
    match kind {
        ComposerControlKind::Agent => app
            .agent_path
            .first()
            .cloned()
            .unwrap_or_else(|| app.launch.agent_name.clone()),
        ComposerControlKind::Model => app
            .launch
            .active_model
            .as_ref()
            .map(|(_, model)| model.clone())
            .unwrap_or_default(),
        ComposerControlKind::Effort => app
            .active_model_selection
            .as_ref()
            .and_then(|active| {
                active
                    .reasoning_effort
                    .as_ref()
                    .map(|effort| format!("effort:{}", effort.value))
                    .or_else(|| {
                        active
                            .thinking_mode
                            .map(|mode| format!("thinking:{}", mode.as_str()))
                    })
            })
            .unwrap_or_default(),
        ComposerControlKind::Approval => app.approval_mode.as_str().to_string(),
        ComposerControlKind::Sandbox => slash::sandbox_mode_label(app.sandbox_mode).to_string(),
    }
}

struct ApprovalModeParse(ApprovalMode);

impl std::str::FromStr for ApprovalModeParse {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "manual" => Ok(Self(ApprovalMode::Manual)),
            "auto" => Ok(Self(ApprovalMode::Auto)),
            "yolo" => Ok(Self(ApprovalMode::Yolo)),
            _ => Err(()),
        }
    }
}

fn sandbox_from_label(label: &str) -> SandboxMode {
    match label {
        "off" => SandboxMode::Off,
        "on" => SandboxMode::Sandbox,
        "container" => SandboxMode::Container,
        "container-readonly" => SandboxMode::ContainerReadonly,
        "refused" => SandboxMode::Refuse,
        _ => SandboxMode::Sandbox,
    }
}
