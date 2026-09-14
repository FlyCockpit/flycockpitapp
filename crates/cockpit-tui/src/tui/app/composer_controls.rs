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
use ratatui::style::Style;
use ratatui::text::Span;
use ratatui::widgets::{Block, BorderType, Borders, Clear, Paragraph};
use uuid::Uuid;

fn point_in(rect: Rect, col: u16, row: u16) -> bool {
    col >= rect.x && col < rect.x + rect.width && row >= rect.y && row < rect.y + rect.height
}

#[derive(Debug, Clone, Default)]
pub(super) struct ComposerControlUi {
    pub generation: u64,
    pub selection: Option<ComposerControlKind>,
    pub picker: Option<ComposerPicker>,
    pub layout: Option<ComposerControlLayout>,
    pub picker_rect: Option<Rect>,
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

#[derive(Debug, Clone)]
pub(super) struct ComposerPickerItem {
    pub id: String,
    pub label: String,
    pub hint: String,
    pub selectable: bool,
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
    pub(super) fn bump_composer_control_generation(&mut self) {
        self.composer_controls.generation = self.composer_controls.generation.wrapping_add(1);
        self.composer_controls.picker = None;
        self.composer_controls.picker_rect = None;
        self.composer_controls.pending = None;
        self.composer_controls.dispatch_armed = false;
        self.composer_controls.selection = None;
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
        if !self.composer_chrome_interactive() {
            self.composer_controls.picker = None;
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
                    .saturating_add(2)
                    .saturating_add(crate::tui::button::display_width(hint))
            })
            .max()
            .unwrap_or(12)
            .max(crate::tui::button::display_width(
                status_line.as_deref().unwrap_or(""),
            ));
        let width = inner_w
            .saturating_add(4)
            .min(layout.area.width.max(16))
            .max(16);
        let body_rows = rows.len().max(1) as u16;
        let status_h = u16::from(status_line.is_some());
        let height = body_rows.saturating_add(2).saturating_add(status_h).min(14);
        let screen = frame.area();
        let y = anchor.y.saturating_sub(height);
        let mut x = anchor.x;
        if x.saturating_add(width) > screen.right() {
            x = screen.right().saturating_sub(width);
        }
        let popover = Rect {
            x,
            y,
            width,
            height,
        };
        frame.render_widget(Clear, popover);
        let title = match picker.level {
            0 => format!(" {} ", picker.kind.as_str()),
            _ => picker
                .categories
                .get(picker.category)
                .map(|c| format!(" {} ", c.label))
                .unwrap_or_else(|| format!(" {} ", picker.kind.as_str())),
        };
        let block = Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(crate::tui::theme::ACCENT_BLUE))
            .title(title);
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
        use crate::tui::button::{ButtonDispatch, ButtonId, ButtonSpec};
        if rows.is_empty() {
            frame.render_widget(
                Paragraph::new(ratatui::text::Line::from(Span::styled(
                    "(none)",
                    Style::default().fg(crate::tui::theme::MUTED_TEXT),
                ))),
                Rect {
                    x: inner.x,
                    y: row_y,
                    width: inner.width,
                    height: 1,
                },
            );
        } else {
            for (index, (label, hint, selectable)) in rows.iter().enumerate() {
                let y = row_y.saturating_add(index as u16);
                if y >= inner.bottom() {
                    break;
                }
                let shown = if hint.is_empty() {
                    label.clone()
                } else {
                    format!("{label}  {hint}")
                };
                let spec = ButtonSpec::new(
                    ButtonId::ComposerPickerRow { index },
                    shown,
                    ButtonDispatch::ComposerPickerRow { index },
                )
                .focused(picker.cursor == index)
                .enabled(*selectable);
                let _ = self
                    .button_registry
                    .paint(frame, inner.x, y, inner.width, spec);
            }
        }
        self.composer_controls.picker_rect = Some(popover);
    }

    pub(super) fn composer_chrome_interactive(&self) -> bool {
        matches!(self.overlay, Overlay::None)
            && self.question_dialog.is_none()
            && !self.dialog.is_active()
            && self.pin_pick.is_none()
            && self.fork_pick.is_none()
            && self.copy_pick.is_none()
            && self.pins_review.is_none()
            && self.rules_review.is_none()
            && self.transcript_find.is_none()
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
        if self.composer_controls.picker.is_some() {
            self.composer_controls.generation = self.composer_controls.generation.wrapping_add(1);
        }
        self.composer_controls.picker = None;
        self.composer_controls.picker_rect = None;
        self.composer_controls.pending = None;
        self.composer_controls.dispatch_armed = false;
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
    }

    pub(super) fn activate_composer_send(&mut self) {
        self.close_composer_picker();
        let _ = self.submit_input();
    }

    pub(super) fn open_composer_picker(&mut self, kind: ComposerControlKind) {
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
        if picker.categories.len() == 1 {
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
        self.composer_controls.picker = Some(picker);
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
            })
            .collect();
        if items.is_empty() {
            items.push(ComposerPickerItem {
                id: current.to_string(),
                label: current.to_string(),
                hint: String::new(),
                selectable: self.agent_path.len() <= 1,
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
                        hint: if current
                            .as_ref()
                            .is_some_and(|(p, m)| p == provider_id && m == &model.id)
                        {
                            "current".to_string()
                        } else {
                            String::new()
                        },
                        selectable: true,
                    });
            }
        }
        for model in self.inventory_models() {
            let items = by_provider.entry(model.provider.clone()).or_default();
            if items.iter().any(|item| item.id == model.id) {
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
            });
        }
        if by_provider.is_empty() {
            picker.status = ComposerPickerStatus::Loading;
            picker.status_text = Some("Loading models…".to_string());
            return;
        }
        for (provider, items) in by_provider {
            let count = items.len();
            picker.categories.push(ComposerPickerCategory {
                id: provider.clone(),
                label: provider,
                hint: format!("{count} models  ›"),
                items,
            });
        }
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
                });
            }
        }
        if effort_items.is_empty() && thinking_items.is_empty() {
            picker.status = ComposerPickerStatus::Unavailable;
            picker.status_text =
                Some("This model does not expose effort or thinking levels.".to_string());
            return;
        }
        if !effort_items.is_empty() {
            picker.categories.push(ComposerPickerCategory {
                id: "effort".to_string(),
                label: "Reasoning effort".to_string(),
                hint: format!("{} levels  ›", effort_items.len()),
                items: effort_items,
            });
        }
        if !thinking_items.is_empty() {
            picker.categories.push(ComposerPickerCategory {
                id: "thinking".to_string(),
                label: "Thinking".to_string(),
                hint: format!("{} levels  ›", thinking_items.len()),
                items: thinking_items,
            });
        }
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
            self.composer_controls.selection = None;
            self.composer_controls.picker = None;
            return false;
        }
        if let Some(mut picker) = self.composer_controls.picker.take() {
            match key.code {
                KeyCode::Esc => {
                    if picker.level > 0 && picker.categories.len() > 1 {
                        picker.level = 0;
                        picker.cursor = picker.category;
                        self.composer_controls.picker = Some(picker);
                    } else {
                        self.close_composer_picker();
                        self.composer_controls.selection = None;
                    }
                    return true;
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    picker.move_cursor(-1);
                    self.composer_controls.picker = Some(picker);
                    return true;
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    picker.move_cursor(1);
                    self.composer_controls.picker = Some(picker);
                    return true;
                }
                KeyCode::Enter => {
                    let persist = key.modifiers.contains(KeyModifiers::CONTROL);
                    self.commit_composer_picker(picker, persist);
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
            KeyCode::Left | KeyCode::Char('h') => {
                self.cycle_composer_pill(selected, -1);
                true
            }
            KeyCode::Right | KeyCode::Char('l') => {
                self.cycle_composer_pill(selected, 1);
                true
            }
            KeyCode::Enter => {
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
            picker.cursor = 0;
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
                let active = ActiveModelRef {
                    provider: category.id,
                    model: item.id,
                    reasoning_effort: self
                        .active_model_selection
                        .as_ref()
                        .and_then(|current| current.reasoning_effort.clone()),
                    thinking_mode: self
                        .active_model_selection
                        .as_ref()
                        .and_then(|current| current.thinking_mode),
                    prompt_cache_retention: self
                        .active_model_selection
                        .as_ref()
                        .and_then(|current| current.prompt_cache_retention),
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
        } else if let Some(value) = id.strip_prefix("thinking:") {
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
