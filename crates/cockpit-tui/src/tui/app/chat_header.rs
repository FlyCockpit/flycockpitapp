//! App wiring for the three-row chat header: state assembly from
//! authoritative sources, the render carve, the collapsed-pill `more`
//! popover, pill activation (mouse + keyboard), and the parity-tested
//! drill-ins into the existing authoritative surfaces.

use super::input::is_modifier_only;
use super::*;

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::widgets::{Block, Borders, Clear};

use crate::tui::chat_header::{
    CHAT_HEADER_HEIGHT, ChatHeaderLayout, ChatHeaderState, HeaderPill, HeaderPillKind,
    HeaderSessionStatus,
};
use crate::tui::history::{HistoryEntry, ToolCallState};
use crate::tui::theme::ACCENT_BLUE;

impl App {
    /// Build one frame's header state. Every value is read from
    /// daemon/launch-owned state; nothing is synthesized.
    pub(super) fn chat_header_state(&self) -> ChatHeaderState {
        ChatHeaderState {
            title: self.chat_header_title(),
            status: self.chat_header_status(),
            routing_status: self.header_routing_status(),
            rail_hidden: !self.session_rail.is_visible(),
            path: self.launch.cwd_display.clone(),
            git: self
                .launch
                .repo_status
                .as_ref()
                .map(crate::tui::chat_header::launch_git_facts),
            pills: self.chat_header_pills(),
        }
    }

    /// The daemon-published session title: the rail summary's title for the
    /// attached session when the projection holds it, else the launch short
    /// id. `None` until either is known — never a placeholder.
    fn chat_header_title(&self) -> Option<String> {
        if let Some(summary) = self
            .session_rail
            .visible_cards()
            .into_iter()
            .find(|summary| Some(summary.session_id) == self.launch.session_id)
        {
            let title = summary
                .title
                .clone()
                .filter(|title| !title.trim().is_empty())
                .or_else(|| summary.short_id.clone().filter(|id| !id.trim().is_empty()));
            if title.is_some() {
                return title;
            }
        }
        self.launch
            .session_short_id
            .clone()
            .filter(|id| !id.trim().is_empty())
    }

    /// Session status from authoritative state: a pending action-required
    /// interrupt outranks an inference reconnect, which outranks a busy
    /// turn. At rest, a transcript that has carried a conversation turn
    /// reads done (the reference's resting rule); only a transcript with
    /// no turns yet reads idle.
    fn chat_header_status(&self) -> HeaderSessionStatus {
        if self.header_attention_count() > 0 {
            return HeaderSessionStatus::Attention;
        }
        if self.reconnect.is_some() || self.daemon_link.is_some() {
            return HeaderSessionStatus::Reconnecting;
        }
        if self.busy || self.pending.is_some() {
            return HeaderSessionStatus::Working;
        }
        if self.header_has_settled_turn() {
            return HeaderSessionStatus::Done;
        }
        HeaderSessionStatus::Idle
    }

    fn header_routing_status(&self) -> Option<String> {
        if let Some(status) = self.daemon_link.as_ref() {
            let label = if status.restarting {
                "daemon restarting"
            } else {
                "daemon reconnecting"
            };
            return Some(format!(
                "{label} · attempt {} · {}s",
                status.attempt,
                status.started_at.elapsed().as_secs()
            ));
        }
        if let Some(status) = self.reconnect.as_ref() {
            return Some(format!(
                "{}/{} · {} · attempt {}",
                status.provider, status.model, status.url, status.attempt
            ));
        }
        (self.agent_path.len() > 1)
            .then(|| self.agent_path.last().cloned())
            .flatten()
    }

    /// Whether the transcript holds any conversation message (user or
    /// agent). Tool chrome and system notes alone do not count as a turn:
    /// a session that has run a turn and has nothing in flight is done,
    /// not idle.
    fn header_has_settled_turn(&self) -> bool {
        self.history.iter().any(|entry| {
            matches!(
                entry,
                HistoryEntry::User { .. } | HistoryEntry::Agent { .. }
            )
        })
    }

    /// Pending action-required interrupts: the attached session's interrupt
    /// plus background-session interrupts (which never open a dialog here).
    fn header_attention_count(&self) -> usize {
        let foreground = usize::from(
            self.attention_interrupt
                .as_ref()
                .is_some_and(|state| state.pending),
        );
        let background = self
            .background_attention_interrupts
            .values()
            .filter(|state| state.pending)
            .count();
        foreground + background
    }

    /// Activity pills in priority order. Each pill is emitted only when its
    /// daemon-backed state is known and non-empty.
    fn chat_header_pills(&self) -> Vec<HeaderPill> {
        let mut pills = Vec::new();

        let attention = self.header_attention_count();
        if attention > 0 {
            pills.push(HeaderPill {
                kind: HeaderPillKind::Attention,
                label: counted_label("attention", attention),
            });
        }

        if let Some(version) = self.update_available_version.as_ref() {
            pills.push(HeaderPill {
                kind: HeaderPillKind::Update,
                label: format!("update {version}"),
            });
        }

        if let Some(tool) = self.header_active_tool() {
            pills.push(HeaderPill {
                kind: HeaderPillKind::Tool,
                label: format!("tool {tool}"),
            });
        }

        // The foreground agent pill surfaces a subagent-driven foreground
        // (path deeper than the primary) or any actively working turn.
        if self.busy || self.agent_path.len() > 1 {
            let path: Vec<&str> = if self.agent_path.is_empty() {
                vec![self.launch.agent_name.as_str()]
            } else {
                self.agent_path.iter().map(String::as_str).collect()
            };
            pills.push(HeaderPill {
                kind: HeaderPillKind::Agent,
                label: path.join(" › "),
            });
        }

        let tasks = self
            .active_schedules
            .values()
            .filter(|job| job.kind == "background" || job.kind == "loop")
            .count();
        if tasks > 0 {
            pills.push(HeaderPill {
                kind: HeaderPillKind::Task,
                label: counted_label("task", tasks),
            });
        }

        let timers = self
            .active_schedules
            .values()
            .filter(|job| job.kind == "timer")
            .count();
        if timers > 0 {
            pills.push(HeaderPill {
                kind: HeaderPillKind::Timer,
                label: counted_label("timer", timers),
            });
        }

        if let Some(skill) = self.header_active_skill() {
            pills.push(HeaderPill {
                kind: HeaderPillKind::Skill,
                label: format!("skill {skill}"),
            });
        }

        if self.pin_count > 0 {
            pills.push(HeaderPill {
                kind: HeaderPillKind::Pins,
                label: format!("pins: {}", self.pin_count),
            });
        }

        if self.longcache_enabled {
            pills.push(HeaderPill {
                kind: HeaderPillKind::Longcache,
                label: if self.longcache_supported {
                    "longcache".to_string()
                } else {
                    "longcache unsupported".to_string()
                },
            });
        }

        pills.push(HeaderPill {
            kind: HeaderPillKind::Setup,
            label: self
                .session_mode
                .map(|mode| format!("Setup: {}", mode.display_name()))
                .unwrap_or_else(|| "Setup: loading…".to_string()),
        });

        if let Some((path, holder)) = self.waiting_for_lock.as_ref() {
            let name = std::path::Path::new(path)
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or(path);
            pills.push(HeaderPill {
                kind: HeaderPillKind::Lock,
                label: format!("lock: {name} · {holder}"),
            });
        }
        if self.side_conversation.is_some() {
            pills.push(HeaderPill {
                kind: HeaderPillKind::Side,
                label: "side".to_string(),
            });
        }
        if self.caffeinate_active {
            pills.push(HeaderPill {
                kind: HeaderPillKind::Caffeinate,
                label: "☕ awake".to_string(),
            });
        }
        #[cfg(feature = "remote")]
        {
            if let Some(disclosure) = self.org_sync_disclosure.as_ref() {
                pills.push(HeaderPill {
                    kind: HeaderPillKind::OrgSync,
                    label: format!("org sync {}", disclosure.org_id),
                });
            }
            if let Some(disclosure) = self.connector_disclosure.as_ref()
                && (disclosure.enabled || disclosure.status != "off")
            {
                pills.push(HeaderPill {
                    kind: HeaderPillKind::Connector,
                    label: format!("remote {}", disclosure.status),
                });
            }
        }

        pills
    }

    /// The tool call currently in flight, from the live history window: the
    /// newest boxed or standalone call still `Verifying`/`Processing`.
    /// Scanning stops at the newest user message — tools above it belong to
    /// settled turns.
    fn header_active_tool(&self) -> Option<String> {
        for index in (0..self.history.len()).rev() {
            match self.history.get(index) {
                Some(HistoryEntry::User { .. }) => return None,
                Some(HistoryEntry::ToolBox { calls, .. }) => {
                    if let Some(call) = calls.iter().rev().find(|call| {
                        matches!(
                            call.state,
                            ToolCallState::Verifying | ToolCallState::Processing
                        )
                    }) {
                        return Some(call.tool.clone());
                    }
                }
                Some(HistoryEntry::ToolLine { tool, state, .. }) => {
                    if matches!(state, ToolCallState::Verifying | ToolCallState::Processing) {
                        return Some(tool.clone());
                    }
                }
                _ => {}
            }
        }
        None
    }

    /// The skill auto-injected onto the current turn: the newest injection
    /// row with no user message after it.
    fn header_active_skill(&self) -> Option<String> {
        for index in (0..self.history.len()).rev() {
            match self.history.get(index) {
                Some(HistoryEntry::User { .. }) => return None,
                Some(HistoryEntry::SkillAutoInjected { name, .. }) => return Some(name.clone()),
                _ => {}
            }
        }
        None
    }

    /// Render the header at the top of `chat`, returning the remaining rect.
    /// It contracts from title/meta/rule to title/rule and then title-only so
    /// one transcript row survives; a one-row pane remains transcript-only.
    pub(super) fn render_chat_header(&mut self, frame: &mut Frame, chat: Rect) -> Rect {
        if chat.width == 0 || chat.height < 2 {
            self.chat_header_layout = None;
            self.header_pill_selection = None;
            self.chat_header_more_open = false;
            self.chat_header_more_rect = None;
            return chat;
        }
        let header_height = CHAT_HEADER_HEIGHT.min(chat.height.saturating_sub(1));
        let header_area = Rect {
            height: header_height,
            ..chat
        };
        let rest = Rect {
            y: chat.y.saturating_add(header_height),
            height: chat.height.saturating_sub(header_height),
            ..chat
        };
        let state = self.chat_header_state();
        let layout = crate::tui::chat_header::plan_chat_header(&state, header_area);
        if layout.more_button.is_none() {
            self.chat_header_more_open = false;
            self.chat_header_more_rect = None;
        }
        let selected = self.header_pill_selection;
        crate::tui::chat_header::paint_chat_header(
            frame,
            &layout,
            &state,
            selected,
            &mut self.button_registry,
        );
        self.chat_header_layout = Some(layout);
        rest
    }

    /// Paint the collapsed-pill `more` popover over the transcript, below
    /// the header's meta row. Called after history renders so it floats on
    /// top; a no-op unless the header rendered and the popover is open.
    /// The popover never floats above a body-owning modal: when one is on
    /// top it closes instead of shadowing that surface.
    pub(super) fn paint_chat_header_more_popover(&mut self, frame: &mut Frame) {
        self.chat_header_more_rect = None;
        if !self.header_chrome_interactive() {
            self.chat_header_more_open = false;
            return;
        }
        let Some(layout) = self.chat_header_layout.clone() else {
            self.chat_header_more_open = false;
            return;
        };
        if !self.chat_header_more_open || layout.collapsed.is_empty() {
            return;
        }
        let Some((_, more_rect)) = layout.more_button else {
            self.chat_header_more_open = false;
            return;
        };

        let labels: Vec<(HeaderPillKind, String)> = layout
            .collapsed
            .iter()
            .map(|pill| (pill.kind, pill.label.clone()))
            .collect();
        let inner_w = labels
            .iter()
            .map(|(_, label)| {
                crate::tui::button::display_width(&crate::tui::button::bracketed_label(label))
            })
            .max()
            .unwrap_or(0) as u16;
        let width = inner_w.saturating_add(2).min(layout.area.width);
        let height = (labels.len() as u16).saturating_add(2);
        let x = more_rect
            .x
            .saturating_add(more_rect.width)
            .saturating_sub(width);
        let y = layout.area.bottom();
        let popover = Rect {
            x,
            y,
            width,
            height,
        };

        frame.render_widget(Clear, popover);
        let block = Block::default()
            .borders(Borders::ALL)
            .border_type(crate::tui::chrome::rounded_border_type())
            .border_style(Style::default().fg(ACCENT_BLUE))
            .title(" more ");
        let inner = block.inner(popover);
        frame.render_widget(block, popover);
        let selected = self.header_pill_selection;
        for (row, (kind, label)) in labels.iter().enumerate() {
            let y = inner.y.saturating_add(row as u16);
            if y >= inner.bottom() {
                break;
            }
            let spec = crate::tui::button::ButtonSpec::new(
                crate::tui::button::ButtonId::HeaderPill(*kind),
                label.clone(),
                crate::tui::button::ButtonDispatch::HeaderPill(*kind),
            )
            .focused(selected == Some(*kind));
            let _ = self
                .button_registry
                .paint(frame, inner.x, y, inner.width, spec);
        }
        self.chat_header_more_rect = Some(popover);
    }

    /// Close the `more` popover when a pointer press lands outside it (and
    /// outside the header rows that own it). Returns true when the popover
    /// was open. The press still routes to whatever it hit.
    pub(super) fn close_chat_header_popover_on_outside_press(
        &mut self,
        column: u16,
        row: u16,
    ) -> bool {
        if !self.chat_header_more_open {
            return false;
        }
        let inside_popover = self
            .chat_header_more_rect
            .is_some_and(|rect| point_in_header(rect, column, row));
        let inside_header = self
            .chat_header_layout
            .as_ref()
            .is_some_and(|layout| point_in_header(layout.area, column, row));
        if !inside_popover && !inside_header {
            self.chat_header_more_open = false;
            return true;
        }
        false
    }

    /// Whether the header's interactive chrome (pills, the `more` chip and
    /// popover) may take input this frame: the header must have rendered,
    /// and no body-owning surface may be on top — the approval question
    /// dialog, any settings/wizard dialog, any overlay (an overlay holding
    /// unsettled local authority also means the header did not render, so
    /// its pane cannot be dropped by a pill), or any keyboard-modal body
    /// surface (the pick/review modes and the transcript-find bar). Header
    /// rows still render behind a modal — the attention/status summary is
    /// exactly then most relevant — but they never preempt its keys or
    /// clicks.
    pub(super) fn header_chrome_interactive(&self) -> bool {
        self.chat_header_layout.is_some()
            && matches!(self.overlay, Overlay::None)
            && self.question_dialog.is_none()
            && !self.dialog.is_active()
            && !self.keyboard_modal_body_surface_open()
    }

    /// The body-owning keyboard modals that are neither `Overlay` variants
    /// nor dialogs: the `/pin`/`/fork`/`/copy-pick` pick modes, the
    /// `/pins`/`/rules` review panels, and the transcript-find bar. Each
    /// paints over the transcript and swallows every keystroke while open
    /// (`handle_key` routes the pick/review modes ahead of the header; the
    /// find bar owns every key once no pill selection is live), so header
    /// chrome must yield to them on the mouse path too — otherwise a pill
    /// click could preempt a workflow the keyboard already treats as
    /// modal, and the click-set selection would then outrank the modal's
    /// keys once the opened overlay closes.
    fn keyboard_modal_body_surface_open(&self) -> bool {
        self.pin_pick.is_some()
            || self.fork_pick.is_some()
            || self.copy_pick.is_some()
            || self.pins_review.is_some()
            || self.rules_review.is_some()
            || self.transcript_find.is_some()
    }

    /// Activate one header pill: select it and open its existing
    /// authoritative detail surface. Exactly one funnel for mouse and
    /// keyboard. Refused (and any selection released) while a body-owning
    /// surface is on top.
    pub(super) fn activate_header_pill(&mut self, kind: HeaderPillKind) {
        if !self.header_chrome_interactive() {
            self.header_pill_selection = None;
            self.chat_header_more_open = false;
            return;
        }
        self.header_pill_selection = Some(kind);
        self.chat_header_more_open = false;
        match kind {
            HeaderPillKind::Attention | HeaderPillKind::Agent => self.open_agent_tree(),
            HeaderPillKind::Update => self.header_pill_selection = None,
            HeaderPillKind::Tool => self.open_tools_pane(),
            HeaderPillKind::Task | HeaderPillKind::Timer => self.handle_schedule_command(""),
            HeaderPillKind::Skill => self.open_skills_pane(),
            HeaderPillKind::Pins => self.enter_pins_review_mode(),
            HeaderPillKind::Setup => self.open_session_setup(),
            HeaderPillKind::Longcache
            | HeaderPillKind::Lock
            | HeaderPillKind::Side
            | HeaderPillKind::Caffeinate => self.header_pill_selection = None,
            #[cfg(feature = "remote")]
            HeaderPillKind::OrgSync | HeaderPillKind::Connector => {
                self.header_pill_selection = None;
            }
        }
    }

    /// Open the tools detail surface (the `/tools` pane), extracted so the
    /// header tool pill and the command share one path.
    pub(super) fn open_tools_pane(&mut self) {
        let agent = self
            .agent_path
            .last()
            .cloned()
            .unwrap_or_else(|| self.launch.agent_name.clone());
        match crate::tui::tools_pane::ToolsPane::open(
            &self.launch.cwd,
            &agent,
            self.agent_path.len() == 1,
        ) {
            Ok(pane) => {
                self.overlay = Overlay::Tools(pane);
            }
            Err(error) => {
                self.push_plain(format!("/tools: {error:#}"));
            }
        }
    }

    /// Toggle the collapsed-pill `more` popover (the `[+N]` chip). A no-op
    /// (and closed) while a body-owning surface is on top.
    pub(super) fn toggle_chat_header_more(&mut self) {
        if !self.header_chrome_interactive() {
            self.chat_header_more_open = false;
            return;
        }
        self.chat_header_more_open = !self.chat_header_more_open;
    }

    /// Keyboard handling for header pills: while a pill is selected, ←/→
    /// cycle through this frame's active pills, Enter activates, Esc clears
    /// (closing an open popover first). Any other ordinary key clears the
    /// selection and falls through. When the header is not the active
    /// input surface (a modal/overlay on top, or it did not render), any
    /// stale selection is released and the key always falls through to the
    /// surface that owns input. Returns true when the key was consumed.
    pub(super) fn handle_header_pill_key(&mut self, key: &KeyEvent) -> bool {
        if !self.header_chrome_interactive() {
            self.header_pill_selection = None;
            self.chat_header_more_open = false;
            return false;
        }
        if self.chat_header_more_open
            && let KeyCode::Esc = key.code
        {
            self.chat_header_more_open = false;
            self.header_pill_selection = None;
            return true;
        }
        let Some(selected) = self.header_pill_selection else {
            return false;
        };
        match key.code {
            KeyCode::Esc => {
                self.header_pill_selection = None;
                true
            }
            KeyCode::Left | KeyCode::Char('h') => {
                self.cycle_header_pill(selected, -1);
                true
            }
            KeyCode::Right | KeyCode::Char('l') => {
                self.cycle_header_pill(selected, 1);
                true
            }
            KeyCode::Enter => {
                self.activate_header_pill(selected);
                true
            }
            _ if !is_modifier_only(key) => {
                self.header_pill_selection = None;
                false
            }
            _ => true,
        }
    }

    /// Move the pill selection one step in priority order over this frame's
    /// active pills; a selection whose pill vanished clears.
    fn cycle_header_pill(&mut self, current: HeaderPillKind, delta: i32) {
        let Some(kinds) = self
            .chat_header_layout
            .as_ref()
            .map(ChatHeaderLayout::active_kinds)
        else {
            self.header_pill_selection = None;
            return;
        };
        if kinds.is_empty() {
            self.header_pill_selection = None;
            return;
        }
        let Some(pos) = kinds.iter().position(|kind| *kind == current) else {
            self.header_pill_selection = None;
            return;
        };
        let len = kinds.len() as i32;
        let next = ((pos as i32 + delta).rem_euclid(len)) as usize;
        self.header_pill_selection = Some(kinds[next]);
    }
}

fn counted_label(base: &str, count: usize) -> String {
    format!("{base} {count}")
}

fn point_in_header(rect: Rect, column: u16, row: u16) -> bool {
    column >= rect.x
        && column < rect.x.saturating_add(rect.width)
        && row >= rect.y
        && row < rect.y.saturating_add(rect.height)
}
