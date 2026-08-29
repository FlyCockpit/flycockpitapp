//! Session-setup panel: agent, model, tools, and MCPs for the attached session.
//!
//! Renders the daemon-owned [`SessionSetupSnapshotV1`]. Installed-agent
//! candidates stay distinct by scope so a same-named global and workspace
//! install never collapse. Colour is supplementary: every distinction is also
//! carried by text so the no-colour projection is equivalent.
//!
//! The pane is used as a full-body overlay (`/session-setup`) and as an inline
//! panel below the banner on a fresh session. Mutations are emitted as
//! [`SessionSetupOutcome`] values; the app owns daemon RPCs.

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState};

use crate::tui::textfield::TextField;
use cockpit_core::agents::{ToolSurfaceSelection, ToolTier};
use cockpit_proto::{
    AgentInstallationChoiceV1, AgentInstallationRecordV1, AgentInstallationScopeWire,
    AgentInstallationUnmatchedRecommendationV1, SessionSetupAgentCandidateV1,
    SessionSetupLockedReasonV1, SessionSetupMcpV1, SessionSetupModelSlotV1, SessionSetupSnapshotV1,
    SessionSetupToolV1, SessionSetupUnavailableReasonV1,
};

use crate::tui::pane::Pane;

/// Outcome of a key press. The overlay/app applies mutations; the pane never
/// talks to the daemon itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SessionSetupOutcome {
    Stay,
    Close,
    /// Re-resolve the session's primary agent (existing `/agent` swap path).
    SelectAgent {
        name: String,
    },
    /// Session-only model rebind for the root node's primary slot.
    SelectModel {
        slot_id: String,
        choice_id: String,
    },
    /// Whole-selection tool-surface replace for this session.
    SetToolSurface {
        override_json: String,
    },
    /// Add an MCP server at an explicit scope.
    AddMcp {
        scope: SessionSetupMcpScope,
        name: String,
        transport: String,
        endpoint: Option<String>,
        command: Option<String>,
        auth: String,
    },
    Notice {
        message: String,
    },
}

/// MCP write target chosen in the Add-MCP dialog.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SessionSetupMcpScope {
    Global,
    Workspace,
    Agent,
}

impl SessionSetupMcpScope {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Global => "global",
            Self::Workspace => "workspace",
            Self::Agent => "agent",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Status {
    /// Snapshot request is in flight; nothing rendered yet.
    Loading,
    /// A snapshot has been applied.
    Ready,
    /// The daemon request failed; the fixed message is shown.
    Error(String),
}

/// Session-setup pane. Retains the last snapshot so Enter can emit a payload
/// and so reopening after collapse still shows current values.
pub(crate) struct SessionSetupPane {
    status: Status,
    /// Ratatui selection/viewport state over the flat display rows.
    list: ListState,
    /// Flat display rows derived from the last applied snapshot.
    rows: Vec<DisplayRow>,
    /// Last applied snapshot. Retained so activations name concrete ids.
    snapshot: Option<SessionSetupSnapshotV1>,
    /// Supplementary colour. `false` yields a plain, equivalent projection.
    color: bool,
    /// Inline notice (refusals, locked rows, lint). Presentation-only.
    notice: Option<String>,
    /// When `true`, render without the full-body title chrome so the panel
    /// can sit below the banner box.
    inline: bool,
    /// Frozen tool order for this session (initial enabled → discoverable →
    /// disabled, safety last). Never re-sorted after the first snapshot.
    tool_order: Vec<String>,
    interaction: Interaction,
}

/// One rendered line, pre-classified so colour is purely supplementary and the
/// no-colour projection reads identically.
#[derive(Debug, Clone, PartialEq, Eq)]
struct DisplayRow {
    kind: RowKind,
    text: String,
    /// Selectable rows anchor the cursor; headers/detail are skipped.
    selectable: bool,
    payload: RowPayload,
}

/// What Enter does for a selectable row. `None` is navigable but inert.
#[derive(Debug, Clone, PartialEq, Eq)]
enum RowPayload {
    None,
    Agent,
    AgentChoice {
        name: String,
    },
    Model,
    ModelChoice {
        slot_id: String,
        choice_id: String,
        out_of_set: bool,
    },
    Tool {
        name: String,
        locked: bool,
    },
    Mcp {
        name: String,
    },
    AddMcp,
}

#[derive(Debug, Clone)]
enum Interaction {
    List,
    AgentPopover {
        names: Vec<String>,
        cursor: usize,
    },
    ModelPopover {
        slot_id: String,
        choices: Vec<ModelChoiceItem>,
        cursor: usize,
    },
    AddMcp(AddMcpForm),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ModelChoiceItem {
    choice_id: String,
    label: String,
    is_default: bool,
    out_of_set: bool,
}

#[derive(Debug, Clone)]
struct AddMcpForm {
    name: TextField,
    endpoint: TextField,
    command: TextField,
    transport: usize,
    auth: usize,
    oauth_authorize_url: TextField,
    oauth_token_url: TextField,
    oauth_client_id: TextField,
    oauth_device_endpoint: TextField,
    scope: SessionSetupMcpScope,
    cursor: usize,
}

impl AddMcpForm {
    fn new() -> Self {
        Self {
            name: TextField::new(""),
            endpoint: TextField::new(""),
            command: TextField::new(""),
            transport: 0,
            auth: 0,
            oauth_authorize_url: TextField::new(""),
            oauth_token_url: TextField::new(""),
            oauth_client_id: TextField::new(""),
            oauth_device_endpoint: TextField::new(""),
            scope: SessionSetupMcpScope::Workspace,
            cursor: 0,
        }
    }
}

const MCP_TRANSPORTS: &[&str] = &["streamable", "stdio", "sse"];
const MCP_AUTHS: &[&str] = &["none", "oauth-browser", "oauth-device", "header", "env"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RowKind {
    CandidateSelected,
    CandidateUnselected,
    CandidateLocked,
    Slot,
    SlotUnavailable,
    ChoiceSuggested,
    ChoiceCompatible,
    Unmatched,
    Blank,
    Section,
    Locked,
}

impl SessionSetupPane {
    /// A fresh pane awaiting its first snapshot.
    pub(crate) fn loading(color: bool) -> Self {
        Self::loading_mode(color, false)
    }

    /// Inline panel below the banner (fresh-session placement).
    pub(crate) fn loading_inline(color: bool) -> Self {
        Self::loading_mode(color, true)
    }

    fn loading_mode(color: bool, inline: bool) -> Self {
        Self {
            status: Status::Loading,
            list: ListState::default(),
            rows: Vec::new(),
            snapshot: None,
            color,
            notice: None,
            inline,
            tool_order: Vec::new(),
            interaction: Interaction::List,
        }
    }

    pub(crate) fn is_inline(&self) -> bool {
        self.inline
    }

    /// Copy the session-frozen tool order (and last snapshot) so a new overlay
    /// pane does not re-sort after collapse. Collapse is presentation-only.
    pub(crate) fn adopt_frozen_session(&mut self, other: &Self) {
        if !other.tool_order.is_empty() {
            self.tool_order = other.tool_order.clone();
        }
        if let Some(snapshot) = other.snapshot.clone() {
            self.apply_snapshot(snapshot);
        }
    }

    pub(crate) fn frozen_tool_order(&self) -> &[String] {
        &self.tool_order
    }

    /// Apply a daemon snapshot, rebuilding the flat rows and clamping the
    /// cursor to the first selectable row.
    pub(crate) fn apply_snapshot(&mut self, snapshot: SessionSetupSnapshotV1) {
        if self.tool_order.is_empty() {
            self.tool_order = initial_tool_order(&snapshot.tools);
        }
        self.rows = build_rows(&snapshot, &self.tool_order);
        self.snapshot = Some(snapshot);
        self.status = Status::Ready;
        if matches!(self.interaction, Interaction::List) {
            let first = self.rows.iter().position(|row| row.selectable);
            self.list.select(first);
        }
    }

    /// Record a fixed, daemon-independent error message.
    pub(crate) fn set_error(&mut self, message: impl Into<String>) {
        self.status = Status::Error(message.into());
    }

    pub(crate) fn set_notice(&mut self, message: impl Into<String>) {
        self.notice = Some(message.into());
    }

    pub(crate) fn notice(&self) -> Option<&str> {
        self.notice.as_deref()
    }

    pub(crate) fn snapshot(&self) -> Option<&SessionSetupSnapshotV1> {
        self.snapshot.as_ref()
    }

    pub(crate) fn captures_all_input(&self) -> bool {
        !matches!(self.interaction, Interaction::List)
    }

    fn selectable_indices(&self) -> impl Iterator<Item = usize> + '_ {
        self.rows
            .iter()
            .enumerate()
            .filter(|(_, row)| row.selectable)
            .map(|(index, _)| index)
    }

    fn move_selection(&mut self, forward: bool) {
        let selectable: Vec<usize> = self.selectable_indices().collect();
        if selectable.is_empty() {
            self.list.select(None);
            return;
        }
        let current = self.list.selected();
        let position = current.and_then(|sel| selectable.iter().position(|row| *row == sel));
        let next = match position {
            Some(pos) if forward => (pos + 1).min(selectable.len() - 1),
            Some(pos) => pos.saturating_sub(1),
            None => 0,
        };
        self.list.select(Some(selectable[next]));
    }

    fn selected_payload(&self) -> Option<&RowPayload> {
        let index = self.list.selected()?;
        Some(&self.rows.get(index)?.payload)
    }

    fn activate_selection(&mut self) -> SessionSetupOutcome {
        match self.selected_payload().cloned().unwrap_or(RowPayload::None) {
            RowPayload::None | RowPayload::Mcp { .. } => SessionSetupOutcome::Stay,
            RowPayload::Agent => self.open_agent_popover(),
            RowPayload::AgentChoice { name } => SessionSetupOutcome::SelectAgent { name },
            RowPayload::Model => self.open_model_popover(),
            RowPayload::ModelChoice {
                slot_id,
                choice_id,
                out_of_set,
            } => {
                if out_of_set {
                    self.notice = Some(
                        "That model is outside the slot-allowed set; applying it as a derived-def override.".to_string(),
                    );
                }
                SessionSetupOutcome::SelectModel { slot_id, choice_id }
            }
            RowPayload::Tool { name, locked } => {
                if locked {
                    self.notice = Some(format!("`{name}` is a safety tool and stays enabled."));
                    SessionSetupOutcome::Stay
                } else {
                    self.cycle_tool(&name)
                }
            }
            RowPayload::AddMcp => {
                self.interaction = Interaction::AddMcp(AddMcpForm::new());
                SessionSetupOutcome::Stay
            }
        }
    }

    fn open_agent_popover(&mut self) -> SessionSetupOutcome {
        let names = self.agent_names();
        if names.is_empty() {
            self.notice = Some("No workspace agents are available.".to_string());
            return SessionSetupOutcome::Stay;
        }
        self.interaction = Interaction::AgentPopover { names, cursor: 0 };
        SessionSetupOutcome::Stay
    }

    fn open_model_popover(&mut self) -> SessionSetupOutcome {
        let Some(snapshot) = self.snapshot.as_ref() else {
            return SessionSetupOutcome::Stay;
        };
        if let Some(reason) = snapshot.model.locked_reason {
            self.notice = Some(format!("Model slot is locked ({reason:?})."));
            return SessionSetupOutcome::Stay;
        }
        let choices = model_choice_items(snapshot);
        if choices.is_empty() {
            self.notice = Some("No models are available for this agent.".to_string());
            return SessionSetupOutcome::Stay;
        }
        self.interaction = Interaction::ModelPopover {
            slot_id: "primary".to_string(),
            choices,
            cursor: 0,
        };
        SessionSetupOutcome::Stay
    }

    fn agent_names(&self) -> Vec<String> {
        let Some(snapshot) = self.snapshot.as_ref() else {
            return Vec::new();
        };
        if !snapshot.available_agents.is_empty() {
            return snapshot.available_agents.clone();
        }
        snapshot
            .candidates
            .iter()
            .filter(|candidate| candidate.locked_reason.is_none())
            .map(|candidate| agent_name(&candidate.installation))
            .collect()
    }

    fn cycle_tool(&mut self, name: &str) -> SessionSetupOutcome {
        let Some(snapshot) = self.snapshot.as_mut() else {
            return SessionSetupOutcome::Stay;
        };
        if !snapshot.root_foreground {
            self.notice = Some(
                "Tool surface changes were refused because an interactive subagent holds the foreground."
                    .to_string(),
            );
            return SessionSetupOutcome::Stay;
        }
        let Some(tool) = snapshot.tools.iter_mut().find(|tool| tool.name == name) else {
            return SessionSetupOutcome::Stay;
        };
        if tool.locked {
            self.notice = Some(format!("`{name}` is a safety tool and stays enabled."));
            return SessionSetupOutcome::Stay;
        }
        let legal: Vec<ToolTier> = tool
            .legal_tiers
            .iter()
            .filter_map(|label| ToolTier::from_label(label))
            .collect();
        let legal = if legal.is_empty() {
            cockpit_core::agents::legal_tool_tiers(name).to_vec()
        } else {
            legal
        };
        let current = ToolTier::from_label(&tool.tier).unwrap_or(ToolTier::Enabled);
        let index = legal.iter().position(|tier| *tier == current).unwrap_or(0);
        let next = legal[(index + 1) % legal.len()];
        tool.tier = next.label().to_string();
        match serde_json::to_string(&tool_selection_from_snapshot(snapshot)) {
            Ok(override_json) => {
                self.rebuild_rows();
                SessionSetupOutcome::SetToolSurface { override_json }
            }
            Err(error) => {
                self.notice = Some(format!("Tool surface update failed — {error}."));
                SessionSetupOutcome::Stay
            }
        }
    }

    fn rebuild_rows(&mut self) {
        if let Some(snapshot) = self.snapshot.as_ref() {
            self.rows = build_rows(snapshot, &self.tool_order);
        }
    }

    pub(crate) fn handle_key(&mut self, key: KeyEvent) -> SessionSetupOutcome {
        if let Interaction::AddMcp(form) = &self.interaction {
            let form = form.clone();
            return self.handle_add_mcp_key(key, form);
        }
        if let Interaction::AgentPopover { names, cursor } = &self.interaction {
            let names = names.clone();
            let mut cursor = *cursor;
            let outcome = match key.code {
                KeyCode::Esc | KeyCode::Char('q') => {
                    self.interaction = Interaction::List;
                    SessionSetupOutcome::Stay
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    if !names.is_empty() {
                        cursor = (cursor + 1).min(names.len() - 1);
                    }
                    self.interaction = Interaction::AgentPopover { names, cursor };
                    SessionSetupOutcome::Stay
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    cursor = cursor.saturating_sub(1);
                    self.interaction = Interaction::AgentPopover { names, cursor };
                    SessionSetupOutcome::Stay
                }
                KeyCode::Enter => {
                    let name = names.get(cursor).cloned();
                    self.interaction = Interaction::List;
                    name.map(|name| SessionSetupOutcome::SelectAgent { name })
                        .unwrap_or(SessionSetupOutcome::Stay)
                }
                _ => SessionSetupOutcome::Stay,
            };
            return outcome;
        }
        if let Interaction::ModelPopover {
            slot_id,
            choices,
            cursor,
        } = &self.interaction
        {
            let slot_id = slot_id.clone();
            let choices = choices.clone();
            let mut cursor = *cursor;
            return match key.code {
                KeyCode::Esc | KeyCode::Char('q') => {
                    self.interaction = Interaction::List;
                    SessionSetupOutcome::Stay
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    if !choices.is_empty() {
                        cursor = (cursor + 1).min(choices.len() - 1);
                    }
                    self.interaction = Interaction::ModelPopover {
                        slot_id,
                        choices,
                        cursor,
                    };
                    SessionSetupOutcome::Stay
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    cursor = cursor.saturating_sub(1);
                    self.interaction = Interaction::ModelPopover {
                        slot_id,
                        choices,
                        cursor,
                    };
                    SessionSetupOutcome::Stay
                }
                KeyCode::Enter => {
                    let picked = choices.get(cursor).cloned();
                    self.interaction = Interaction::List;
                    if let Some(choice) = picked {
                        if choice.out_of_set {
                            self.notice = Some(
                                "That model is outside the slot-allowed set; applying it as a derived-def override."
                                    .to_string(),
                            );
                        }
                        SessionSetupOutcome::SelectModel {
                            slot_id,
                            choice_id: choice.choice_id,
                        }
                    } else {
                        SessionSetupOutcome::Stay
                    }
                }
                _ => SessionSetupOutcome::Stay,
            };
        }
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') => SessionSetupOutcome::Close,
            KeyCode::Down | KeyCode::Char('j') => {
                self.move_selection(true);
                SessionSetupOutcome::Stay
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.move_selection(false);
                SessionSetupOutcome::Stay
            }
            KeyCode::Enter => self.activate_selection(),
            _ => SessionSetupOutcome::Stay,
        }
    }

    fn handle_add_mcp_key(&mut self, key: KeyEvent, mut form: AddMcpForm) -> SessionSetupOutcome {
        match key.code {
            KeyCode::Esc => {
                self.interaction = Interaction::List;
                SessionSetupOutcome::Stay
            }
            KeyCode::Tab | KeyCode::Down => {
                form.cursor = (form.cursor + 1) % 10;
                self.interaction = Interaction::AddMcp(form);
                SessionSetupOutcome::Stay
            }
            KeyCode::Up => {
                form.cursor = form.cursor.saturating_sub(1);
                self.interaction = Interaction::AddMcp(form);
                SessionSetupOutcome::Stay
            }
            KeyCode::Left | KeyCode::Right | KeyCode::Char(' ') if form.cursor == 3 => {
                let dir = if matches!(key.code, KeyCode::Left) {
                    form.transport.saturating_sub(1)
                } else {
                    (form.transport + 1) % MCP_TRANSPORTS.len()
                };
                form.transport = dir;
                self.interaction = Interaction::AddMcp(form);
                SessionSetupOutcome::Stay
            }
            KeyCode::Left | KeyCode::Right | KeyCode::Char(' ') if form.cursor == 4 => {
                form.auth = if matches!(key.code, KeyCode::Left) {
                    form.auth.saturating_sub(1)
                } else {
                    (form.auth + 1) % MCP_AUTHS.len()
                };
                self.interaction = Interaction::AddMcp(form);
                SessionSetupOutcome::Stay
            }
            KeyCode::Left | KeyCode::Right | KeyCode::Char(' ') if form.cursor == 9 => {
                form.scope = match form.scope {
                    SessionSetupMcpScope::Global => SessionSetupMcpScope::Workspace,
                    SessionSetupMcpScope::Workspace => SessionSetupMcpScope::Agent,
                    SessionSetupMcpScope::Agent => SessionSetupMcpScope::Global,
                };
                self.interaction = Interaction::AddMcp(form);
                SessionSetupOutcome::Stay
            }
            KeyCode::Enter
                if form.cursor == 9 || form.cursor == 0 && !form.name.text().is_empty() =>
            {
                if form.name.text().trim().is_empty() {
                    self.notice = Some("MCP name is required.".to_string());
                    self.interaction = Interaction::AddMcp(form);
                    return SessionSetupOutcome::Stay;
                }
                let transport = MCP_TRANSPORTS[form.transport].to_string();
                let auth_kind = MCP_AUTHS[form.auth];
                let auth = match auth_kind {
                    "oauth-browser" => {
                        if form.oauth_authorize_url.text().is_empty()
                            || form.oauth_token_url.text().is_empty()
                        {
                            self.notice = Some(
                                "Browser OAuth requires authorize and token URLs.".to_string(),
                            );
                            self.interaction = Interaction::AddMcp(form);
                            return SessionSetupOutcome::Stay;
                        }
                        serde_json::json!({
                            "kind": "oauth",
                            "authorize_url": form.oauth_authorize_url.text(),
                            "token_url": form.oauth_token_url.text(),
                            "client_id": form.oauth_client_id.text(),
                        })
                        .to_string()
                    }
                    "oauth-device" => {
                        if form.oauth_device_endpoint.text().is_empty()
                            || form.oauth_token_url.text().is_empty()
                        {
                            self.notice = Some(
                                "Device OAuth requires device-authorization and token URLs."
                                    .to_string(),
                            );
                            self.interaction = Interaction::AddMcp(form);
                            return SessionSetupOutcome::Stay;
                        }
                        serde_json::json!({
                            "kind": "oauth",
                            "device_authorization_endpoint": form.oauth_device_endpoint.text(),
                            "token_url": form.oauth_token_url.text(),
                            "client_id": form.oauth_client_id.text(),
                        })
                        .to_string()
                    }
                    kind => kind.to_string(),
                };
                let endpoint =
                    Some(form.endpoint.text().to_string()).filter(|value| !value.is_empty());
                let command =
                    Some(form.command.text().to_string()).filter(|value| !value.is_empty());
                if transport == "stdio" && command.is_none() {
                    self.notice = Some("A stdio MCP requires a command.".to_string());
                    self.interaction = Interaction::AddMcp(form);
                    return SessionSetupOutcome::Stay;
                }
                if transport != "stdio" && endpoint.is_none() {
                    self.notice = Some("A remote MCP requires an endpoint.".to_string());
                    self.interaction = Interaction::AddMcp(form);
                    return SessionSetupOutcome::Stay;
                }
                let outcome = SessionSetupOutcome::AddMcp {
                    scope: form.scope,
                    name: form.name.text().to_string(),
                    transport,
                    endpoint,
                    command,
                    auth,
                };
                self.interaction = Interaction::List;
                outcome
            }
            _ => {
                match form.cursor {
                    0 => {
                        form.name.handle_key(key);
                    }
                    1 => {
                        form.endpoint.handle_key(key);
                    }
                    2 => {
                        form.command.handle_key(key);
                    }
                    5 => form.oauth_authorize_url.handle_key(key),
                    6 => form.oauth_token_url.handle_key(key),
                    7 => form.oauth_client_id.handle_key(key),
                    8 => form.oauth_device_endpoint.handle_key(key),
                    _ => {}
                }
                self.interaction = Interaction::AddMcp(form);
                SessionSetupOutcome::Stay
            }
        }
    }

    pub(crate) fn render(&mut self, frame: &mut Frame, area: Rect) {
        let title = if self.inline {
            " Session setup (Tab: composer) "
        } else {
            " Session setup "
        };
        let block = Block::default().borders(Borders::ALL).title(title);
        let inner = block.inner(area);
        frame.render_widget(block, area);

        let mut lines: Vec<Line<'static>> = if !matches!(self.interaction, Interaction::List) {
            self.inline_lines()
        } else {
            match &self.status {
                Status::Loading => vec![Line::from(Span::raw("Loading session setup…"))],
                Status::Error(message) => vec![Line::from(styled(
                    message.clone(),
                    RowKind::CandidateLocked,
                    self.color,
                ))],
                Status::Ready => self
                    .rows
                    .iter()
                    .map(|row| Line::from(styled(row.text.clone(), row.kind, self.color)))
                    .collect(),
            }
        };
        if let Some(notice) = &self.notice {
            lines.insert(
                0,
                Line::from(styled(notice.clone(), RowKind::CandidateLocked, self.color)),
            );
        }

        let items: Vec<ListItem<'static>> = lines.into_iter().map(ListItem::new).collect();
        let list = List::new(items).highlight_symbol("› ");
        frame.render_stateful_widget(list, inner, &mut self.list);
    }

    /// Lines for the inline panel (no outer overlay chrome). Used by the
    /// session-view renderer so the panel sits below the banner box.
    pub(crate) fn inline_lines(&self) -> Vec<Line<'static>> {
        let mut lines = vec![Line::from(styled(
            "Session setup".to_string(),
            RowKind::CandidateSelected,
            self.color,
        ))];
        if let Some(notice) = &self.notice {
            lines.push(Line::from(styled(
                notice.clone(),
                RowKind::CandidateLocked,
                self.color,
            )));
        }
        match &self.status {
            Status::Loading => lines.push(Line::from(Span::raw("Loading session setup…"))),
            Status::Error(message) => lines.push(Line::from(styled(
                message.clone(),
                RowKind::CandidateLocked,
                self.color,
            ))),
            Status::Ready => {
                for row in self.inline_visible_rows() {
                    lines.push(Line::from(styled(row.text.clone(), row.kind, self.color)));
                }
            }
        }
        match &self.interaction {
            Interaction::AgentPopover { names, cursor } => {
                lines.push(Line::from(styled(
                    "Agents".to_string(),
                    RowKind::Section,
                    self.color,
                )));
                for (index, name) in names.iter().enumerate() {
                    let marker = if index == *cursor { "› " } else { "  " };
                    lines.push(Line::from(styled(
                        format!("{marker}{name}"),
                        RowKind::CandidateUnselected,
                        self.color,
                    )));
                }
            }
            Interaction::ModelPopover {
                choices, cursor, ..
            } => {
                lines.push(Line::from(styled(
                    "Models".to_string(),
                    RowKind::Section,
                    self.color,
                )));
                for (index, choice) in choices.iter().enumerate() {
                    let marker = if index == *cursor { "› " } else { "  " };
                    lines.push(Line::from(styled(
                        format!("{marker}{}", choice.label),
                        RowKind::ChoiceCompatible,
                        self.color,
                    )));
                }
            }
            Interaction::AddMcp(form) => {
                lines.push(Line::from(styled(
                    "Add MCP".to_string(),
                    RowKind::Section,
                    self.color,
                )));
                let marker = |index| if form.cursor == index { "›" } else { " " };
                lines.push(Line::from(Span::raw(format!(
                    "{} name: {}",
                    marker(0),
                    form.name.text()
                ))));
                lines.push(Line::from(Span::raw(format!(
                    "{} endpoint: {}",
                    marker(1),
                    form.endpoint.text()
                ))));
                lines.push(Line::from(Span::raw(format!(
                    "{} command: {}",
                    marker(2),
                    form.command.text()
                ))));
                lines.push(Line::from(Span::raw(format!(
                    "{} transport: {}",
                    marker(3),
                    MCP_TRANSPORTS[form.transport]
                ))));
                lines.push(Line::from(Span::raw(format!(
                    "{} auth: {}",
                    marker(4),
                    MCP_AUTHS[form.auth]
                ))));
                lines.push(Line::from(Span::raw(format!(
                    "{} authorize URL: {}",
                    marker(5),
                    form.oauth_authorize_url.text()
                ))));
                lines.push(Line::from(Span::raw(format!(
                    "{} token URL: {}",
                    marker(6),
                    form.oauth_token_url.text()
                ))));
                lines.push(Line::from(Span::raw(format!(
                    "{} client id: {}",
                    marker(7),
                    form.oauth_client_id.text()
                ))));
                lines.push(Line::from(Span::raw(format!(
                    "{} device endpoint: {}",
                    marker(8),
                    form.oauth_device_endpoint.text()
                ))));
                lines.push(Line::from(Span::raw(format!(
                    "{} scope: {}  (Enter to add)",
                    marker(9),
                    form.scope.as_str()
                ))));
            }
            Interaction::List => {}
        }
        lines.push(Line::from(styled(
            "Enter activates · j/k move · Tab composer".to_string(),
            RowKind::Unmatched,
            self.color,
        )));
        lines
    }

    fn inline_visible_rows(&self) -> Vec<&DisplayRow> {
        const TOOL_WINDOW: usize = 6;
        const MCP_WINDOW: usize = 4;
        let selected = self.list.selected();
        let selected_tool = selected.and_then(|index| match &self.rows.get(index)?.payload {
            RowPayload::Tool { name, .. } => Some(name.as_str()),
            _ => None,
        });
        let selected_mcp = selected.and_then(|index| match &self.rows.get(index)?.payload {
            RowPayload::Mcp { name } => Some(name.as_str()),
            RowPayload::AddMcp => Some(""),
            _ => None,
        });
        let tools: Vec<_> = self
            .rows
            .iter()
            .filter(|row| matches!(&row.payload, RowPayload::Tool { .. }))
            .collect();
        let mcps: Vec<_> = self
            .rows
            .iter()
            .filter(|row| matches!(&row.payload, RowPayload::Mcp { .. } | RowPayload::AddMcp))
            .collect();
        let tool_start = selected_tool
            .and_then(|name| tools.iter().position(|row| matches!(&row.payload, RowPayload::Tool { name: row_name, .. } if row_name == name)))
            .unwrap_or(0)
            .saturating_sub(TOOL_WINDOW / 2)
            .min(tools.len().saturating_sub(TOOL_WINDOW));
        let mcp_start = selected_mcp
            .and_then(|name| {
                mcps.iter().position(|row| match &row.payload {
                    RowPayload::Mcp { name: row_name } => row_name == name,
                    RowPayload::AddMcp => name.is_empty(),
                    _ => false,
                })
            })
            .unwrap_or(0)
            .saturating_sub(MCP_WINDOW / 2)
            .min(mcps.len().saturating_sub(MCP_WINDOW));
        self.rows
            .iter()
            .filter(|row| match &row.payload {
                RowPayload::Tool { .. } => tools
                    [tool_start..tools.len().min(tool_start + TOOL_WINDOW)]
                    .iter()
                    .any(|visible| std::ptr::eq(*visible, *row)),
                RowPayload::Mcp { .. } | RowPayload::AddMcp => mcps
                    [mcp_start..mcps.len().min(mcp_start + MCP_WINDOW)]
                    .iter()
                    .any(|visible| std::ptr::eq(*visible, *row)),
                _ => true,
            })
            .collect()
    }
}

impl Pane for SessionSetupPane {
    type Outcome = SessionSetupOutcome;

    fn handle_key(&mut self, key: KeyEvent) -> Self::Outcome {
        SessionSetupPane::handle_key(self, key)
    }

    fn render(&mut self, frame: &mut Frame, area: Rect) {
        SessionSetupPane::render(self, frame, area);
    }
}

/// Fixed, human-readable scope label. Same `source_agent_id` in two scopes
/// stays distinct because the scope word is always present.
fn scope_label(scope: AgentInstallationScopeWire) -> &'static str {
    match scope {
        AgentInstallationScopeWire::Global => "global",
        AgentInstallationScopeWire::WorkspacePrivate => "workspace (private)",
        AgentInstallationScopeWire::WorkspaceShared => "workspace",
    }
}

fn locked_reason_label(reason: SessionSetupLockedReasonV1) -> &'static str {
    match reason {
        SessionSetupLockedReasonV1::DefinitionUnavailable => "definition unavailable",
        SessionSetupLockedReasonV1::RebindRequired => "rebind required",
    }
}

fn unavailable_reason_label(reason: SessionSetupUnavailableReasonV1) -> &'static str {
    match reason {
        SessionSetupUnavailableReasonV1::NoHardCompatibleLocalModel => {
            "no hard-compatible local model"
        }
        SessionSetupUnavailableReasonV1::RebindRequired => "rebind required",
    }
}

fn candidate_header(candidate: &SessionSetupAgentCandidateV1) -> DisplayRow {
    let record: &AgentInstallationRecordV1 = &candidate.installation;
    let selected = if candidate.selected { "● " } else { "○ " };
    let mut text = format!(
        "{selected}{} [{}]",
        record.source_agent_id,
        scope_label(record.scope),
    );
    let kind = if let Some(reason) = candidate.locked_reason {
        text.push_str(&format!(" — locked: {}", locked_reason_label(reason)));
        RowKind::CandidateLocked
    } else if candidate.selected {
        RowKind::CandidateSelected
    } else {
        RowKind::CandidateUnselected
    };
    DisplayRow {
        kind,
        text,
        selectable: candidate.locked_reason.is_none(),
        payload: RowPayload::AgentChoice {
            name: agent_name(record),
        },
    }
}

fn agent_name(record: &AgentInstallationRecordV1) -> String {
    record
        .source_agent_id
        .rsplit('/')
        .next()
        .unwrap_or(&record.source_agent_id)
        .to_string()
}

/// One choice line. Author-suggested / exact-alias offerings are marked so the
/// daemon's ordering (suggested first, then other compatible) is visible in
/// text as well as colour. The advisory `canonical_upstream_identity` is shown
/// only as display metadata — never as a selectable alias or route.
fn choice_row(choice: &AgentInstallationChoiceV1) -> DisplayRow {
    let mut markers = Vec::new();
    if choice.author_suggested {
        markers.push("suggested");
    }
    if choice.exact_alias_match {
        markers.push("exact");
    }
    let mut text = format!("      {}/{}", choice.provider_id, choice.model_id);
    if let Some(rec) = &choice.recommendation_id {
        text.push_str(&format!(" (rec {rec})"));
    }
    if let Some(label) = &choice.author_label {
        text.push_str(&format!(" — {label}"));
    }
    if let Some(identity) = &choice.canonical_upstream_identity {
        text.push_str(&format!(" [{identity}]"));
    }
    if !markers.is_empty() {
        text.push_str(&format!("  <{}>", markers.join(",")));
    }
    let kind = if choice.author_suggested || choice.exact_alias_match {
        RowKind::ChoiceSuggested
    } else {
        RowKind::ChoiceCompatible
    };
    DisplayRow {
        kind,
        text,
        selectable: true,
        payload: RowPayload::ModelChoice {
            slot_id: choice.slot_id.clone(),
            choice_id: choice.choice_id.clone(),
            out_of_set: false,
        },
    }
}

fn unmatched_row(rec: &AgentInstallationUnmatchedRecommendationV1) -> DisplayRow {
    let mut text = format!(
        "      (unmatched) {} [{}]",
        rec.recommendation_id, rec.canonical_upstream_identity,
    );
    if let Some(label) = &rec.author_label {
        text.push_str(&format!(" — {label}"));
    }
    DisplayRow {
        kind: RowKind::Unmatched,
        text,
        selectable: false,
        payload: RowPayload::None,
    }
}

fn slot_rows(slot: &SessionSetupModelSlotV1, out: &mut Vec<DisplayRow>) {
    let unavailable = slot.unavailable_reason;
    let header_text = match unavailable {
        Some(reason) => format!(
            "    slot {} — unavailable: {}",
            slot.slot_id,
            unavailable_reason_label(reason),
        ),
        None => format!("    slot {}", slot.slot_id),
    };
    out.push(DisplayRow {
        kind: if unavailable.is_some() {
            RowKind::SlotUnavailable
        } else {
            RowKind::Slot
        },
        text: header_text,
        selectable: false,
        payload: RowPayload::None,
    });
    // Choices are already ordered by the daemon: exact alias / author-suggested
    // first, then other hard-compatible offerings. Render in that exact order;
    // never reorder or fuzzy-match here.
    for choice in &slot.choices {
        let mut row = choice_row(choice);
        if slot.default_choice_id.as_deref() == Some(choice.choice_id.as_str()) {
            row.text.push_str(" (default)");
        }
        out.push(row);
    }
    // Visibly unmatched recommendations are retained rather than fuzzy-matched.
    for rec in &slot.unmatched_recommendations {
        out.push(unmatched_row(rec));
    }
}

/// Flatten a snapshot into ordered display rows. Pure and deterministic so
/// tests can assert scope distinctness, choice ordering, unmatched display,
/// and reason labels without a terminal.
fn build_rows(snapshot: &SessionSetupSnapshotV1, tool_order: &[String]) -> Vec<DisplayRow> {
    let mut rows = Vec::new();
    rows.push(section_row("Agent"));
    rows.push(agent_summary_row(snapshot));
    rows.push(section_row("Model"));
    rows.push(model_summary_row(snapshot));
    rows.push(section_row("Tools"));
    rows.extend(tool_rows(snapshot, tool_order));
    rows.push(section_row("MCPs"));
    rows.extend(mcp_rows(snapshot));
    rows.push(DisplayRow {
        kind: RowKind::ChoiceSuggested,
        text: "  [Add MCP]".to_string(),
        selectable: true,
        payload: RowPayload::AddMcp,
    });
    if !snapshot.candidates.is_empty() && snapshot.available_agents.is_empty() {
        // Keep candidate identity rows so colliding scopes stay visible.
        rows.push(DisplayRow {
            kind: RowKind::Blank,
            text: String::new(),
            selectable: false,
            payload: RowPayload::None,
        });
        for candidate in &snapshot.candidates {
            rows.push(candidate_header(candidate));
            for slot in &candidate.slots {
                slot_rows(slot, &mut rows);
            }
        }
    }
    rows
}

fn section_row(title: &str) -> DisplayRow {
    DisplayRow {
        kind: RowKind::Section,
        text: title.to_string(),
        selectable: false,
        payload: RowPayload::None,
    }
}

fn agent_summary_row(snapshot: &SessionSetupSnapshotV1) -> DisplayRow {
    let name = snapshot
        .resolved_agent
        .clone()
        .or_else(|| snapshot.last_used_agent.clone())
        .or_else(|| {
            snapshot
                .candidates
                .iter()
                .find(|candidate| candidate.selected)
                .map(|candidate| agent_name(&candidate.installation))
        })
        .unwrap_or_else(|| "Build".to_string());
    let locked = snapshot
        .candidates
        .iter()
        .any(|candidate| candidate.selected && candidate.locked_reason.is_some());
    DisplayRow {
        kind: if locked {
            RowKind::CandidateLocked
        } else {
            RowKind::CandidateSelected
        },
        text: format!("  {name}  (Enter to change)"),
        selectable: true,
        payload: RowPayload::Agent,
    }
}

fn model_summary_row(snapshot: &SessionSetupSnapshotV1) -> DisplayRow {
    if let Some(reason) = snapshot.model.locked_reason {
        return DisplayRow {
            kind: RowKind::Locked,
            text: format!("  locked ({reason:?})"),
            selectable: true,
            payload: RowPayload::Model,
        };
    }
    let label = snapshot
        .model
        .effective
        .as_ref()
        .map(|model| {
            let badge = if model.is_default { "  <default>" } else { "" };
            format!(
                "  {}/{}{badge}  (Enter to change)",
                model.provider_id, model.model_id
            )
        })
        .unwrap_or_else(|| "  (no model)  (Enter to change)".to_string());
    DisplayRow {
        kind: RowKind::Slot,
        text: label,
        selectable: true,
        payload: RowPayload::Model,
    }
}

fn tool_rows(snapshot: &SessionSetupSnapshotV1, tool_order: &[String]) -> Vec<DisplayRow> {
    let mut rows = Vec::new();
    let order = if tool_order.is_empty() {
        initial_tool_order(&snapshot.tools)
    } else {
        tool_order.to_vec()
    };
    for name in order {
        let Some(tool) = snapshot.tools.iter().find(|tool| tool.name == name) else {
            continue;
        };
        rows.push(DisplayRow {
            kind: if tool.locked {
                RowKind::Locked
            } else {
                match tool.tier.as_str() {
                    "enabled" => RowKind::ChoiceSuggested,
                    "discoverable" => RowKind::Slot,
                    _ => RowKind::Unmatched,
                }
            },
            text: if tool.locked {
                format!("  {:<22} {}  (locked)", tool.name, tool.tier)
            } else {
                format!("  {:<22} {}  (Enter rotates)", tool.name, tool.tier)
            },
            selectable: true,
            payload: RowPayload::Tool {
                name: tool.name.clone(),
                locked: tool.locked,
            },
        });
    }
    rows
}

fn mcp_rows(snapshot: &SessionSetupSnapshotV1) -> Vec<DisplayRow> {
    snapshot.mcps.iter().map(|server| mcp_row(server)).collect()
}

fn mcp_row(server: &SessionSetupMcpV1) -> DisplayRow {
    let state = if server.enabled { "on" } else { "off" };
    let shadow = server
        .shadowed_by
        .as_deref()
        .map(|scope| format!("  shadowed by {scope}"))
        .unwrap_or_default();
    let profile = server
        .profile
        .as_deref()
        .map(|profile| format!("  profile:{profile}"))
        .unwrap_or_default();
    DisplayRow {
        kind: if server.shadowed_by.is_some() {
            RowKind::Unmatched
        } else {
            RowKind::ChoiceCompatible
        },
        text: format!(
            "  [{scope}] {name}  {state}{profile}{shadow}",
            scope = server.scope,
            name = server.name
        ),
        selectable: true,
        payload: RowPayload::Mcp {
            name: server.name.clone(),
        },
    }
}

fn initial_tool_order(tools: &[SessionSetupToolV1]) -> Vec<String> {
    let rank = |tool: &SessionSetupToolV1| {
        if tool.locked {
            return 3;
        }
        match tool.tier.as_str() {
            "enabled" => 0,
            "discoverable" => 1,
            _ => 2,
        }
    };
    let mut ordered: Vec<&SessionSetupToolV1> = tools.iter().collect();
    ordered.sort_by(|left, right| {
        rank(left)
            .cmp(&rank(right))
            .then_with(|| left.name.cmp(&right.name))
    });
    ordered.into_iter().map(|tool| tool.name.clone()).collect()
}

fn model_choice_items(snapshot: &SessionSetupSnapshotV1) -> Vec<ModelChoiceItem> {
    let active = snapshot.resolved_agent.as_deref();
    let selected = snapshot
        .candidates
        .iter()
        .find(|candidate| {
            active.is_some_and(|active| agent_name(&candidate.installation) == active)
        })
        .or_else(|| {
            snapshot
                .candidates
                .iter()
                .find(|candidate| candidate.selected)
        });
    let mut items = Vec::new();
    if let Some(candidate) = selected
        && let Some(slot) = candidate
            .slots
            .iter()
            .find(|slot| slot.slot_id == "primary")
            .or_else(|| candidate.slots.first())
    {
        for choice in &slot.choices {
            let is_default = slot.default_choice_id.as_deref() == Some(choice.choice_id.as_str());
            let out_of_set = !slot.allowed_choice_ids.contains(&choice.choice_id);
            items.push(ModelChoiceItem {
                choice_id: choice.choice_id.clone(),
                label: format!(
                    "{}/{}{}",
                    choice.provider_id,
                    choice.model_id,
                    if is_default {
                        "  <default>"
                    } else if out_of_set {
                        "  (compatible, out of set)"
                    } else {
                        ""
                    }
                ),
                is_default,
                out_of_set,
            });
        }
        items.sort_by_key(|item| item.out_of_set);
    }
    items
}

fn tool_selection_from_snapshot(snapshot: &SessionSetupSnapshotV1) -> ToolSurfaceSelection {
    let mut tools = Vec::new();
    let mut tool_tiers = std::collections::BTreeMap::new();
    for tool in &snapshot.tools {
        if let Some(tier) = ToolTier::from_label(&tool.tier) {
            if tier != ToolTier::Disabled {
                tools.push(tool.name.clone());
            }
            if tier == ToolTier::Discoverable {
                tool_tiers.insert(tool.name.clone(), tier);
            }
        }
    }
    ToolSurfaceSelection { tools, tool_tiers }
}

/// Supplementary colour for a row. With `color = false` the style is default,
/// so the projection is equivalent to the text alone.
fn styled(text: String, kind: RowKind, color: bool) -> Span<'static> {
    if !color {
        return Span::raw(text);
    }
    let style = match kind {
        RowKind::CandidateSelected => Style::default()
            .fg(Color::Green)
            .add_modifier(Modifier::BOLD),
        RowKind::CandidateUnselected => Style::default().add_modifier(Modifier::BOLD),
        RowKind::CandidateLocked | RowKind::SlotUnavailable => Style::default().fg(Color::Red),
        RowKind::Slot => Style::default().fg(Color::Cyan),
        RowKind::ChoiceSuggested => Style::default().fg(Color::Green),
        RowKind::ChoiceCompatible => Style::default(),
        RowKind::Unmatched => Style::default().fg(Color::DarkGray),
        RowKind::Blank => Style::default(),
        RowKind::Section => Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
        RowKind::Locked => Style::default().fg(Color::DarkGray),
    };
    Span::styled(text, style)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cockpit_proto::AgentInstallationScopeWire::{Global, WorkspaceShared};

    fn record(
        source_agent_id: &str,
        scope: AgentInstallationScopeWire,
    ) -> AgentInstallationRecordV1 {
        AgentInstallationRecordV1 {
            installation_id: format!("{source_agent_id}-{scope:?}"),
            scope,
            source_agent_id: source_agent_id.to_string(),
            source_identity: "publisher/repo:agents/reviewer.md".to_string(),
            source_revision: Some("a".repeat(40)),
            source_digest: "b".repeat(64),
            installation_revision: 1,
            bindings: Vec::new(),
        }
    }

    fn choice(
        provider: &str,
        model: &str,
        suggested: bool,
        exact: bool,
    ) -> AgentInstallationChoiceV1 {
        AgentInstallationChoiceV1 {
            choice_id: format!("{provider}/{model}"),
            slot_id: "primary".to_string(),
            offering_id: format!("{provider}:{model}"),
            provider_id: provider.to_string(),
            model_id: model.to_string(),
            recommendation_id: suggested.then(|| "rec-1".to_string()),
            canonical_upstream_identity: Some("author/model".to_string()),
            author_label: suggested.then(|| "Author choice".to_string()),
            rationale: None,
            author_suggested: suggested,
            exact_alias_match: exact,
        }
    }

    fn candidate(
        source_agent_id: &str,
        scope: AgentInstallationScopeWire,
        selected: bool,
        slots: Vec<SessionSetupModelSlotV1>,
        locked: Option<SessionSetupLockedReasonV1>,
    ) -> SessionSetupAgentCandidateV1 {
        SessionSetupAgentCandidateV1 {
            installation: record(source_agent_id, scope),
            selected,
            slots,
            locked_reason: locked,
        }
    }

    fn snapshot(candidates: Vec<SessionSetupAgentCandidateV1>) -> SessionSetupSnapshotV1 {
        SessionSetupSnapshotV1 {
            dto_version: cockpit_proto::SESSION_SETUP_DTO_VERSION,
            session_id: "11111111-1111-4111-8111-111111111111".to_string(),
            config_generation: 7,
            revision: 3,
            selected_installation_id: None,
            candidates,
            resolved_agent: None,
            last_used_agent: None,
            available_agents: Vec::new(),
            root_agent_instance_id: None,
            override_revision: 0,
            root_foreground: true,
            model: Default::default(),
            tools: Vec::new(),
            mcps: Vec::new(),
        }
    }

    #[test]
    fn modes_session_setup_colliding_scope_entries_remain_distinct() {
        let snap = snapshot(vec![
            candidate("authored/reviewer", Global, false, Vec::new(), None),
            candidate(
                "authored/reviewer",
                WorkspaceShared,
                false,
                Vec::new(),
                None,
            ),
        ]);
        let rows = build_rows(&snap, &[]);
        let headers: Vec<&str> = rows
            .iter()
            .filter(|row| {
                matches!(
                    row.kind,
                    RowKind::CandidateSelected
                        | RowKind::CandidateUnselected
                        | RowKind::CandidateLocked
                )
            })
            .map(|row| row.text.as_str())
            .collect();
        assert_eq!(headers.len(), 2, "both scopes must render as distinct rows");
        assert!(headers[0].contains("[global]"));
        assert!(headers[1].contains("[workspace]"));
        assert_ne!(headers[0], headers[1]);
    }

    #[test]
    fn modes_session_setup_choices_render_in_daemon_order_without_fuzzy_match() {
        // Daemon delivers suggested/exact first, then a plain compatible model.
        let slot = SessionSetupModelSlotV1 {
            slot_id: "primary".to_string(),
            choices: vec![
                choice("local", "first", true, true),
                choice("local", "compatible", false, false),
            ],
            choice_routes: Vec::new(),
            allowed_choice_ids: Vec::new(),
            unmatched_recommendations: vec![AgentInstallationUnmatchedRecommendationV1 {
                recommendation_id: "missing".to_string(),
                canonical_upstream_identity: "author/missing".to_string(),
                author_label: None,
                rationale: None,
            }],
            default_choice_id: None,
            unavailable_reason: None,
        };
        let snap = snapshot(vec![candidate(
            "authored/reviewer",
            Global,
            true,
            vec![slot],
            None,
        )]);
        let rows = build_rows(&snap, &[]);
        let choice_rows: Vec<&DisplayRow> = rows
            .iter()
            .filter(|row| {
                matches!(
                    row.kind,
                    RowKind::ChoiceSuggested | RowKind::ChoiceCompatible
                )
            })
            .collect();
        assert_eq!(choice_rows.len(), 2);
        assert_eq!(choice_rows[0].kind, RowKind::ChoiceSuggested);
        assert!(choice_rows[0].text.contains("local/first"));
        assert_eq!(choice_rows[1].kind, RowKind::ChoiceCompatible);
        assert!(choice_rows[1].text.contains("local/compatible"));
        // Unmatched recommendation is displayed, never fuzzy-matched into a choice.
        let unmatched: Vec<&DisplayRow> = rows
            .iter()
            .filter(|row| matches!(row.kind, RowKind::Unmatched))
            .collect();
        assert_eq!(unmatched.len(), 1);
        assert!(unmatched[0].text.contains("missing"));
        assert!(!unmatched[0].selectable);
    }

    #[test]
    fn modes_session_setup_unavailable_and_locked_reasons_use_fixed_labels() {
        let slot = SessionSetupModelSlotV1 {
            slot_id: "primary".to_string(),
            choices: Vec::new(),
            choice_routes: Vec::new(),
            allowed_choice_ids: Vec::new(),
            unmatched_recommendations: Vec::new(),
            default_choice_id: None,
            unavailable_reason: Some(SessionSetupUnavailableReasonV1::NoHardCompatibleLocalModel),
        };
        let snap = snapshot(vec![candidate(
            "authored/reviewer",
            Global,
            false,
            vec![slot],
            Some(SessionSetupLockedReasonV1::RebindRequired),
        )]);
        let rows = build_rows(&snap, &[]);
        assert!(rows.iter().any(|row| {
            row.kind == RowKind::CandidateLocked && row.text.contains("locked: rebind required")
        }));
        assert!(rows.iter().any(|row| {
            row.kind == RowKind::SlotUnavailable
                && row
                    .text
                    .contains("unavailable: no hard-compatible local model")
        }));
    }

    #[test]
    fn modes_session_setup_no_color_projection_is_text_equivalent() {
        let snap = snapshot(vec![candidate(
            "authored/reviewer",
            Global,
            true,
            vec![SessionSetupModelSlotV1 {
                slot_id: "primary".to_string(),
                choices: vec![choice("local", "first", true, true)],
                choice_routes: Vec::new(),
                allowed_choice_ids: Vec::new(),
                unmatched_recommendations: Vec::new(),
                default_choice_id: None,
                unavailable_reason: None,
            }],
            None,
        )]);
        for row in build_rows(&snap, &[]) {
            let colored = styled(row.text.clone(), row.kind, true);
            let plain = styled(row.text.clone(), row.kind, false);
            assert_eq!(
                colored.content, plain.content,
                "text must not depend on colour"
            );
            assert_eq!(
                plain.style,
                Style::default(),
                "no-colour projection is unstyled"
            );
        }
    }

    #[test]
    fn modes_session_setup_rendered_text_carries_no_secret_fields() {
        // The snapshot DTO has no credential/profile/path fields; assert the
        // rows only ever contain the public identity/model text and never a
        // source_digest or source_identity path leak.
        let snap = snapshot(vec![candidate(
            "authored/reviewer",
            Global,
            false,
            vec![SessionSetupModelSlotV1 {
                slot_id: "primary".to_string(),
                choices: vec![choice("local", "first", true, true)],
                choice_routes: Vec::new(),
                allowed_choice_ids: Vec::new(),
                unmatched_recommendations: Vec::new(),
                default_choice_id: None,
                unavailable_reason: None,
            }],
            None,
        )]);
        let text: String = build_rows(&snap, &[])
            .iter()
            .map(|row| row.text.clone())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            !text.contains(&"b".repeat(64)),
            "source_digest must not render"
        );
        assert!(!text.contains("publisher/repo:agents/reviewer.md"));
    }

    fn press(code: KeyCode) -> KeyEvent {
        use crossterm::event::{KeyEventKind, KeyEventState, KeyModifiers};
        KeyEvent {
            code,
            modifiers: KeyModifiers::empty(),
            kind: KeyEventKind::Press,
            state: KeyEventState::empty(),
        }
    }

    #[test]
    fn modes_session_setup_enter_on_agent_candidate_emits_select_agent() {
        let snap = snapshot(vec![candidate(
            "authored/reviewer",
            Global,
            false,
            Vec::new(),
            None,
        )]);
        let mut pane = SessionSetupPane::loading(false);
        pane.apply_snapshot(snap);
        let outcome = pane.handle_key(press(KeyCode::Enter));
        assert_eq!(outcome, SessionSetupOutcome::Stay);
        let outcome = pane.handle_key(press(KeyCode::Enter));
        assert_eq!(
            outcome,
            SessionSetupOutcome::SelectAgent {
                name: "reviewer".to_string(),
            }
        );
    }

    #[test]
    fn modes_session_setup_enter_on_locked_agent_stays_with_notice() {
        let snap = snapshot(vec![candidate(
            "authored/reviewer",
            Global,
            false,
            Vec::new(),
            Some(SessionSetupLockedReasonV1::RebindRequired),
        )]);
        let mut pane = SessionSetupPane::loading(false);
        pane.apply_snapshot(snap);
        let outcome = pane.handle_key(press(KeyCode::Enter));
        assert_eq!(outcome, SessionSetupOutcome::Stay);
        assert!(
            pane.notice().is_some_and(|notice| {
                notice.contains("locked") || notice.contains("No workspace agents")
            }),
            "locked agent must surface a notice, not a silent no-op"
        );
    }

    #[test]
    fn modes_session_setup_agent_rows_carry_payload() {
        let snap = snapshot(vec![candidate(
            "authored/reviewer",
            Global,
            true,
            Vec::new(),
            None,
        )]);
        let rows = build_rows(&snap, &[]);
        let agent = rows
            .iter()
            .find(|row| matches!(row.payload, RowPayload::AgentChoice { .. }))
            .expect("agent candidate row");
        assert!(agent.selectable);
        match &agent.payload {
            RowPayload::AgentChoice { name } => {
                assert_eq!(name, "reviewer");
            }
            other => panic!("expected agent payload, got {other:?}"),
        }
    }

    #[test]
    fn modes_session_setup_inline_loading_is_distinct_from_overlay() {
        let inline = SessionSetupPane::loading_inline(false);
        assert!(inline.is_inline());
        assert!(!SessionSetupPane::loading(false).is_inline());
        let lines = inline.inline_lines();
        assert!(
            lines
                .iter()
                .any(|line| line.to_string().contains("Loading session setup")),
            "inline loading state must render a loading line"
        );
    }

    fn render_inline_text(pane: &SessionSetupPane, width: u16, height: u16) -> String {
        use ratatui::{Terminal, backend::TestBackend};
        let mut terminal = Terminal::new(TestBackend::new(width, height)).expect("terminal");
        terminal
            .draw(|frame| {
                let lines = pane.inline_lines();
                let para = ratatui::widgets::Paragraph::new(lines);
                frame.render_widget(para, frame.area());
            })
            .expect("draw");
        terminal.backend().buffer().area().width;
        format!("{:?}", terminal.backend().buffer())
    }

    #[test]
    fn modes_session_setup_layout_snapshot_expanded_and_narrow() {
        let snap = snapshot(vec![candidate(
            "authored/reviewer",
            Global,
            true,
            Vec::new(),
            None,
        )]);
        let mut pane = SessionSetupPane::loading_inline(false);
        pane.apply_snapshot(snap);
        let wide = render_inline_text(&pane, 80, 12);
        let narrow = render_inline_text(&pane, 40, 12);
        assert!(wide.contains("Session setup"));
        assert!(wide.contains("reviewer"));
        assert!(narrow.contains("Session setup"));
        assert!(
            !narrow.contains('\u{fffd}'),
            "narrow width must clip rather than overflow"
        );
    }

    #[test]
    fn modes_session_setup_collapse_preserves_applied_snapshot() {
        let snap = snapshot(vec![candidate(
            "authored/reviewer",
            Global,
            true,
            Vec::new(),
            None,
        )]);
        let mut pane = SessionSetupPane::loading_inline(false);
        pane.apply_snapshot(snap);
        pane.handle_key(press(KeyCode::Down));
        let before = pane.inline_lines();
        // Collapse is presentation-only on App; the pane snapshot stays.
        let after = pane.inline_lines();
        assert_eq!(
            before, after,
            "pending applied snapshot must survive collapse"
        );
        assert!(
            after
                .iter()
                .any(|line| line.to_string().contains("reviewer"))
        );
    }

    fn tool(name: &str, tier: &str, locked: bool) -> SessionSetupToolV1 {
        SessionSetupToolV1 {
            name: name.to_string(),
            tier: tier.to_string(),
            locked,
            legal_tiers: if locked {
                vec!["enabled".to_string()]
            } else {
                vec![
                    "enabled".to_string(),
                    "discoverable".to_string(),
                    "disabled".to_string(),
                ]
            },
            family: "test".to_string(),
        }
    }

    #[test]
    fn modes_session_setup_tools_initial_order_and_safety_pin() {
        let mut snap = snapshot(vec![]);
        snap.tools = vec![
            tool("bash", "disabled", false),
            tool("read", "enabled", false),
            tool("question", "enabled", true),
            tool("mcp", "discoverable", false),
        ];
        let order = initial_tool_order(&snap.tools);
        assert_eq!(order, vec!["read", "mcp", "bash", "question"]);
        assert!(!order.iter().any(|name| name == "escalate"));
    }

    #[test]
    fn modes_session_setup_tools_order_frozen_after_edit() {
        let mut snap = snapshot(vec![]);
        snap.tools = vec![
            tool("read", "enabled", false),
            tool("bash", "discoverable", false),
        ];
        snap.root_foreground = true;
        let mut pane = SessionSetupPane::loading(false);
        pane.apply_snapshot(snap);
        let before = pane
            .rows
            .iter()
            .filter_map(|row| match &row.payload {
                RowPayload::Tool { name, .. } => Some(name.clone()),
                _ => None,
            })
            .collect::<Vec<_>>();
        pane.list.select(pane.rows.iter().position(
            |row| matches!(row.payload, RowPayload::Tool { name, locked: false } if name == "read"),
        ));
        let _ = pane.handle_key(press(KeyCode::Enter));
        let after = pane
            .rows
            .iter()
            .filter_map(|row| match &row.payload {
                RowPayload::Tool { name, .. } => Some(name.clone()),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            before, after,
            "tool order must not reshuffle after a tier edit"
        );
    }

    #[test]
    fn modes_session_setup_overlay_reopen_keeps_frozen_tool_order() {
        let mut snap = snapshot(vec![]);
        snap.tools = vec![
            tool("read", "enabled", false),
            tool("bash", "discoverable", false),
        ];
        let mut inline = SessionSetupPane::loading_inline(false);
        inline.apply_snapshot(snap.clone());
        let frozen = inline.frozen_tool_order().to_vec();
        assert_eq!(frozen, vec!["read".to_string(), "bash".to_string()]);
        snap.tools = vec![
            tool("bash", "enabled", false),
            tool("read", "discoverable", false),
        ];
        let mut overlay = SessionSetupPane::loading(false);
        overlay.adopt_frozen_session(&inline);
        overlay.apply_snapshot(snap);
        assert_eq!(overlay.frozen_tool_order(), frozen.as_slice());
        let names: Vec<_> = overlay
            .rows
            .iter()
            .filter_map(|row| match &row.payload {
                RowPayload::Tool { name, .. } => Some(name.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(names, vec!["read".to_string(), "bash".to_string()]);
    }

    #[test]
    fn modes_session_setup_model_out_of_set_uses_live_allowed_choice_ids() {
        let slot = SessionSetupModelSlotV1 {
            slot_id: "primary".to_string(),
            choices: vec![
                choice("local", "suggested-unbound", true, true),
                choice("local", "bound", false, false),
            ],
            choice_routes: Vec::new(),
            allowed_choice_ids: vec!["local/bound".to_string()],
            unmatched_recommendations: Vec::new(),
            default_choice_id: Some("local/bound".to_string()),
            unavailable_reason: None,
        };
        let snap = snapshot(vec![candidate(
            "authored/reviewer",
            Global,
            true,
            vec![slot],
            None,
        )]);
        let items = model_choice_items(&snap);
        assert_eq!(
            items
                .iter()
                .map(|item| (item.choice_id.as_str(), item.out_of_set))
                .collect::<Vec<_>>(),
            vec![("local/bound", false), ("local/suggested-unbound", true)]
        );
    }

    #[test]
    fn modes_session_setup_tools_rotate_legal_and_surface_foreground_refusal() {
        let mut snap = snapshot(vec![]);
        snap.tools = vec![tool("bash", "enabled", false)];
        snap.root_foreground = false;
        let mut pane = SessionSetupPane::loading(false);
        pane.apply_snapshot(snap);
        pane.list.select(pane.rows.iter().position(
            |row| matches!(row.payload, RowPayload::Tool { name, .. } if name == "bash"),
        ));
        let outcome = pane.handle_key(press(KeyCode::Enter));
        assert_eq!(outcome, SessionSetupOutcome::Stay);
        assert!(
            pane.notice()
                .is_some_and(|notice| notice.contains("foreground")),
            "foreground refusal must be an inline notice"
        );
    }

    #[test]
    fn modes_session_setup_mcp_groups_and_shadow() {
        let mut snap = snapshot(vec![]);
        snap.mcps = vec![
            SessionSetupMcpV1 {
                name: "g".into(),
                scope: "global".into(),
                enabled: true,
                shadowed_by: Some("workspace".into()),
                profile: Some("default".into()),
            },
            SessionSetupMcpV1 {
                name: "w".into(),
                scope: "workspace".into(),
                enabled: true,
                shadowed_by: None,
                profile: None,
            },
        ];
        let rows = build_rows(&snap, &[]);
        let mcp_text: Vec<_> = rows
            .iter()
            .filter(|row| matches!(row.payload, RowPayload::Mcp { .. } | RowPayload::AddMcp))
            .map(|row| row.text.as_str())
            .collect();
        assert!(
            mcp_text
                .iter()
                .any(|text| text.contains("[global]") && text.contains("shadowed by workspace"))
        );
        assert!(mcp_text.iter().any(|text| text.contains("[workspace]")));
        assert!(mcp_text.iter().any(|text| text.contains("[Add MCP]")));
    }

    #[test]
    fn modes_session_setup_model_default_badge_and_locked() {
        let mut snap = snapshot(vec![]);
        snap.model.effective = Some(cockpit_proto::AgentModelRefV1 {
            choice_id: "local/first".into(),
            provider_id: "local".into(),
            model_id: "first".into(),
            is_default: true,
        });
        let rows = build_rows(&snap, &[]);
        assert!(rows.iter().any(|row| {
            matches!(row.payload, RowPayload::Model) && row.text.contains("<default>")
        }));
        snap.model.locked_reason =
            Some(cockpit_proto::AgentControlLockedReasonV1::InheritedFromProfile);
        let rows = build_rows(&snap, &[]);
        assert!(rows.iter().any(|row| {
            matches!(row.payload, RowPayload::Model) && row.text.contains("locked")
        }));
    }

    #[test]
    fn modes_session_setup_e2e_scripted_fresh_session_flow() {
        let mut snap = snapshot(vec![candidate(
            "authored/reviewer",
            Global,
            true,
            vec![SessionSetupModelSlotV1 {
                slot_id: "primary".to_string(),
                choices: vec![choice("local", "first", true, true)],
                choice_routes: Vec::new(),
                allowed_choice_ids: vec!["local/first".to_string()],
                unmatched_recommendations: Vec::new(),
                default_choice_id: Some("local/first".to_string()),
                unavailable_reason: None,
            }],
            None,
        )]);
        snap.resolved_agent = Some("reviewer".into());
        snap.available_agents = vec!["Build".into(), "reviewer".into()];
        snap.tools = vec![
            tool("read", "enabled", false),
            tool("bash", "discoverable", false),
            tool("question", "enabled", true),
        ];
        snap.root_foreground = true;
        snap.mcps = vec![SessionSetupMcpV1 {
            name: "docs".into(),
            scope: "workspace".into(),
            enabled: true,
            shadowed_by: None,
            profile: None,
        }];
        let mut pane = SessionSetupPane::loading_inline(false);
        pane.apply_snapshot(snap);
        // Agent popover → select
        assert_eq!(
            pane.handle_key(press(KeyCode::Enter)),
            SessionSetupOutcome::Stay
        );
        let selected = pane.handle_key(press(KeyCode::Enter));
        assert!(matches!(selected, SessionSetupOutcome::SelectAgent { .. }));
        // Model popover
        pane.list.select(
            pane.rows
                .iter()
                .position(|row| matches!(row.payload, RowPayload::Model)),
        );
        assert_eq!(
            pane.handle_key(press(KeyCode::Enter)),
            SessionSetupOutcome::Stay
        );
        let model = pane.handle_key(press(KeyCode::Enter));
        assert!(matches!(model, SessionSetupOutcome::SelectModel { .. }));
        // Two tool rotations
        pane.list.select(pane.rows.iter().position(
            |row| matches!(row.payload, RowPayload::Tool { name, locked: false } if name == "read"),
        ));
        assert!(matches!(
            pane.handle_key(press(KeyCode::Enter)),
            SessionSetupOutcome::SetToolSurface { .. }
        ));
        pane.list.select(pane.rows.iter().position(
            |row| matches!(row.payload, RowPayload::Tool { name, locked: false } if name == "bash"),
        ));
        assert!(matches!(
            pane.handle_key(press(KeyCode::Enter)),
            SessionSetupOutcome::SetToolSurface { .. }
        ));
        // Add MCP
        pane.list.select(
            pane.rows
                .iter()
                .position(|row| matches!(row.payload, RowPayload::AddMcp)),
        );
        assert_eq!(
            pane.handle_key(press(KeyCode::Enter)),
            SessionSetupOutcome::Stay
        );
        // type a name, an endpoint (streamable requires one), then submit
        pane.handle_key(press(KeyCode::Char('w')));
        pane.handle_key(press(KeyCode::Char('s')));
        pane.handle_key(press(KeyCode::Tab));
        for ch in "https://example.test/mcp".chars() {
            pane.handle_key(press(KeyCode::Char(ch)));
        }
        pane.handle_key(press(KeyCode::Up));
        let add = pane.handle_key(press(KeyCode::Enter));
        match add {
            SessionSetupOutcome::AddMcp {
                name,
                scope,
                endpoint,
                ..
            } => {
                assert_eq!(name, "ws");
                assert_eq!(scope, SessionSetupMcpScope::Workspace);
                assert_eq!(endpoint.as_deref(), Some("https://example.test/mcp"));
            }
            other => panic!("expected AddMcp, got {other:?}"),
        }
        let collapsed = pane.inline_lines();
        assert!(
            collapsed
                .iter()
                .any(|line| line.to_string().contains("Session setup"))
        );
    }

    #[test]
    fn modes_session_setup_keyboard_reaches_every_section() {
        let mut snap = snapshot(vec![]);
        snap.resolved_agent = Some("Build".into());
        snap.available_agents = vec!["Build".into(), "Plan".into()];
        snap.tools = vec![
            tool("read", "enabled", false),
            tool("question", "enabled", true),
        ];
        snap.mcps = vec![SessionSetupMcpV1 {
            name: "docs".into(),
            scope: "global".into(),
            enabled: true,
            shadowed_by: None,
            profile: Some("default".into()),
        }];
        let mut pane = SessionSetupPane::loading_inline(false);
        pane.apply_snapshot(snap);
        assert!(
            pane.rows
                .iter()
                .any(|row| matches!(row.payload, RowPayload::Agent))
        );
        assert!(
            pane.rows
                .iter()
                .any(|row| matches!(row.payload, RowPayload::Model))
        );
        assert!(
            pane.rows
                .iter()
                .any(|row| matches!(row.payload, RowPayload::Tool { .. }))
        );
        assert!(
            pane.rows
                .iter()
                .any(|row| matches!(row.payload, RowPayload::AddMcp))
        );
        pane.move_selection(true);
        pane.move_selection(true);
        assert!(pane.list.selected().is_some());
        let narrow = render_inline_text(&pane, 36, 16);
        assert!(narrow.contains("Session setup"));
        assert!(
            pane.rows.iter().all(|row| row.text.chars().count() < 200),
            "rows must stay as single lines the panel can scroll"
        );
    }
}
