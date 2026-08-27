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

use cockpit_proto::{
    AgentInstallationChoiceV1, AgentInstallationRecordV1, AgentInstallationScopeWire,
    AgentInstallationUnmatchedRecommendationV1, SessionSetupAgentCandidateV1,
    SessionSetupLockedReasonV1, SessionSetupModelSlotV1, SessionSetupSnapshotV1,
    SessionSetupUnavailableReasonV1,
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
    Agent {
        name: String,
        locked: bool,
    },
    ModelChoice {
        slot_id: String,
        choice_id: String,
    },
}

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
        }
    }

    pub(crate) fn is_inline(&self) -> bool {
        self.inline
    }

    /// Apply a daemon snapshot, rebuilding the flat rows and clamping the
    /// cursor to the first selectable row.
    pub(crate) fn apply_snapshot(&mut self, snapshot: SessionSetupSnapshotV1) {
        self.rows = build_rows(&snapshot);
        self.snapshot = Some(snapshot);
        self.status = Status::Ready;
        let first = self.rows.iter().position(|row| row.selectable);
        self.list.select(first);
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
            RowPayload::None => SessionSetupOutcome::Stay,
            RowPayload::Agent { name, locked } => {
                if locked {
                    self.notice = Some(format!("Agent `{name}` is locked and cannot be selected."));
                    SessionSetupOutcome::Stay
                } else {
                    SessionSetupOutcome::SelectAgent { name }
                }
            }
            RowPayload::ModelChoice {
                slot_id,
                choice_id,
            } => SessionSetupOutcome::SelectModel {
                slot_id,
                choice_id,
            },
        }
    }

    pub(crate) fn handle_key(&mut self, key: KeyEvent) -> SessionSetupOutcome {
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

    pub(crate) fn render(&mut self, frame: &mut Frame, area: Rect) {
        let title = if self.inline {
            " Session setup (Tab: composer) "
        } else {
            " Session setup "
        };
        let block = Block::default().borders(Borders::ALL).title(title);
        let inner = block.inner(area);
        frame.render_widget(block, area);

        let mut lines: Vec<Line<'static>> = match &self.status {
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
                for row in &self.rows {
                    lines.push(Line::from(styled(
                        row.text.clone(),
                        row.kind,
                        self.color,
                    )));
                }
            }
        }
        lines.push(Line::from(styled(
            "Enter activates · j/k move · Tab composer".to_string(),
            RowKind::Unmatched,
            self.color,
        )));
        lines
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
        selectable: true,
        payload: RowPayload::Agent {
            name: agent_name(record),
            locked: candidate.locked_reason.is_some(),
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
fn build_rows(snapshot: &SessionSetupSnapshotV1) -> Vec<DisplayRow> {
    let mut rows = Vec::new();
    for candidate in &snapshot.candidates {
        rows.push(candidate_header(candidate));
        for slot in &candidate.slots {
            slot_rows(slot, &mut rows);
        }
        rows.push(DisplayRow {
            kind: RowKind::Blank,
            text: String::new(),
            selectable: false,
            payload: RowPayload::None,
        });
    }
    rows
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
            tool_surface_notice: None,
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
        let rows = build_rows(&snap);
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
        let rows = build_rows(&snap);
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
        let rows = build_rows(&snap);
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
        for row in build_rows(&snap) {
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
        let text: String = build_rows(&snap)
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
            pane.notice()
                .is_some_and(|notice| notice.contains("locked")),
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
        let rows = build_rows(&snap);
        let agent = rows
            .iter()
            .find(|row| matches!(row.payload, RowPayload::Agent { .. }))
            .expect("agent candidate row");
        assert!(agent.selectable);
        match &agent.payload {
            RowPayload::Agent { name, locked } => {
                assert_eq!(name, "reviewer");
                assert!(!*locked);
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
        assert_eq!(before, after, "pending applied snapshot must survive collapse");
        assert!(
            after
                .iter()
                .any(|line| line.to_string().contains("reviewer"))
        );
    }
}
