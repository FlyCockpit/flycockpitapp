//! Agent-tree navigation overlay (modes AC3/AC4).
//!
//! Renders the daemon-owned agent tree as a read-only, indented outline with a
//! breadcrumb path to the focused node, a read-only ancestor drawer, and the
//! deterministically ordered attention list ([`crate::tui::agent_attention`]).
//! Focus changes presentation only — it never alters any node's authority.
//! Selecting a pending attention row and pressing Enter emits a resolve intent
//! attributed to that row's child agent; the daemon owns the actual decision
//! transaction. Everything on the wire is already daemon-redacted (no prompt,
//! credential, live tool handle, or approval operation crosses the boundary).

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState};
use uuid::Uuid;

use cockpit_config::config::extended::LlmMode;
use cockpit_config::config::sandbox_mode::SandboxMode;
use cockpit_proto::{
    AgentDecisionAttention, AgentEffectiveSettingsV1, AgentQuestionOverrideV1,
    AgentSessionOverrideFieldV1, AgentTreeNode, AgentVerificationReductionV1,
};

use crate::tui::agent_attention::order_attention;
use crate::tui::pane::Pane;

/// Outcome of a key press.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AgentTreeOutcome {
    Stay,
    Close,
    /// Resolve/steer the selected child's pending decision. The daemon owns the
    /// transaction; the pane only names which decision, attributed to a child.
    Resolve {
        decision_request_id: Uuid,
        agent_instance_id: Uuid,
    },
    /// Re-fetch the tree and attention (manual refresh, or `AgentTreeChanged`).
    Refresh,
    /// Open the per-node override controls for the selected node (modes
    /// AC5/6/7). The app fetches `GetAgentEffectiveSettings` for it.
    OpenOverride {
        agent_instance_id: Uuid,
    },
    /// Apply one typed, non-escalating override to a node against its
    /// effective-settings revision. The daemon owns the CAS.
    ApplyOverride {
        agent_instance_id: Uuid,
        expected_override_revision: u64,
        field: AgentSessionOverrideFieldV1,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Status {
    Loading,
    Ready,
    Error(String),
}

pub(crate) struct AgentTreePane {
    status: Status,
    rows: Vec<TreeRow>,
    list: ListState,
    color: bool,
    /// Short breadcrumb path (root → … → focused) for the currently selected
    /// tree node. Recomputed on selection changes.
    breadcrumb: String,
    /// When `Some`, the pane renders the per-node override controls (modes
    /// AC5/6/7) for a focused node instead of the tree. Cleared on Esc/q.
    override_view: Option<OverrideView>,
}

/// The per-node override controls: the daemon-owned effective settings for one
/// node plus the actionable/read-only rows projected from them.
struct OverrideView {
    agent_instance_id: Uuid,
    override_revision: u64,
    terminal: bool,
    title: String,
    rows: Vec<OverrideRow>,
    list: ListState,
    /// Last daemon rejection or load error, shown at the top of the controls.
    error: Option<String>,
}

/// One override-control row. Actionable rows carry the exact override field they
/// submit; header/effective/locked rows are read-only.
#[derive(Debug, Clone, PartialEq, Eq)]
struct OverrideRow {
    kind: OverrideRowKind,
    text: String,
    /// The override this row applies when actioned, if any.
    field: Option<AgentSessionOverrideFieldV1>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OverrideRowKind {
    Header,
    Effective,
    Action,
    Locked,
    Blank,
}

/// One flat display row.
#[derive(Debug, Clone, PartialEq, Eq)]
struct TreeRow {
    kind: RowKind,
    text: String,
    selectable: bool,
    /// For a tree-node row: its instance id (for breadcrumb recompute).
    node: Option<Uuid>,
    /// For an attention row: its decision + owning agent (for resolve intent).
    decision: Option<(Uuid, Uuid)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RowKind {
    Node,
    Header,
    AttentionPending,
    AttentionResolved,
    Blank,
}

impl AgentTreePane {
    pub(crate) fn loading(color: bool) -> Self {
        Self {
            status: Status::Loading,
            rows: Vec::new(),
            list: ListState::default(),
            color,
            breadcrumb: String::new(),
            override_view: None,
        }
    }

    /// Populate the per-node override controls from a daemon effective-settings
    /// snapshot and switch the pane into override mode.
    pub(crate) fn apply_effective_settings(&mut self, snapshot: AgentEffectiveSettingsV1) {
        let previous_error = self
            .override_view
            .as_ref()
            .filter(|view| view.agent_instance_id.to_string() == snapshot.agent_instance_id)
            .and_then(|view| view.error.clone());
        let agent_instance_id = Uuid::parse_str(&snapshot.agent_instance_id).unwrap_or_default();
        let rows = build_override_rows(&snapshot);
        let first = rows.iter().position(|row| row.field.is_some());
        let mut list = ListState::default();
        list.select(first);
        self.override_view = Some(OverrideView {
            agent_instance_id,
            override_revision: snapshot.override_revision,
            terminal: snapshot.terminal,
            title: format!("Overrides — {}", short_id(agent_instance_id)),
            rows,
            list,
            error: previous_error,
        });
    }

    /// Record an override load/apply error in the open override controls (or as
    /// the pane status when no override view is open).
    pub(crate) fn set_override_error(&mut self, message: impl Into<String>) {
        let message = message.into();
        match &mut self.override_view {
            Some(view) => view.error = Some(message),
            None => self.status = Status::Error(message),
        }
    }

    /// Apply a fresh tree + attention snapshot.
    pub(crate) fn apply(&mut self, nodes: Vec<AgentTreeNode>, attention: Vec<AgentDecisionAttention>) {
        self.rows = build_rows(&nodes, &attention);
        self.status = Status::Ready;
        let first = self.rows.iter().position(|row| row.selectable);
        self.list.select(first);
        self.recompute_breadcrumb(&nodes);
    }

    pub(crate) fn set_error(&mut self, message: impl Into<String>) {
        self.status = Status::Error(message.into());
    }

    fn recompute_breadcrumb(&mut self, nodes: &[AgentTreeNode]) {
        let Some(selected) = self.list.selected().and_then(|index| self.rows.get(index)) else {
            self.breadcrumb.clear();
            return;
        };
        let Some(focus) = selected.node else {
            // Focused on an attention row: keep the previous node breadcrumb.
            return;
        };
        self.breadcrumb = breadcrumb_for(nodes, focus);
    }

    fn selectable_indices(&self) -> Vec<usize> {
        self.rows
            .iter()
            .enumerate()
            .filter(|(_, row)| row.selectable)
            .map(|(index, _)| index)
            .collect()
    }

    fn move_selection(&mut self, forward: bool) {
        let selectable = self.selectable_indices();
        if selectable.is_empty() {
            return;
        }
        let position = self
            .list
            .selected()
            .and_then(|sel| selectable.iter().position(|row| *row == sel));
        let next = match position {
            Some(pos) if forward => (pos + 1).min(selectable.len() - 1),
            Some(pos) => pos.saturating_sub(1),
            None => 0,
        };
        self.list.select(Some(selectable[next]));
    }

    pub(crate) fn handle_key(&mut self, key: KeyEvent) -> AgentTreeOutcome {
        if self.override_view.is_some() {
            return self.handle_override_key(key);
        }
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') => AgentTreeOutcome::Close,
            KeyCode::Char('r') => AgentTreeOutcome::Refresh,
            KeyCode::Down | KeyCode::Char('j') => {
                self.move_selection(true);
                AgentTreeOutcome::Stay
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.move_selection(false);
                AgentTreeOutcome::Stay
            }
            // Open per-node override controls for the selected tree node.
            KeyCode::Char('o') => self
                .list
                .selected()
                .and_then(|index| self.rows.get(index))
                .and_then(|row| row.node)
                .map(|agent_instance_id| AgentTreeOutcome::OpenOverride { agent_instance_id })
                .unwrap_or(AgentTreeOutcome::Stay),
            KeyCode::Enter => self
                .list
                .selected()
                .and_then(|index| self.rows.get(index))
                .and_then(|row| row.decision)
                .map(|(decision_request_id, agent_instance_id)| AgentTreeOutcome::Resolve {
                    decision_request_id,
                    agent_instance_id,
                })
                .unwrap_or(AgentTreeOutcome::Stay),
            _ => AgentTreeOutcome::Stay,
        }
    }

    /// Key handling while the per-node override controls are open. Esc/q returns
    /// to the tree (never closes the overlay outright).
    fn handle_override_key(&mut self, key: KeyEvent) -> AgentTreeOutcome {
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') => {
                self.override_view = None;
                AgentTreeOutcome::Stay
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.move_override_selection(true);
                AgentTreeOutcome::Stay
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.move_override_selection(false);
                AgentTreeOutcome::Stay
            }
            KeyCode::Enter => {
                let Some(view) = self.override_view.as_ref() else {
                    return AgentTreeOutcome::Stay;
                };
                let Some(field) = view
                    .list
                    .selected()
                    .and_then(|index| view.rows.get(index))
                    .and_then(|row| row.field.clone())
                else {
                    return AgentTreeOutcome::Stay;
                };
                AgentTreeOutcome::ApplyOverride {
                    agent_instance_id: view.agent_instance_id,
                    expected_override_revision: view.override_revision,
                    field,
                }
            }
            _ => AgentTreeOutcome::Stay,
        }
    }

    fn move_override_selection(&mut self, forward: bool) {
        let Some(view) = self.override_view.as_mut() else {
            return;
        };
        let actionable: Vec<usize> = view
            .rows
            .iter()
            .enumerate()
            .filter(|(_, row)| row.field.is_some())
            .map(|(index, _)| index)
            .collect();
        if actionable.is_empty() {
            return;
        }
        let position = view
            .list
            .selected()
            .and_then(|sel| actionable.iter().position(|row| *row == sel));
        let next = match position {
            Some(pos) if forward => (pos + 1).min(actionable.len() - 1),
            Some(pos) => pos.saturating_sub(1),
            None => 0,
        };
        view.list.select(Some(actionable[next]));
    }

    pub(crate) fn render(&mut self, frame: &mut Frame, area: Rect) {
        if self.override_view.is_some() {
            self.render_override(frame, area);
            return;
        }
        let title = if self.breadcrumb.is_empty() {
            " Agent tree ".to_string()
        } else {
            format!(" Agent tree — {} ", self.breadcrumb)
        };
        let block = Block::default().borders(Borders::ALL).title(title);
        let inner = block.inner(area);
        frame.render_widget(block, area);

        let lines: Vec<Line<'static>> = match &self.status {
            Status::Loading => vec![Line::from(Span::raw("Loading agent tree…"))],
            Status::Error(message) => {
                vec![Line::from(styled(message.clone(), RowKind::AttentionResolved, self.color))]
            }
            Status::Ready => self
                .rows
                .iter()
                .map(|row| Line::from(styled(row.text.clone(), row.kind, self.color)))
                .collect(),
        };
        let items: Vec<ListItem<'static>> = lines.into_iter().map(ListItem::new).collect();
        let list = List::new(items).highlight_symbol("› ");
        frame.render_stateful_widget(list, inner, &mut self.list);
    }

    fn render_override(&mut self, frame: &mut Frame, area: Rect) {
        let color = self.color;
        let Some(view) = self.override_view.as_mut() else {
            return;
        };
        let block = Block::default()
            .borders(Borders::ALL)
            .title(format!(" {} ", view.title));
        let inner = block.inner(area);
        frame.render_widget(block, area);

        let mut lines: Vec<Line<'static>> = Vec::new();
        if let Some(error) = &view.error {
            lines.push(Line::from(override_styled(
                error.clone(),
                OverrideRowKind::Locked,
                color,
            )));
            lines.push(Line::from(Span::raw(String::new())));
        }
        if view.terminal {
            lines.push(Line::from(override_styled(
                "This agent has finished; settings are read-only.".to_string(),
                OverrideRowKind::Locked,
                color,
            )));
        }
        for row in &view.rows {
            lines.push(Line::from(override_styled(row.text.clone(), row.kind, color)));
        }
        let items: Vec<ListItem<'static>> = lines.into_iter().map(ListItem::new).collect();
        // The list selection indexes into `view.rows`; the optional error/
        // terminal preamble lines are prepended, so offset the highlight.
        let preamble = usize::from(view.error.is_some()) * 2 + usize::from(view.terminal);
        let mut render_state = ListState::default();
        render_state.select(view.list.selected().map(|index| index + preamble));
        let list = List::new(items).highlight_symbol("› ");
        frame.render_stateful_widget(list, inner, &mut render_state);
    }
}

impl Pane for AgentTreePane {
    type Outcome = AgentTreeOutcome;

    fn handle_key(&mut self, key: KeyEvent) -> Self::Outcome {
        AgentTreePane::handle_key(self, key)
    }

    fn render(&mut self, frame: &mut Frame, area: Rect) {
        AgentTreePane::render(self, frame, area);
    }
}

/// Short opaque id (first 8 chars) for compact display. Never a secret — the
/// agent instance id is a daemon-owned uuid.
fn short_id(id: Uuid) -> String {
    id.simple().to_string()[..8].to_string()
}

/// Depth of `node` from its root via the parent chain, bounded to guard a
/// malformed cycle.
fn depth_of(nodes: &[AgentTreeNode], mut id: Uuid) -> usize {
    let mut depth = 0usize;
    let mut guard = 0usize;
    while let Some(parent) = nodes
        .iter()
        .find(|node| node.agent_instance_id == id)
        .and_then(|node| node.parent_agent_instance_id)
    {
        depth += 1;
        id = parent;
        guard += 1;
        if guard > nodes.len() {
            break;
        }
    }
    depth
}

/// Root → … → focused breadcrumb of short ids.
fn breadcrumb_for(nodes: &[AgentTreeNode], focus: Uuid) -> String {
    let mut chain = vec![focus];
    let mut id = focus;
    let mut guard = 0usize;
    while let Some(parent) = nodes
        .iter()
        .find(|node| node.agent_instance_id == id)
        .and_then(|node| node.parent_agent_instance_id)
    {
        chain.push(parent);
        id = parent;
        guard += 1;
        if guard > nodes.len() {
            break;
        }
    }
    chain.reverse();
    chain
        .into_iter()
        .map(short_id)
        .collect::<Vec<_>>()
        .join(" › ")
}

/// Flatten the tree + ordered attention into display rows. Nodes are rendered
/// parent-before-child (stable by created_at, then id) and indented by depth.
fn build_rows(nodes: &[AgentTreeNode], attention: &[AgentDecisionAttention]) -> Vec<TreeRow> {
    let mut rows = Vec::new();

    let mut ordered_nodes = nodes.to_vec();
    // Roots first, then by creation, then id — a stable pre-order-ish outline
    // that keeps children grouped under their parents by depth indentation.
    ordered_nodes.sort_by(|a, b| {
        depth_of(nodes, a.agent_instance_id)
            .cmp(&depth_of(nodes, b.agent_instance_id))
            .then_with(|| a.created_at_unix_ms.cmp(&b.created_at_unix_ms))
            .then_with(|| a.agent_instance_id.cmp(&b.agent_instance_id))
    });
    for node in &ordered_nodes {
        let indent = "  ".repeat(depth_of(nodes, node.agent_instance_id));
        let workspace = node
            .workspace_ref
            .as_deref()
            .map(|ws| format!(" @{ws}"))
            .unwrap_or_default();
        rows.push(TreeRow {
            kind: RowKind::Node,
            text: format!("{indent}{} [{}]{workspace}", short_id(node.agent_instance_id), node.state),
            selectable: true,
            node: Some(node.agent_instance_id),
            decision: None,
        });
    }

    let ordered_attention = order_attention(attention);
    if !ordered_attention.is_empty() {
        rows.push(TreeRow {
            kind: RowKind::Blank,
            text: String::new(),
            selectable: false,
            node: None,
            decision: None,
        });
        rows.push(TreeRow {
            kind: RowKind::Header,
            text: "Attention".to_string(),
            selectable: false,
            node: None,
            decision: None,
        });
        for entry in &ordered_attention {
            let resolved = entry.resolved_at_unix_ms.is_some();
            let deadline = entry
                .deadline_unix_ms
                .map(|ms| format!(" ⏱{ms}"))
                .unwrap_or_default();
            let status = if resolved { "resolved" } else { "pending" };
            rows.push(TreeRow {
                kind: if resolved {
                    RowKind::AttentionResolved
                } else {
                    RowKind::AttentionPending
                },
                text: format!(
                    "  {} · {} · {status}{deadline}  (agent {})",
                    entry.decision_class,
                    entry.decision_state,
                    short_id(entry.agent_instance_id),
                ),
                // Only pending rows are actionable; resolved rows are read-only.
                selectable: !resolved,
                node: None,
                decision: (!resolved)
                    .then_some((entry.decision_request_id, entry.agent_instance_id)),
            });
        }
    }

    rows
}

fn styled(text: String, kind: RowKind, color: bool) -> Span<'static> {
    if !color {
        return Span::raw(text);
    }
    let style = match kind {
        RowKind::Node => Style::default(),
        RowKind::Header => Style::default().add_modifier(Modifier::BOLD),
        RowKind::AttentionPending => Style::default().fg(Color::Yellow),
        RowKind::AttentionResolved => Style::default().fg(Color::DarkGray),
        RowKind::Blank => Style::default(),
    };
    Span::styled(text, style)
}

fn sandbox_label(mode: SandboxMode) -> &'static str {
    match mode {
        SandboxMode::Off => "off",
        SandboxMode::Sandbox => "sandbox",
        SandboxMode::Container => "container",
        SandboxMode::ContainerReadonly => "container_readonly",
    }
}

fn mode_label(mode: LlmMode) -> &'static str {
    match mode {
        LlmMode::Defensive => "defensive",
        LlmMode::Normal => "normal",
        LlmMode::Frontier => "frontier",
    }
}

/// Project daemon-owned effective settings into display + action rows. Only
/// daemon-permitted, non-escalating transitions become actionable rows; the
/// effective value, locked reasons, and pending markers are read-only. The
/// daemon owns all authority — this never infers an allowed transition.
fn build_override_rows(snapshot: &AgentEffectiveSettingsV1) -> Vec<OverrideRow> {
    let mut rows = Vec::new();
    let terminal = snapshot.terminal;

    // --- Sandbox ---
    let sandbox = &snapshot.sandbox;
    rows.push(header(format!("Sandbox — {}", sandbox_label(sandbox.effective))));
    if let Some(pending) = sandbox.pending {
        rows.push(effective(format!("  pending → {}", sandbox_label(pending))));
    }
    if let Some(reason) = sandbox.locked_reason {
        rows.push(locked(format!("  locked: {}", locked_label(reason))));
    } else if !terminal {
        for &candidate in &sandbox.allowed {
            if candidate == sandbox.effective {
                continue;
            }
            rows.push(action(
                format!("  → set sandbox {}", sandbox_label(candidate)),
                AgentSessionOverrideFieldV1::Sandbox { mode: candidate },
            ));
        }
    }
    rows.push(blank());

    // --- Mode ---
    let mode = &snapshot.mode;
    rows.push(header(format!("Mode — {}", mode_label(mode.effective))));
    if let Some(pending) = mode.pending {
        rows.push(effective(format!("  pending → {}", mode_label(pending))));
    }
    if let Some(reason) = mode.locked_reason {
        rows.push(locked(format!("  locked: {}", locked_label(reason))));
    } else if !terminal {
        for &candidate in &mode.allowed {
            if candidate == mode.effective {
                continue;
            }
            rows.push(action(
                format!("  → set mode {}", mode_label(candidate)),
                AgentSessionOverrideFieldV1::Mode { mode: candidate },
            ));
        }
    }
    rows.push(blank());

    // --- Verification ---
    rows.push(header("Verification".to_string()));
    if snapshot.verification.regions.is_empty() {
        rows.push(effective("  (no verification regions)".to_string()));
    }
    for region in &snapshot.verification.regions {
        let state = if region.enabled { "on" } else { "off" };
        rows.push(effective(format!("  {} — {}", region.label, state)));
        if region.pending {
            rows.push(effective("    pending reduction staged".to_string()));
        }
        if !terminal && region.can_disable {
            rows.push(action(
                "    → disable (write off mask)".to_string(),
                AgentSessionOverrideFieldV1::Verification {
                    reduction: AgentVerificationReductionV1::Off {
                        region_id: region.region_id.clone(),
                    },
                },
            ));
        }
    }
    rows.push(blank());

    // --- Questions ---
    rows.push(header("Questions".to_string()));
    match &snapshot.question.effective {
        None => {
            rows.push(locked("  off (cannot be enabled by a session override)".to_string()));
        }
        Some(effective_policy) => {
            let auto = if effective_policy.auto_answer_enabled {
                "on"
            } else {
                "off"
            };
            rows.push(effective(format!(
                "  auto-answer {auto}, timeout {}s (ceiling {}s)",
                effective_policy.required_decision_timeout_seconds,
                effective_policy.host_ceiling_seconds,
            )));
            if let Some(pending) = &snapshot.question.pending {
                rows.push(effective(format!("  pending → {}", question_pending_label(pending))));
            }
            if !terminal {
                if effective_policy.can_disable_auto_answer {
                    rows.push(action(
                        "  → disable auto-answer (strictest)".to_string(),
                        AgentSessionOverrideFieldV1::Question {
                            policy: AgentQuestionOverrideV1::Disable,
                        },
                    ));
                }
                // Lengthening the wait up to the host ceiling is the reduction.
                if effective_policy.max_required_decision_timeout_seconds
                    > effective_policy.required_decision_timeout_seconds
                {
                    rows.push(action(
                        format!(
                            "  → lengthen timeout to ceiling ({}s)",
                            effective_policy.max_required_decision_timeout_seconds
                        ),
                        AgentSessionOverrideFieldV1::Question {
                            policy: AgentQuestionOverrideV1::Reduce {
                                required_decision_timeout_seconds: effective_policy
                                    .max_required_decision_timeout_seconds,
                            },
                        },
                    ));
                }
            }
        }
    }

    rows
}

fn header(text: String) -> OverrideRow {
    OverrideRow {
        kind: OverrideRowKind::Header,
        text,
        field: None,
    }
}

fn effective(text: String) -> OverrideRow {
    OverrideRow {
        kind: OverrideRowKind::Effective,
        text,
        field: None,
    }
}

fn locked(text: String) -> OverrideRow {
    OverrideRow {
        kind: OverrideRowKind::Locked,
        text,
        field: None,
    }
}

fn blank() -> OverrideRow {
    OverrideRow {
        kind: OverrideRowKind::Blank,
        text: String::new(),
        field: None,
    }
}

fn action(text: String, field: AgentSessionOverrideFieldV1) -> OverrideRow {
    OverrideRow {
        kind: OverrideRowKind::Action,
        text,
        field: Some(field),
    }
}

fn locked_label(reason: cockpit_proto::AgentControlLockedReasonV1) -> &'static str {
    use cockpit_proto::AgentControlLockedReasonV1 as Reason;
    match reason {
        Reason::InheritedFromProfile => "fixed by the agent profile",
        Reason::HostPolicy => "bounded by host policy",
        Reason::Terminal => "agent finished",
    }
}

fn question_pending_label(pending: &AgentQuestionOverrideV1) -> String {
    match pending {
        AgentQuestionOverrideV1::Disable => "disable auto-answer".to_string(),
        AgentQuestionOverrideV1::Reduce {
            required_decision_timeout_seconds,
        } => format!("timeout {required_decision_timeout_seconds}s"),
    }
}

fn override_styled(text: String, kind: OverrideRowKind, color: bool) -> Span<'static> {
    if !color {
        return Span::raw(text);
    }
    let style = match kind {
        OverrideRowKind::Header => Style::default().add_modifier(Modifier::BOLD),
        OverrideRowKind::Effective => Style::default(),
        OverrideRowKind::Action => Style::default().fg(Color::Cyan),
        OverrideRowKind::Locked => Style::default().fg(Color::DarkGray),
        OverrideRowKind::Blank => Style::default(),
    };
    Span::styled(text, style)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(id: u128, parent: Option<u128>, state: &str, created: i64) -> AgentTreeNode {
        AgentTreeNode {
            agent_instance_id: Uuid::from_u128(id),
            parent_agent_instance_id: parent.map(Uuid::from_u128),
            workspace_ref: None,
            state: state.to_string(),
            revision: 1,
            created_at_unix_ms: created,
            updated_at_unix_ms: created,
        }
    }

    fn attn(id: u128, agent: u128, class: &str, resolved: Option<i64>) -> AgentDecisionAttention {
        AgentDecisionAttention {
            attention_id: Uuid::from_u128(id),
            decision_request_id: Uuid::from_u128(id),
            agent_instance_id: Uuid::from_u128(agent),
            state: "waiting".to_string(),
            decision_state: if resolved.is_some() { "resolved" } else { "pending" }.to_string(),
            decision_class: class.to_string(),
            task_call_id: None,
            workspace_ref: None,
            options_contract_json: "{}".to_string(),
            free_text_contract_json: None,
            recommendation_json: None,
            deadline_unix_ms: None,
            revision: 1,
            raised_at_unix_ms: 10,
            resolved_at_unix_ms: resolved,
        }
    }

    #[test]
    fn modes_session_setup_agent_tree_breadcrumb_is_root_to_focus() {
        let nodes = vec![
            node(1, None, "running", 1),
            node(2, Some(1), "running", 2),
            node(3, Some(2), "waiting_for_user", 3),
        ];
        assert_eq!(
            breadcrumb_for(&nodes, Uuid::from_u128(3)),
            format!(
                "{} › {} › {}",
                short_id(Uuid::from_u128(1)),
                short_id(Uuid::from_u128(2)),
                short_id(Uuid::from_u128(3)),
            )
        );
    }

    #[test]
    fn modes_session_setup_agent_tree_nodes_indent_by_depth_and_are_read_only() {
        let nodes = vec![node(1, None, "running", 1), node(2, Some(1), "running", 2)];
        let rows = build_rows(&nodes, &[]);
        let node_rows: Vec<&TreeRow> = rows.iter().filter(|r| r.kind == RowKind::Node).collect();
        assert_eq!(node_rows.len(), 2);
        assert!(!node_rows[0].text.starts_with(' '), "root is not indented");
        assert!(node_rows[1].text.starts_with("  "), "child is indented one level");
        // Tree nodes are navigable but carry no resolve intent (read-only).
        assert!(node_rows.iter().all(|r| r.decision.is_none()));
    }

    #[test]
    fn modes_session_setup_agent_tree_attention_ordered_and_pending_actionable() {
        let nodes = vec![node(1, None, "running", 1)];
        let attention = vec![
            attn(10, 1, "user_question", Some(500)), // resolved
            attn(20, 1, "user_question", None),      // pending question
            attn(30, 1, "host_approval", None),      // pending critical approval
        ];
        let rows = build_rows(&nodes, &attention);
        let attention_rows: Vec<&TreeRow> = rows
            .iter()
            .filter(|r| matches!(r.kind, RowKind::AttentionPending | RowKind::AttentionResolved))
            .collect();
        // Ordered: critical approval, then question, then resolved.
        assert_eq!(attention_rows[0].kind, RowKind::AttentionPending);
        assert!(attention_rows[0].text.contains("host_approval"));
        assert_eq!(attention_rows[2].kind, RowKind::AttentionResolved);
        // Pending rows are actionable (resolve intent); resolved is read-only.
        assert!(attention_rows[0].decision.is_some());
        assert!(attention_rows[2].decision.is_none());
        assert!(!attention_rows[2].selectable);
    }

    #[test]
    fn modes_session_setup_agent_tree_enter_on_pending_emits_resolve_for_child() {
        let nodes = vec![node(1, None, "running", 1)];
        let attention = vec![attn(30, 1, "host_approval", None)];
        let mut pane = AgentTreePane::loading(false);
        pane.apply(nodes, attention);
        // Move selection to the pending attention row, then Enter.
        // (Root node is first selectable; the approval is the next.)
        pane.move_selection(true);
        let outcome = pane.handle_key(KeyEvent::from(KeyCode::Enter));
        assert_eq!(
            outcome,
            AgentTreeOutcome::Resolve {
                decision_request_id: Uuid::from_u128(30),
                agent_instance_id: Uuid::from_u128(1),
            }
        );
    }

    fn effective_settings(
        revision: u64,
        terminal: bool,
        sandbox_effective: SandboxMode,
        sandbox_allowed: Vec<SandboxMode>,
    ) -> AgentEffectiveSettingsV1 {
        AgentEffectiveSettingsV1 {
            dto_version: 1,
            session_id: Uuid::from_u128(1).to_string(),
            agent_instance_id: Uuid::from_u128(7).to_string(),
            override_revision: revision,
            terminal,
            sandbox: cockpit_proto::AgentSandboxControlV1 {
                effective: sandbox_effective,
                allowed: sandbox_allowed,
                locked_reason: None,
                pending: None,
            },
            mode: cockpit_proto::AgentModeControlV1 {
                effective: LlmMode::Normal,
                allowed: vec![LlmMode::Defensive, LlmMode::Normal],
                locked_reason: None,
                pending: None,
            },
            verification: cockpit_proto::AgentVerificationControlV1 {
                regions: Vec::new(),
            },
            question: cockpit_proto::AgentQuestionControlV1 {
                effective: None,
                locked_reason: None,
                pending: None,
            },
        }
    }

    #[test]
    fn modes_session_setup_override_open_on_node_emits_open_override() {
        let mut pane = AgentTreePane::loading(false);
        pane.apply(vec![node(7, None, "running", 1)], Vec::new());
        // The root node is the first selectable row; 'o' opens its controls.
        let outcome = pane.handle_key(KeyEvent::from(KeyCode::Char('o')));
        assert_eq!(
            outcome,
            AgentTreeOutcome::OpenOverride {
                agent_instance_id: Uuid::from_u128(7),
            }
        );
    }

    #[test]
    fn modes_session_setup_override_rows_list_only_allowed_transitions() {
        // Effective sandbox is `sandbox`; only `container` is a permitted
        // reduction. `off` (loosening) and the current value are never offered.
        let snapshot = effective_settings(
            3,
            false,
            SandboxMode::Sandbox,
            vec![SandboxMode::Sandbox, SandboxMode::Container],
        );
        let rows = build_override_rows(&snapshot);
        let sandbox_actions: Vec<&OverrideRow> = rows
            .iter()
            .filter(|r| r.kind == OverrideRowKind::Action)
            .filter(|r| matches!(&r.field, Some(AgentSessionOverrideFieldV1::Sandbox { .. })))
            .collect();
        assert_eq!(sandbox_actions.len(), 1);
        assert_eq!(
            sandbox_actions[0].field,
            Some(AgentSessionOverrideFieldV1::Sandbox {
                mode: SandboxMode::Container,
            })
        );
    }

    #[test]
    fn modes_session_setup_override_enter_on_action_emits_apply_with_revision() {
        let mut pane = AgentTreePane::loading(false);
        pane.apply_effective_settings(effective_settings(
            5,
            false,
            SandboxMode::Sandbox,
            vec![SandboxMode::Sandbox, SandboxMode::Container],
        ));
        // The first actionable row is the sandbox `container` reduction.
        let outcome = pane.handle_key(KeyEvent::from(KeyCode::Enter));
        assert_eq!(
            outcome,
            AgentTreeOutcome::ApplyOverride {
                agent_instance_id: Uuid::from_u128(7),
                expected_override_revision: 5,
                field: AgentSessionOverrideFieldV1::Sandbox {
                    mode: SandboxMode::Container,
                },
            }
        );
    }

    #[test]
    fn modes_session_setup_override_terminal_is_read_only() {
        let snapshot = effective_settings(
            2,
            true,
            SandboxMode::Sandbox,
            vec![SandboxMode::Sandbox, SandboxMode::Container],
        );
        let rows = build_override_rows(&snapshot);
        assert!(
            rows.iter().all(|r| r.field.is_none()),
            "a terminal node exposes no actionable override rows"
        );
    }

    #[test]
    fn modes_session_setup_override_esc_returns_to_tree_without_closing() {
        let mut pane = AgentTreePane::loading(false);
        pane.apply(vec![node(7, None, "running", 1)], Vec::new());
        pane.apply_effective_settings(effective_settings(
            1,
            false,
            SandboxMode::Sandbox,
            vec![SandboxMode::Sandbox, SandboxMode::Container],
        ));
        // Esc while in override mode returns to the tree (Stay), not Close.
        let outcome = pane.handle_key(KeyEvent::from(KeyCode::Esc));
        assert_eq!(outcome, AgentTreeOutcome::Stay);
        assert!(pane.override_view.is_none());
    }
}
