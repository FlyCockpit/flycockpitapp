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

use cockpit_proto::{AgentDecisionAttention, AgentTreeNode};

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

    pub(crate) fn render(&mut self, frame: &mut Frame, area: Rect) {
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
}
