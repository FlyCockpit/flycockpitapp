//! `/resources` pane for the daemon-owned resource scheduler.

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};

use crate::tui::pane::{Pane, ScrollList};
use crate::tui::theme::{ACCENT_BLUE_INDEX, MUTED_COLOR_INDEX};
use cockpit_core::engine::resource_scheduler::{
    ResourceQueuedSnapshot, ResourceQueuedState, ResourceRunningSnapshot, ResourceSchedulerSnapshot,
};

#[derive(Debug)]
pub enum ResourcesOutcome {
    Close,
    Refresh,
    Promote(String),
}

pub struct ResourcesPane {
    snapshot: Option<ResourceSchedulerSnapshot>,
    error: Option<String>,
    loading: bool,
    list: ScrollList,
    last_body_height: usize,
    last_content_rows: usize,
}

impl ResourcesPane {
    pub fn keybindings() -> crate::tui::keys_overlay::KeyGroup {
        use crate::tui::keys_overlay::{KeyBinding, KeyGroup};
        KeyGroup {
            title: "Resources",
            bindings: &[
                KeyBinding {
                    key: "↑/↓",
                    action: "move",
                    desc: "highlight a queued resource request",
                },
                KeyBinding {
                    key: "Enter/Space",
                    action: "promote",
                    desc: "move the highlighted request to the front",
                },
                KeyBinding {
                    key: "r",
                    action: "refresh",
                    desc: "reload scheduler state",
                },
                KeyBinding {
                    key: "q/Esc",
                    action: "close",
                    desc: "close the resources pane",
                },
            ],
        }
    }

    pub fn open() -> Self {
        Self {
            snapshot: None,
            error: None,
            loading: true,
            list: ScrollList::new(),
            last_body_height: 0,
            last_content_rows: 0,
        }
    }

    pub fn apply_snapshot_result(&mut self, result: Result<ResourceSchedulerSnapshot, String>) {
        self.loading = false;
        match result {
            Ok(snapshot) => {
                self.error = None;
                self.list.clamp_cursor(snapshot.queued.len());
                self.snapshot = Some(snapshot);
            }
            Err(e) => self.error = Some(e),
        }
    }

    pub fn handle_key(&mut self, key: KeyEvent) -> Option<ResourcesOutcome> {
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') => Some(ResourcesOutcome::Close),
            KeyCode::Char('r') => {
                self.loading = true;
                Some(ResourcesOutcome::Refresh)
            }
            KeyCode::Up | KeyCode::Char('k') => {
                let n = self.queued_len();
                self.list.move_by(-1, n);
                None
            }
            KeyCode::Down | KeyCode::Char('j') => {
                let n = self.queued_len();
                self.list.move_by(1, n);
                None
            }
            KeyCode::Enter | KeyCode::Char(' ') => self
                .selected_request()
                .map(|entry| ResourcesOutcome::Promote(entry.display_id.clone())),
            _ => None,
        }
    }

    pub fn render(&mut self, frame: &mut Frame, area: Rect) {
        let block = Block::default().borders(Borders::ALL).title(" /resources ");
        let inner = block.inner(area);
        frame.render_widget(block, area);

        let layout = Layout::vertical([Constraint::Min(0), Constraint::Length(1)]).split(inner);
        let body = layout[0];
        let help_area = layout[1];

        let (lines, selected_span) = self.body_lines_with_selected_span();
        self.last_content_rows = lines.len();
        self.last_body_height = body.height as usize;
        let max_scroll = self.last_content_rows.saturating_sub(self.last_body_height);
        self.list.set_scroll(self.list.scroll().min(max_scroll));
        if let Some((start, end)) = selected_span {
            self.list
                .clamp_visible_span(self.last_body_height, self.last_content_rows, start, end);
        }
        frame.render_widget(
            Paragraph::new(lines).scroll((self.list.scroll() as u16, 0)),
            body,
        );
        frame.render_widget(
            Paragraph::new(self.help_line())
                .style(Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX))),
            help_area,
        );
    }

    fn queued_len(&self) -> usize {
        self.snapshot.as_ref().map(|s| s.queued.len()).unwrap_or(0)
    }

    fn selected_request(&self) -> Option<&ResourceQueuedSnapshot> {
        self.snapshot
            .as_ref()
            .and_then(|snapshot| snapshot.queued.get(self.list.cursor()))
    }

    fn help_line(&self) -> Line<'static> {
        Line::from("q close  r refresh  up/down move  enter/space promote")
    }

    #[cfg(test)]
    fn body_lines(&self) -> Vec<Line<'static>> {
        self.body_lines_with_selected_span().0
    }

    fn body_lines_with_selected_span(&self) -> (Vec<Line<'static>>, Option<(usize, usize)>) {
        let mut lines = Vec::new();
        let mut selected_span = None;
        if let Some(e) = &self.error {
            lines.push(Line::from(Span::styled(
                format!("resources unavailable: {e}"),
                Style::default().fg(Color::Red),
            )));
            lines.push(Line::default());
        }
        if self.loading {
            lines.push(Line::from(Span::styled(
                "Loading resources...",
                Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX)),
            )));
            return (lines, None);
        }
        let Some(snapshot) = &self.snapshot else {
            lines.push(muted("No scheduler snapshot loaded."));
            return (lines, None);
        };
        if !snapshot.enabled {
            lines.push(muted("Resource scheduler is disabled."));
            return (lines, None);
        }

        lines.push(section("Pools"));
        if snapshot.pools.is_empty() {
            lines.push(muted("  no pools configured"));
        } else {
            for pool in &snapshot.pools {
                lines.push(Line::from(format!(
                    "  {}  used {}/{}  available {}",
                    pool.name, pool.used, pool.capacity, pool.available
                )));
            }
        }

        lines.push(Line::default());
        lines.push(section("Running"));
        if snapshot.running.is_empty() {
            lines.push(muted("  none"));
        } else {
            for entry in &snapshot.running {
                lines.push(running_line(entry));
            }
        }

        lines.push(Line::default());
        lines.push(section("Queued"));
        if snapshot.queued.is_empty() {
            lines.push(muted("  none"));
        } else {
            for (i, entry) in snapshot.queued.iter().enumerate() {
                let start = lines.len();
                lines.push(queued_line(entry, i == self.list.cursor()));
                if i == self.list.cursor() {
                    selected_span = Some((start, start + 1));
                }
            }
        }
        (lines, selected_span)
    }
}

fn section(text: &str) -> Line<'static> {
    Line::from(Span::styled(
        text.to_string(),
        Style::default()
            .fg(Color::Indexed(ACCENT_BLUE_INDEX))
            .add_modifier(Modifier::BOLD),
    ))
}

impl Pane for ResourcesPane {
    type Outcome = Option<ResourcesOutcome>;

    fn handle_key(&mut self, key: KeyEvent) -> Self::Outcome {
        ResourcesPane::handle_key(self, key)
    }

    fn render(&mut self, frame: &mut Frame, area: Rect) {
        ResourcesPane::render(self, frame, area);
    }
}

fn muted(text: impl Into<String>) -> Line<'static> {
    Line::from(Span::styled(
        text.into(),
        Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX)),
    ))
}

fn running_line(entry: &ResourceRunningSnapshot) -> Line<'static> {
    Line::from(format!(
        "  {}  {}  {}  {}  wait {}ms  running",
        entry.display_id,
        actor_label(
            entry.metadata.agent_id.as_deref(),
            entry.metadata.session_id.map(|id| id.to_string())
        ),
        command_label(entry.metadata.command_label.as_deref()),
        resources_label(&entry.resources.pools),
        entry.wait_ms
    ))
}

fn queued_line(entry: &ResourceQueuedSnapshot, selected: bool) -> Line<'static> {
    let marker = if selected { ">" } else { " " };
    let state = match entry.state {
        ResourceQueuedState::Queued => "queued",
        ResourceQueuedState::Promoted => "promoted",
    };
    let style = if selected {
        Style::default().add_modifier(Modifier::BOLD)
    } else {
        Style::default()
    };
    Line::from(vec![Span::styled(
        format!(
            "{marker} {}  {}  {}  {}  wait {}ms  {}  [promote]",
            entry.display_id,
            actor_label(
                entry.metadata.agent_id.as_deref(),
                entry.metadata.session_id.map(|id| id.to_string())
            ),
            command_label(entry.metadata.command_label.as_deref()),
            resources_label(&entry.resources.pools),
            entry.wait_ms,
            state
        ),
        style,
    )])
}

fn actor_label(agent: Option<&str>, session_id: Option<String>) -> String {
    match (agent, session_id) {
        (Some(agent), Some(session_id)) => {
            format!("{agent}/{}", session_id.chars().take(8).collect::<String>())
        }
        (Some(agent), None) => agent.to_string(),
        (None, Some(session_id)) => session_id.chars().take(8).collect(),
        (None, None) => "unknown".to_string(),
    }
}

fn resources_label(resources: &std::collections::BTreeMap<String, u32>) -> String {
    if resources.is_empty() {
        return "-".to_string();
    }
    resources
        .iter()
        .map(|(name, count)| format!("{name}:{count}"))
        .collect::<Vec<_>>()
        .join(",")
}

fn command_label(label: Option<&str>) -> String {
    let label = label.unwrap_or("unknown").trim();
    if label.is_empty() {
        return "unknown".to_string();
    }
    let mut out = label.chars().take(32).collect::<String>();
    if label.chars().count() > 32 {
        out.push_str("...");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use cockpit_core::engine::resource_scheduler::{
        ResourcePoolSnapshot, ResourceRequestMetadata, ResourceRequirements,
    };
    use crossterm::event::{KeyEventKind, KeyEventState, KeyModifiers};
    use uuid::Uuid;

    fn press(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: KeyModifiers::empty(),
            kind: KeyEventKind::Press,
            state: KeyEventState::empty(),
        }
    }

    fn snapshot() -> ResourceSchedulerSnapshot {
        let metadata = ResourceRequestMetadata {
            session_id: Some(Uuid::nil()),
            agent_id: Some("Build".to_string()),
            command_label: Some("bash".to_string()),
            effective_requirements: ResourceRequirements::new([("cpu", 1)]),
            ..ResourceRequestMetadata::default()
        };
        ResourceSchedulerSnapshot {
            enabled: true,
            pools: vec![ResourcePoolSnapshot {
                name: "cpu".to_string(),
                capacity: 2,
                used: 2,
                available: 0,
            }],
            running: vec![ResourceRunningSnapshot {
                id: Uuid::new_v4(),
                display_id: "rs-0001".to_string(),
                resources: ResourceRequirements::new([("cpu", 1)]),
                metadata: metadata.clone(),
                queued_at_ms: 0,
                started_at_ms: 1,
                wait_ms: 1,
                promoted_by: None,
                promoted_at_ms: None,
            }],
            queued: vec![ResourceQueuedSnapshot {
                id: Uuid::new_v4(),
                display_id: "rs-0002".to_string(),
                resources: ResourceRequirements::new([("cpu", 1)]),
                metadata,
                queued_at_ms: 2,
                wait_ms: 10,
                state: ResourceQueuedState::Queued,
                promoted_by: None,
                promoted_at_ms: None,
            }],
            max_queued: 16,
        }
    }

    fn render_text(pane: &ResourcesPane) -> String {
        pane.body_lines()
            .into_iter()
            .map(|line| {
                line.spans
                    .into_iter()
                    .map(|span| span.content.into_owned())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn renders_running_and_queued_snapshot() {
        let mut pane = ResourcesPane::open();
        pane.apply_snapshot_result(Ok(snapshot()));

        let text = render_text(&pane);
        assert!(text.contains("Pools"));
        assert!(text.contains("rs-0001"));
        assert!(text.contains("rs-0002"));
        assert!(text.contains("[promote]"));
    }

    #[test]
    fn enter_promotes_selected_queued_request() {
        let mut pane = ResourcesPane::open();
        pane.apply_snapshot_result(Ok(snapshot()));

        match pane.handle_key(press(KeyCode::Enter)) {
            Some(ResourcesOutcome::Promote(id)) => assert_eq!(id, "rs-0002"),
            other => panic!("expected promote outcome, got {other:?}"),
        }
    }
}
