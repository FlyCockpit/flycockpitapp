//! `/resources` pane for the daemon-owned resource scheduler.

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, List, ListItem, ListState, Paragraph, Scrollbar, ScrollbarOrientation,
    ScrollbarState,
};

use crate::tui::pane::Pane;
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
    list: ListState,
    selected_request_id: Option<String>,
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
            list: ListState::default(),
            selected_request_id: None,
            last_body_height: 0,
            last_content_rows: 0,
        }
    }

    pub fn apply_snapshot_result(&mut self, result: Result<ResourceSchedulerSnapshot, String>) {
        self.loading = false;
        match result {
            Ok(snapshot) => {
                self.error = None;
                let previous_index = self.selected_index();
                self.selected_request_id = self
                    .selected_request_id
                    .take()
                    .filter(|id| snapshot.queued.iter().any(|entry| entry.display_id == *id))
                    .or_else(|| {
                        snapshot
                            .queued
                            .get(previous_index.min(snapshot.queued.len().saturating_sub(1)))
                            .map(|entry| entry.display_id.clone())
                    });
                self.snapshot = Some(snapshot);
            }
            Err(e) => self.error = Some(e),
        }
    }

    pub(crate) fn pointer_promote(&mut self, request_id: &str) -> Option<ResourcesOutcome> {
        let request_id = self
            .snapshot
            .as_ref()?
            .queued
            .iter()
            .find(|entry| entry.display_id == request_id)?
            .display_id
            .clone();
        self.selected_request_id = Some(request_id.clone());
        Some(ResourcesOutcome::Promote(request_id))
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
                self.move_selection(-1, n);
                None
            }
            KeyCode::Down | KeyCode::Char('j') => {
                let n = self.queued_len();
                self.move_selection(1, n);
                None
            }
            KeyCode::Enter | KeyCode::Char(' ') => self
                .selected_request()
                .map(|entry| ResourcesOutcome::Promote(entry.display_id.clone())),
            _ => None,
        }
    }

    pub fn render(&mut self, frame: &mut Frame, area: Rect) {
        self.render_with_buttons(frame, area, None);
    }

    pub(crate) fn render_with_buttons(
        &mut self,
        frame: &mut Frame,
        area: Rect,
        mut buttons: Option<&mut crate::tui::button::ButtonRegistry>,
    ) {
        let block = Block::default().borders(Borders::ALL).title(" /resources ");
        let inner = block.inner(area);
        frame.render_widget(block, area);

        let layout = Layout::vertical([Constraint::Min(0), Constraint::Length(1)]).split(inner);
        let body = layout[0];
        let help_area = layout[1];

        let (lines, selected_row, queued_rows) =
            self.body_lines_with_selected_row(buttons.is_none());
        self.last_content_rows = lines.len();
        self.last_body_height = body.height as usize;
        self.list.select(selected_row);
        *self.list.offset_mut() = self
            .list
            .offset()
            .min(self.last_content_rows.saturating_sub(self.last_body_height));
        let mut viewport = self.list.clone();
        viewport.select(None);
        frame.render_stateful_widget(
            List::new(lines.into_iter().map(ListItem::new).collect::<Vec<_>>())
                .highlight_style(Style::default().add_modifier(Modifier::BOLD))
                .scroll_padding(1),
            body,
            &mut viewport,
        );
        *self.list.offset_mut() = viewport.offset();
        render_scrollbar(
            frame,
            body,
            self.last_content_rows,
            self.last_body_height,
            self.list.offset(),
        );
        if let Some(registry) = buttons.as_mut() {
            let offset = self.list.offset();
            for (request_id, row) in queued_rows {
                if row < offset || row >= offset + self.last_body_height {
                    continue;
                }
                let y = body.y.saturating_add((row - offset) as u16);
                if y >= body.bottom() || body.width < 11 {
                    continue;
                }
                let spec = crate::tui::button::ButtonSpec::new(
                    crate::tui::button::ButtonId::ResourcePromote {
                        request_id: request_id.clone(),
                    },
                    "promote",
                    crate::tui::button::ButtonDispatch::ResourcePromote {
                        request_id: request_id.clone(),
                    },
                )
                .focused(self.selected_request_id.as_deref() == Some(&request_id));
                let _ = registry.paint(frame, body.right().saturating_sub(10), y, 9, spec);
            }
        }
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
        let snapshot = self.snapshot.as_ref()?;
        self.selected_request_id
            .as_ref()
            .and_then(|id| snapshot.queued.iter().find(|entry| entry.display_id == *id))
            .or_else(|| snapshot.queued.first())
    }

    fn help_line(&self) -> Line<'static> {
        Line::from("q close  r refresh  up/down move  enter/space promote")
    }

    #[cfg(test)]
    fn body_lines(&self) -> Vec<Line<'static>> {
        self.body_lines_with_selected_row(true).0
    }

    #[cfg(test)]
    pub(crate) fn queued_display_ids(&self) -> Vec<String> {
        self.snapshot
            .as_ref()
            .map(|snapshot| {
                snapshot
                    .queued
                    .iter()
                    .map(|entry| entry.display_id.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    fn body_lines_with_selected_row(
        &self,
        show_inline_action: bool,
    ) -> (Vec<Line<'static>>, Option<usize>, Vec<(String, usize)>) {
        let mut lines = Vec::new();
        let mut selected_row = None;
        let mut queued_rows = Vec::new();
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
            return (lines, None, queued_rows);
        }
        let Some(snapshot) = &self.snapshot else {
            lines.push(muted("No scheduler snapshot loaded."));
            return (lines, None, queued_rows);
        };
        if !snapshot.enabled {
            lines.push(muted("Resource scheduler is disabled."));
            return (lines, None, queued_rows);
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
                let selected = i == self.selected_index();
                if selected {
                    selected_row = Some(lines.len());
                }
                queued_rows.push((entry.display_id.clone(), lines.len()));
                lines.push(queued_line(entry, selected, show_inline_action));
            }
        }
        (lines, selected_row, queued_rows)
    }

    fn selected_index(&self) -> usize {
        let Some(snapshot) = &self.snapshot else {
            return 0;
        };
        self.selected_request_id
            .as_ref()
            .and_then(|id| {
                snapshot
                    .queued
                    .iter()
                    .position(|entry| entry.display_id == *id)
            })
            .unwrap_or(0)
    }

    fn select_index(&mut self, index: usize) {
        self.selected_request_id = self
            .snapshot
            .as_ref()
            .and_then(|snapshot| snapshot.queued.get(index))
            .map(|entry| entry.display_id.clone());
    }

    fn move_selection(&mut self, delta: isize, total: usize) {
        if total == 0 {
            self.selected_request_id = None;
            self.list.select(None);
            *self.list.offset_mut() = 0;
            return;
        }
        let current = self.selected_index();
        let next = if delta < 0 {
            crate::tui::nav::wrap_prev(current, total)
        } else {
            crate::tui::nav::wrap_next(current, total)
        };
        self.select_index(next);
    }

    pub fn scroll_up(&mut self) {
        *self.list.offset_mut() = self.list.offset().saturating_sub(1);
    }

    pub fn scroll_down(&mut self) {
        let max = self.last_content_rows.saturating_sub(self.last_body_height);
        *self.list.offset_mut() = (self.list.offset() + 1).min(max);
    }
}

fn render_scrollbar(
    frame: &mut Frame,
    area: Rect,
    content_rows: usize,
    viewport_rows: usize,
    offset: usize,
) {
    if viewport_rows == 0 || content_rows <= viewport_rows || area.width <= 1 {
        return;
    }
    let mut state = ScrollbarState::new(content_rows)
        .position(offset)
        .viewport_content_length(viewport_rows);
    frame.render_stateful_widget(
        Scrollbar::new(ScrollbarOrientation::VerticalRight)
            .begin_symbol(None)
            .end_symbol(None),
        area,
        &mut state,
    );
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

fn queued_line(
    entry: &ResourceQueuedSnapshot,
    selected: bool,
    show_inline_action: bool,
) -> Line<'static> {
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
    let action = if show_inline_action {
        "  [promote]"
    } else {
        ""
    };
    Line::from(vec![Span::styled(
        format!(
            "{marker} {}  {}  {}  {}  wait {}ms  {}{action}",
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
    use crossterm::event::{MouseButton, MouseEvent, MouseEventKind};
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use uuid::Uuid;

    fn press(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: KeyModifiers::empty(),
            kind: KeyEventKind::Press,
            state: KeyEventState::empty(),
        }
    }

    fn mouse(kind: MouseEventKind, x: u16, y: u16) -> MouseEvent {
        MouseEvent {
            kind,
            column: x,
            row: y,
            modifiers: KeyModifiers::NONE,
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

    fn rendered_buffer(pane: &mut ResourcesPane, width: u16, height: u16) -> String {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).expect("terminal");
        terminal
            .draw(|frame| pane.render(frame, Rect::new(0, 0, width, height)))
            .expect("draw resources");
        terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect()
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

    #[test]
    fn test_backend_matrix_covers_loading_unicode_and_widths() {
        let mut loading = ResourcesPane::open();
        assert!(rendered_buffer(&mut loading, 24, 6).contains("Loading"));

        for width in [24, 80, 140] {
            let mut ready = ResourcesPane::open();
            let mut value = snapshot();
            value.queued[0].metadata.command_label = Some("e\u{301}dit-工具".to_string());
            ready.apply_snapshot_result(Ok(value));
            let rendered = rendered_buffer(&mut ready, width, 10);
            assert!(rendered.contains("/resources"));
            assert!(rendered.contains("rs-0002"));
        }
    }

    #[test]
    fn selection_survives_snapshot_reorder_by_request_identity() {
        let mut pane = ResourcesPane::open();
        let mut first = snapshot();
        let mut second = first.queued[0].clone();
        second.id = Uuid::new_v4();
        second.display_id = "rs-0003".to_string();
        first.queued.push(second);
        pane.apply_snapshot_result(Ok(first.clone()));
        pane.handle_key(press(KeyCode::Down));
        assert_eq!(pane.selected_request().unwrap().display_id, "rs-0003");

        first.queued.reverse();
        pane.apply_snapshot_result(Ok(first));
        assert_eq!(pane.selected_request().unwrap().display_id, "rs-0003");
    }

    #[test]
    fn visible_promote_button_uses_same_pass_row_geometry() {
        let mut pane = ResourcesPane::open();
        pane.apply_snapshot_result(Ok(snapshot()));
        let mut registry = crate::tui::button::ButtonRegistry::default();
        registry.begin_frame(true, 1);
        let mut terminal = Terminal::new(TestBackend::new(80, 12)).expect("terminal");
        terminal
            .draw(|frame| {
                pane.render_with_buttons(frame, Rect::new(0, 0, 80, 12), Some(&mut registry))
            })
            .expect("draw resources with buttons");
        assert_eq!(registry.targets().len(), 1);
        assert!(matches!(
            &registry.targets()[0].id,
            crate::tui::button::ButtonId::ResourcePromote { request_id }
                if request_id == "rs-0002"
        ));
        assert!(registry.targets()[0].rect.y < 11);
    }

    #[test]
    fn pressed_promote_identity_survives_reorder_and_activates_exact_request() {
        let mut value = snapshot();
        let mut other = value.queued[0].clone();
        other.id = Uuid::new_v4();
        other.display_id = "rs-0003".to_string();
        value.queued.push(other);
        let mut pane = ResourcesPane::open();
        pane.apply_snapshot_result(Ok(value.clone()));
        let mut registry = crate::tui::button::ButtonRegistry::default();
        registry.begin_frame(true, 7);
        let mut terminal = Terminal::new(TestBackend::new(80, 16)).expect("terminal");
        terminal
            .draw(|frame| {
                pane.render_with_buttons(frame, Rect::new(0, 0, 80, 16), Some(&mut registry))
            })
            .expect("initial render");
        registry.end_frame();
        let pressed = registry
            .targets()
            .iter()
            .find(|target| matches!(&target.id, crate::tui::button::ButtonId::ResourcePromote { request_id } if request_id == "rs-0002"))
            .expect("original request target")
            .rect;
        assert!(matches!(
            registry.handle_mouse(mouse(
                MouseEventKind::Down(MouseButton::Left),
                pressed.x,
                pressed.y
            )),
            Some(crate::tui::button::ButtonPointerOutcome::Pressed(_))
        ));

        value.queued.reverse();
        pane.apply_snapshot_result(Ok(value));
        registry.begin_frame(true, 7);
        terminal
            .draw(|frame| {
                pane.render_with_buttons(frame, Rect::new(0, 0, 80, 16), Some(&mut registry))
            })
            .expect("reordered render");
        registry.end_frame();
        let moved = registry
            .targets()
            .iter()
            .find(|target| matches!(&target.id, crate::tui::button::ButtonId::ResourcePromote { request_id } if request_id == "rs-0002"))
            .expect("same request after reorder")
            .rect;
        assert!(matches!(
            registry.handle_mouse(mouse(
                MouseEventKind::Up(MouseButton::Left),
                moved.x,
                moved.y
            )),
            Some(crate::tui::button::ButtonPointerOutcome::Activated(
                crate::tui::button::ButtonDispatch::ResourcePromote { request_id }
            )) if request_id == "rs-0002"
        ));
    }

    #[test]
    fn wheel_viewport_remains_independent_of_selected_queued_row() {
        let mut value = snapshot();
        for index in 0..6 {
            let mut pool = value.pools[0].clone();
            pool.name = format!("pool-{index}");
            value.pools.push(pool);
            let mut running = value.running[0].clone();
            running.id = Uuid::new_v4();
            running.display_id = format!("running-{index}");
            value.running.push(running);
        }
        let mut pane = ResourcesPane::open();
        pane.apply_snapshot_result(Ok(value));
        let initial = rendered_buffer(&mut pane, 80, 10);
        assert!(initial.contains("Pools"));
        assert_eq!(pane.list.offset(), 0);

        pane.scroll_down();
        pane.scroll_down();
        let scrolled = rendered_buffer(&mut pane, 80, 10);
        assert_eq!(pane.list.offset(), 2);
        assert_ne!(scrolled, initial);

        for _ in 0..100 {
            pane.scroll_down();
        }
        let _ = rendered_buffer(&mut pane, 80, 10);
        assert_eq!(
            pane.list.offset(),
            pane.last_content_rows.saturating_sub(pane.last_body_height)
        );
    }
}
