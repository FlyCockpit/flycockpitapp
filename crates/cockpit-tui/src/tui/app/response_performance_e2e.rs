//! Response-performance e2e harness. Feature-gated; not a production API.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use cockpit_client::presentation::ResponsePerformance;
use cockpit_core::test_support::{
    ResponsePerformanceE2eStreamChunk, drive_response_performance_dispatcher_for_e2e,
    turn_event_to_proto_for_response_performance_e2e,
};
use crossterm::event::{KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
use ratatui::Terminal;
use ratatui::backend::TestBackend;
use uuid::Uuid;

use super::{App, StartupWorkspaceTrust};
use crate::tui::agent_runner::{AgentRunner, TestRunnerOverrides};
use crate::tui::history::HistoryEntry;
use crate::tui::settings::Dialog;

/// Fake provider/model stream plus injected tokenizer outcomes.
pub struct ResponsePerformanceE2eInput {
    agent: String,
    provider: String,
    model: String,
    text_chunks: Vec<(Duration, String)>,
    tokenizer_outcomes: Vec<Result<usize, String>>,
}

impl ResponsePerformanceE2eInput {
    pub fn new(
        agent: impl Into<String>,
        provider: impl Into<String>,
        model: impl Into<String>,
        text_chunks: Vec<(Duration, String)>,
        tokenizer_outcomes: Vec<Result<usize, String>>,
    ) -> Self {
        Self {
            agent: agent.into(),
            provider: provider.into(),
            model: model.into(),
            text_chunks,
            tokenizer_outcomes,
        }
    }
}

/// Observations after driving the production pipeline through a click.
pub struct ResponsePerformanceE2eObservation {
    pub published_events: Vec<cockpit_proto::Event>,
    pub metric: ResponsePerformance,
    pub rendered_cells: Vec<Vec<String>>,
    pub chip_row: u16,
    pub chip_col_start: u16,
    pub chip_col_end: u16,
    pub expanded_history_index: usize,
    pub performance_expanded: bool,
}

/// Runs the production dispatcher → proto conversion → AgentRunner
/// reducer → render → mouse down/up path.
pub struct ResponsePerformanceE2eHarness;

impl ResponsePerformanceE2eHarness {
    pub async fn run(input: ResponsePerformanceE2eInput) -> ResponsePerformanceE2eObservation {
        let session_id = Uuid::new_v4();
        let chunks = input
            .text_chunks
            .into_iter()
            .map(|(at, text)| ResponsePerformanceE2eStreamChunk::Text { at, text })
            .collect();
        let turn_events = drive_response_performance_dispatcher_for_e2e(
            input.agent,
            input.provider,
            input.model,
            chunks,
            input.tokenizer_outcomes,
        )
        .await;

        let (publication_tx, mut publication_rx) = tokio::sync::mpsc::unbounded_channel();
        for event in turn_events {
            for converted in turn_event_to_proto_for_response_performance_e2e(event, session_id) {
                publication_tx
                    .send(converted)
                    .expect("in-memory publication sink remains attached");
            }
        }
        drop(publication_tx);
        let mut published_events = Vec::new();
        while let Some(event) = publication_rx.recv().await {
            published_events.push(event);
        }

        let metric = published_events
            .iter()
            .find_map(|event| match event {
                cockpit_proto::Event::AssistantDisplayComplete {
                    response_performance: Some(perf),
                    ..
                } => Some(ResponsePerformance {
                    ttft_ms: perf.ttft_ms,
                    generation_ms: perf.generation_ms,
                    displayed_tokens: perf.displayed_tokens,
                    encoding: perf.encoding.clone(),
                }),
                _ => None,
            })
            .expect("production dispatcher must emit AssistantDisplayComplete with a snapshot");

        let tmp = tempfile::tempdir().expect("e2e tempdir");
        let mut app =
            App::new_with_workspace_trust(Some(tmp.path()), false, StartupWorkspaceTrust::Decided);
        app.daemon_prompt = None;
        app.dialog = Dialog::None;
        app.mouse_capture = true;
        app.copy_on_release = false;

        let last_applied_seq = Arc::new(Mutex::new(None));
        let runner = AgentRunner::test_fixture(TestRunnerOverrides {
            session_id: Some(session_id),
            last_applied_seq: Some(Arc::clone(&last_applied_seq)),
            ..Default::default()
        });
        for event in published_events.iter().cloned() {
            runner.apply_published_event(event);
        }
        app.agent_runner = Some(Ok(runner));
        app.drain_agent_events();

        const WIDTH: u16 = 80;
        const HEIGHT: u16 = 24;
        let backend = TestBackend::new(WIDTH, HEIGHT);
        let mut terminal = Terminal::new(backend).expect("e2e test backend");
        terminal
            .draw(|frame| app.render(frame))
            .expect("e2e render");
        let buffer = terminal.backend().buffer().clone();
        let rendered_cells = buffer_cells(&buffer);

        let area = app.chat_area.expect("render registers chat_area");
        let (rel_row, hit) = app
            .chat_row_meta
            .iter()
            .enumerate()
            .find_map(|(row, meta)| meta.metric_hit.map(|hit| (row, hit)))
            .expect("render pass must register the performance-chip hit target");
        let chip_row = area.y.saturating_add(rel_row as u16);
        let chip_col_start = area.x.saturating_add(hit.col_start);
        let chip_col_end = area.x.saturating_add(hit.col_end);
        let click_col =
            chip_col_start.saturating_add(chip_col_end.saturating_sub(chip_col_start) / 2);
        let click_row = chip_row;

        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: click_col,
            row: click_row,
            modifiers: KeyModifiers::empty(),
        });
        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::Up(MouseButton::Left),
            column: click_col,
            row: click_row,
            modifiers: KeyModifiers::empty(),
        });

        let expanded_history_index = hit.history_index;
        let performance_expanded = match app.history.get(expanded_history_index) {
            Some(HistoryEntry::Agent {
                performance_expanded,
                ..
            }) => *performance_expanded,
            other => panic!("expected Agent history row after click, got {other:?}"),
        };

        ResponsePerformanceE2eObservation {
            published_events,
            metric,
            rendered_cells,
            chip_row,
            chip_col_start,
            chip_col_end,
            expanded_history_index,
            performance_expanded,
        }
    }
}

fn buffer_cells(buffer: &ratatui::buffer::Buffer) -> Vec<Vec<String>> {
    let area = *buffer.area();
    let mut rows = Vec::with_capacity(area.height as usize);
    for y in 0..area.height {
        let mut row = Vec::with_capacity(area.width as usize);
        for x in 0..area.width {
            row.push(buffer[(x, y)].symbol().to_string());
        }
        rows.push(row);
    }
    rows
}
