use std::time::Duration;

use cockpit_tui::test_support::{ResponsePerformanceE2eHarness, ResponsePerformanceE2eInput};

#[tokio::test]
async fn response_performance_e2e_stream_produces_clickable_chip() {
    let observation = ResponsePerformanceE2eHarness::run(ResponsePerformanceE2eInput::new(
        "Build",
        "local",
        "test-model",
        vec![
            (Duration::from_millis(100), "Hello ".to_string()),
            (Duration::from_millis(200), "world".to_string()),
        ],
        vec![Ok(2)],
    ))
    .await;

    assert!(
        observation.metric.ttft_ms > 0 || observation.metric.displayed_tokens > 0,
        "injected-time deltas must produce a nonzero metric"
    );
    assert_eq!(observation.metric.ttft_ms, 100);
    assert_eq!(observation.metric.generation_ms, 100);
    assert_eq!(observation.metric.displayed_tokens, 2);

    let completes = observation
        .published_events
        .iter()
        .filter(|event| matches!(event, cockpit_proto::Event::AssistantDisplayComplete { .. }))
        .count();
    assert_eq!(completes, 1, "exactly one real AssistantDisplayComplete");

    assert!(
        observation.chip_col_end > observation.chip_col_start,
        "chip hit range must cover at least one cell"
    );
    let row = observation
        .rendered_cells
        .get(observation.chip_row as usize)
        .expect("hit row is inside the rendered buffer");
    let chip: String = row
        .get(observation.chip_col_start as usize..observation.chip_col_end as usize)
        .expect("hit columns are inside the rendered row")
        .join("");
    assert_eq!(
        chip, "0.1/20",
        "rendered target range must contain exactly the chip cells, got {chip:?}"
    );

    assert!(
        observation.performance_expanded,
        "down/up in the chip range must expand the matching row"
    );
    assert_eq!(observation.expanded_history_index, 0);
}
