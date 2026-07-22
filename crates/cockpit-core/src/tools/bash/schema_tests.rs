use super::*;
use crate::engine::tool::Tool;

#[test]
fn bash_terse_description_is_within_the_raised_budget() {
    let tool = BashTool::new();
    let len = tool.description().len();
    assert!(
        (300..=400).contains(&len),
        "bash terse description is {len} bytes: {}",
        tool.description()
    );
}

#[test]
fn bash_terse_description_routes_to_native_tools() {
    let description = BashTool::new().description().to_string();
    for term in ["read", "search", "tree", "cat", "grep", "ls", "find"] {
        assert!(description.contains(term), "missing {term}: {description}");
    }
}

#[test]
fn bash_terse_description_states_fresh_shell_semantics() {
    let description = BashTool::new().description().to_string();
    assert!(description.contains("Fresh shell"), "{description}");
    assert!(
        description.contains("cd/env do NOT persist"),
        "{description}"
    );
}

#[test]
fn bash_terse_description_warns_about_interactive_and_long_running_commands() {
    let description = BashTool::new().description().to_string();
    assert!(description.contains("Non-interactive"), "{description}");
    assert!(description.contains("pagers"), "{description}");
    assert!(
        ["-i", "watch", "tail -f", "servers"]
            .iter()
            .any(|needle| description.contains(needle)),
        "{description}"
    );
}

#[test]
fn bash_terse_description_states_the_default_timeout() {
    let description = BashTool::new().description().to_string();
    assert!(description.contains("120s default"), "{description}");
}

#[test]
fn bash_defensive_description_warns_about_interactive_and_long_running_commands() {
    let description = BashTool::new().defensive_description().unwrap();
    assert!(description.contains("non-interactive"), "{description}");
    assert!(description.contains("stdin is /dev/null"), "{description}");
    assert!(description.contains("pagers"), "{description}");
    assert!(description.contains("editors"), "{description}");
    assert!(description.contains("tail -f"), "{description}");
    assert!(description.contains("servers"), "{description}");
}

#[test]
fn bash_timeout_schema_declares_default_and_bounds_in_both_tiers() {
    let tool = BashTool::new();
    let normal = tool.parameters();
    let defensive = tool.defensive_parameters().unwrap();

    for field in ["timeout_ms", "queue_timeout_ms"] {
        let normal_field = &normal["properties"][field];
        let defensive_field = &defensive["properties"][field];
        for keyword in ["default", "minimum", "maximum"] {
            assert_eq!(
                normal_field[keyword], defensive_field[keyword],
                "{field}.{keyword} differs"
            );
        }
        assert_eq!(
            normal_field["default"],
            serde_json::json!(DEFAULT_TIMEOUT_MS)
        );
        assert_eq!(normal_field["maximum"], serde_json::json!(MAX_TIMEOUT_MS));
    }

    assert_eq!(
        normal["properties"]["timeout_ms"]["minimum"],
        serde_json::json!(MIN_TIMEOUT_MS)
    );
    assert_eq!(
        normal["properties"]["queue_timeout_ms"]["minimum"],
        serde_json::json!(MIN_QUEUE_TIMEOUT_MS)
    );
}
