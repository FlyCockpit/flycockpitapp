use super::*;
use crate::engine::tool::Tool;

#[test]
fn bash_descriptions_carry_required_steering() {
    let tool = BashTool::new();
    let terse = tool.description();
    let len = terse.len();
    assert!(
        (300..=400).contains(&len),
        "bash terse description is {len} bytes: {terse}"
    );
    let verbose = tool.verbose_description().unwrap();
    for (description, required) in [
        (
            terse,
            &[
                "read",
                "search",
                "code",
                "cat",
                "grep",
                "ls",
                "find",
                "Fresh shell",
                "cd/env do NOT persist",
                "Non-interactive",
                "pagers",
                "120s default",
            ][..],
        ),
        (
            verbose.as_str(),
            &[
                "non-interactive",
                "stdin is /dev/null",
                "pagers",
                "editors",
                "tail -f",
                "servers",
            ][..],
        ),
    ] {
        for term in required {
            assert!(description.contains(term), "missing {term}: {description}");
        }
    }
    assert!(
        ["-i", "watch", "tail -f", "servers"]
            .iter()
            .any(|term| terse.contains(term)),
        "{terse}"
    );
}

#[test]
fn bash_timeout_schema_declares_default_and_bounds_in_both_tiers() {
    let tool = BashTool::new();
    let normal = tool.parameters();
    let defensive = tool.verbose_parameters().unwrap();

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

/// #528: on macOS the hedged `sed` hint is part of the description the
/// provider actually receives (`advertised_definitions`, not a capability
/// suffix that inference never sends), in both steering tiers; other build
/// targets carry no hint.
#[test]
fn macos_sed_hint_is_in_the_provider_visible_definition_only_on_macos() {
    let toolbox = crate::engine::tool::ToolBox::new().with(std::sync::Arc::new(BashTool::new()));
    for steering in [
        crate::agents::ToolSteering::Terse,
        crate::agents::ToolSteering::Verbose,
    ] {
        let definitions = toolbox.advertised_definitions(steering);
        let bash = definitions
            .iter()
            .find(|definition| definition.name == "bash")
            .expect("bash is advertised");
        assert_eq!(
            bash.description.contains("`sed` may be BSD sed"),
            cfg!(target_os = "macos"),
            "{steering:?}: {}",
            bash.description
        );
    }
}
