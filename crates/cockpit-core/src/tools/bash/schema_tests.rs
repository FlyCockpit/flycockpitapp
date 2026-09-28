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
    for term in ["read", "search", "code", "cat", "grep", "ls", "find"] {
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
fn bash_verbose_description_warns_about_interactive_and_long_running_commands() {
    let description = BashTool::new().verbose_description().unwrap();
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

/// #528 follow-up: the macOS `sed` note reflects what the effective PATH
/// resolves, and is never claimed for containers, other hosts, or a GNU
/// `sed` shadowing the system one (Homebrew gnubin first on PATH).
#[test]
fn sed_flavor_note_describes_only_a_resolved_system_bsd_sed_on_a_macos_host() {
    use crate::capabilities::ExecutionTarget::{Container, Host};
    let bsd = Some(Path::new("/usr/bin/sed"));
    let gnubin = Some(Path::new("/opt/homebrew/opt/gnu-sed/libexec/gnubin/sed"));
    let with_gsed = sed_flavor_note(true, Host, bsd, true).expect("BSD sed on a macOS host");
    assert!(with_gsed.contains("BSD sed") && with_gsed.contains("`gsed`"));
    let without_gsed = sed_flavor_note(true, Host, bsd, false).expect("BSD sed without gsed");
    assert!(without_gsed.contains("BSD sed") && !without_gsed.contains("gsed"));
    assert_eq!(sed_flavor_note(true, Host, gnubin, true), None);
    assert_eq!(sed_flavor_note(true, Host, None, true), None);
    assert_eq!(sed_flavor_note(true, Container, bsd, true), None);
    assert_eq!(sed_flavor_note(false, Host, bsd, true), None);
}
