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

/// #528 follow-up: the macOS `sed` note reflects what each launcher's child
/// shell resolves, and is never claimed for containers, other hosts, or a GNU
/// `sed` shadowing the system one (Homebrew gnubin first on PATH).
#[test]
fn sed_flavor_note_describes_only_a_resolved_system_bsd_sed_on_a_macos_host() {
    use crate::capabilities::ExecutionTarget::{Container, Host};
    let bsd = |gsed| ChildSed {
        sed: Some(Path::new("/usr/bin/sed")),
        gsed,
    };
    let gnubin = ChildSed {
        sed: Some(Path::new("/opt/homebrew/opt/gnu-sed/libexec/gnubin/sed")),
        gsed: true,
    };
    let both = sed_flavor_note(true, Host, bsd(true), bsd(true)).expect("BSD sed everywhere");
    assert_eq!(both, " `sed` is BSD sed; use `gsed` for GNU sed syntax.");
    let no_gsed = sed_flavor_note(true, Host, bsd(false), bsd(false)).expect("no gsed");
    assert!(
        no_gsed.contains("BSD sed") && !no_gsed.contains("gsed"),
        "{no_gsed}"
    );
    let unsandboxed_only =
        sed_flavor_note(true, Host, gnubin, bsd(true)).expect("unsandboxed BSD sed");
    assert!(
        unsandboxed_only.contains("in unsandboxed runs"),
        "{unsandboxed_only}"
    );
    let sandboxed_only = sed_flavor_note(true, Host, bsd(true), gnubin).expect("sandboxed BSD");
    assert!(
        sandboxed_only.contains("in sandboxed runs"),
        "{sandboxed_only}"
    );
    assert_eq!(sed_flavor_note(true, Host, gnubin, gnubin), None);
    assert_eq!(
        sed_flavor_note(true, Host, ChildSed::default(), ChildSed::default()),
        None
    );
    assert_eq!(sed_flavor_note(true, Container, bsd(true), bsd(true)), None);
    assert_eq!(sed_flavor_note(false, Host, bsd(true), bsd(true)), None);
}

/// G2: without a session-overlay `PATH` the unsandboxed child (`env_clear()`
/// + overlay) sees the shell's default `PATH`, not the daemon's; the
/// sandboxed child keeps the daemon's. An overlay `PATH` wins for both.
#[test]
fn bash_child_paths_follow_each_launcher() {
    assert_eq!(
        bash_child_paths(None, Some("/daemon/bin"), Some("/usr/bin:/bin")),
        (
            Some("/daemon/bin".to_string()),
            Some("/usr/bin:/bin".to_string())
        )
    );
    assert_eq!(
        bash_child_paths(Some("/overlay/bin"), Some("/daemon/bin"), Some("/usr/bin")),
        (
            Some("/overlay/bin".to_string()),
            Some("/overlay/bin".to_string())
        )
    );
}

/// G2 end to end on a real macOS host: with no overlay `PATH`, the
/// unsandboxed child's `sh` default `PATH` resolves the system BSD sed, so
/// the note must say so even when the daemon's own `PATH` puts GNU sed
/// (Homebrew gnubin) first.
#[cfg(target_os = "macos")]
#[test]
fn macos_note_reflects_the_unsandboxed_child_default_path() {
    let note = BashTool::new()
        .capability_description_note(
            &std::collections::HashMap::new(),
            Path::new("/"),
            crate::capabilities::ExecutionTarget::Host,
        )
        .expect("an env_clear()ed macOS sh resolves /usr/bin/sed");
    assert!(note.contains("BSD sed"), "{note}");
}
