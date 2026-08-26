//! Man-page generation tests for release packaging.

#[test]
fn mangen_generates_and_hides_hidden() {
    let tempdir = tempfile::tempdir().expect("tempdir");

    cockpit_cli::manpages::generate_manpages(tempdir.path()).expect("generate man pages");

    let main_page = tempdir.path().join("cockpit.1");
    assert!(main_page.is_file(), "main man page should exist");

    let rendered = std::fs::read_to_string(&main_page).expect("read main man page");
    assert!(rendered.contains("AI coding harness"));
    assert!(!rendered.contains("pure"), "hidden --pure must not render");

    let pages = std::fs::read_dir(tempdir.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect::<std::collections::BTreeSet<_>>();
    for command in [
        "ask", "run", "agent", "provider", "setup", "models", "daemon", "doctor", "session",
        "trust", "export", "config", "init",
    ] {
        assert!(
            pages.contains(&format!("cockpit-{command}.1")),
            "missing {command} man page"
        );
    }
    for internal in [
        "assistant",
        "invocation",
        "mcp",
        "schedule",
        "skill",
        "stats",
    ] {
        assert!(
            !pages.contains(&format!("cockpit-{internal}.1")),
            "unexpected public {internal} man page"
        );
    }
}
