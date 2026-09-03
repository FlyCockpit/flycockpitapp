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
    // Every root of the public local profile gets a man page, mirroring the
    // fixture-pinned surface (canonical roots; nested subcommands also get
    // pages and are covered by the recursion itself).
    for command in [
        "acp",
        "ask",
        "run",
        "invocation",
        "agent",
        "code",
        "assistant",
        "computer",
        "assistants",
        "provider",
        "setup",
        "models",
        "provider-catalog-status",
        "fetch-models",
        "jq",
        "daemon",
        "doctor",
        "session",
        "knowledge",
        "dream",
        "skill",
        "trust",
        "export",
        "import",
        "stats",
        "debug",
        "config",
        "mcp",
        "packages",
        "kcl",
        "init",
        "bash-hints",
        "completion",
    ] {
        assert!(
            pages.contains(&format!("cockpit-{command}.1")),
            "missing {command} man page"
        );
    }
    // Roots outside the local profile (opt-in `extended`/`remote` features)
    // stay out of the public local man pages.
    for internal in ["schedule", "account", "sync", "connect"] {
        assert!(
            !pages.contains(&format!("cockpit-{internal}.1")),
            "unexpected public {internal} man page"
        );
    }
}
