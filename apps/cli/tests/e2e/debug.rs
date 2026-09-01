use crate::support::{IsolatedHome, output_text};

#[test]
fn paths_reports_locations() {
    let home = IsolatedHome::new();
    let home_config = home.config_dir();
    let project_config = home.project_path().join(".cockpit");
    std::fs::create_dir_all(&home_config).unwrap();
    std::fs::create_dir_all(&project_config).unwrap();

    let output = home.cockpit().args(["debug", "paths"]).output().unwrap();
    assert!(output.status.success(), "{}", output_text(&output));
    let text = output_text(&output);

    assert!(
        text.contains(&format!("database: {} (absent)", home.db_path().display())),
        "{text}"
    );
    assert!(
        text.contains(&format!(
            "daemon socket: {} (absent)",
            home.socket_path().display()
        )),
        "{text}"
    );
    assert!(
        text.contains(&format!("log: {} (present)", home.log_file().display())),
        "{text}"
    );

    let home_config_row = format!("{} (present)", home_config.display());
    let local_row = format!(
        "{}/local-configs/",
        home.db_path().parent().unwrap().display()
    );
    let project_config_row = format!("{} (present)", project_config.display());
    let home_config_at = text.find(&home_config_row).expect("home config candidate");
    let local_at = text
        .find(&local_row)
        .expect("machine-local config candidate");
    let project_config_at = text
        .find(&project_config_row)
        .expect("project config candidate");
    assert!(
        home_config_at < local_at && local_at < project_config_at,
        "config candidates must be least-to-most specific:
{text}"
    );
}

#[test]
fn paths_works_with_unopenable_db() {
    let mut home = IsolatedHome::new();
    home.set_env("XDG_DATA_HOME", "/dev/null");
    let db_user = home
        .cockpit()
        .args(["debug", "failed-calls"])
        .output()
        .unwrap();
    assert!(
        !db_user.status.success(),
        "the fixture must make Db::open fail: {}",
        output_text(&db_user)
    );

    let output = home.cockpit().args(["debug", "paths"]).output().unwrap();
    assert!(output.status.success(), "{}", output_text(&output));
}

#[test]
fn config_renders_effective_configuration() {
    let home = IsolatedHome::new();
    let config = home.config_dir();
    std::fs::create_dir_all(config.join("providers")).unwrap();
    std::fs::write(config.join("config.json"), "{}").unwrap();
    std::fs::write(
        config.join("providers/debug.json"),
        r#"{"url":"https://debug-provider.example/v1","headers":[{"name":"x-api-key","value":"debug-known-secret-12345"}]}"#,
    )
    .unwrap();

    let output = home.cockpit().args(["debug", "config"]).output().unwrap();
    assert!(output.status.success(), "{}", output_text(&output));
    let text = output_text(&output);
    assert!(text.contains("https://debug-provider.example/v1"), "{text}");
    assert!(text.contains("[redacted]"), "{text}");
    assert!(!text.contains("debug-known-secret-12345"), "{text}");
}

#[test]
fn config_redacts_secrets() {
    let home = IsolatedHome::new();
    let config = home.config_dir();
    std::fs::create_dir_all(config.join("providers")).unwrap();
    std::fs::write(config.join("config.json"), "{}").unwrap();
    std::fs::write(
        config.join("providers/local.json"),
        r#"{"url":"http://localhost","headers":[{"name":"x-custom-opaque","value":"debug-custom-header-secret-67890"},{"name":"x-custom-ref","value":"$secret:debug-known-secret-12345"}]}"#,
    )
    .unwrap();
    let output = home.cockpit().args(["debug", "config"]).output().unwrap();
    assert!(output.status.success(), "{}", output_text(&output));
    let text = output_text(&output);
    assert!(text.contains("[redacted]"), "{text}");
    assert!(!text.contains("debug-known-secret-12345"), "{text}");
    assert!(!text.contains("debug-custom-header-secret-67890"), "{text}");
}

#[test]
fn context_is_redacted_and_bounded() {
    let mut home = IsolatedHome::new();
    home.set_env("COCKPIT_DEBUG_SECRET", "debug-context-secret-12345");
    std::fs::write(
        home.project_path().join("AGENTS.md"),
        format!(
            "PROJECT_GUIDANCE_NONSECRET_MARKER
Use debug-context-secret-12345 only for this test.
{}",
            "large guidance content ".repeat(2_000)
        ),
    )
    .unwrap();
    let output = home.cockpit().args(["debug", "context"]).output().unwrap();
    assert!(output.status.success(), "{}", output_text(&output));
    let text = output_text(&output);
    assert!(text.contains("assembled context (fresh-session baseline)"));
    assert!(text.contains("System prompt:"));
    assert!(text.contains("Project guidance (user-role prelude):"));
    assert!(text.contains("AGENTS.md"));
    assert!(text.contains("PROJECT_GUIDANCE_NONSECRET_MARKER"));
    assert!(!text.contains("debug-context-secret-12345"));
    assert!(text.contains("[truncated at 16384 bytes]"), "{text}");
    assert!(text.len() <= 17 * 1024, "{}", text.len());
}

#[test]
fn removed_subcommands_are_absent() {
    let home = IsolatedHome::new();
    for command in [
        ["pr"].as_slice(),
        ["meta"].as_slice(),
        ["debug", "scrap"].as_slice(),
        ["debug", "skill"].as_slice(),
        ["debug", "agent", "name"].as_slice(),
        ["debug", "file"].as_slice(),
        ["debug", "redact"].as_slice(),
        ["debug", "wait"].as_slice(),
    ] {
        let output = home.cockpit().args(command).output().unwrap();
        assert_eq!(
            output.status.code(),
            Some(2),
            "{}: {}",
            command.join(" "),
            output_text(&output)
        );
        assert!(
            output_text(&output).contains("unrecognized subcommand"),
            "{}",
            output_text(&output)
        );
    }
}
