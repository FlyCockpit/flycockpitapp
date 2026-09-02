use super::*;
use std::path::Path;
use tempfile::TempDir;

fn enabled_cfg() -> RedactConfig {
    RedactConfig {
        enabled: true,
        scan_environment: false,
        scan_dotenv: false,
        scan_ssh_keys: false,
        ssh_key_dir: None,
        dotenv_patterns: crate::config::extended::default_dotenv_patterns(),
        extra_dotenv_paths: vec![],
        secret_path_patterns: vec![],
        min_secret_length: 8,
        placeholder: "***REDACT***".into(),
        denylist: vec![],
        allowlist: vec![],
    }
}

fn protected_cfg() -> RedactConfig {
    let mut cfg = enabled_cfg();
    cfg.scan_environment = true;
    cfg.min_secret_length = 1;
    cfg
}

fn path_string(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn build_with_session_env(
    cfg: &RedactConfig,
    cwd: &Path,
    env: &HashMap<String, String>,
) -> RedactionTable {
    RedactionTable::build_with_env_and_secrets(cfg, cwd, env, Vec::<(String, String)>::new())
        .unwrap()
}

fn protected_paths(cwd: &Path, env: &HashMap<String, String>) -> Vec<String> {
    protected::ProtectedPaths::from_session(cwd, env).to_persisted()
}

fn entry_origins(table: &RedactionTable) -> Vec<String> {
    table.entries_for_debug()
}

fn assert_origin_absent(table: &RedactionTable, origin: &str) {
    assert!(
        !entry_origins(table).iter().any(|o| o == origin),
        "expected protected origin `{origin}` to be absent"
    );
}

#[test]
fn mcp_oauth_json_registers_each_token_leaf() {
    let cfg = enabled_cfg();
    let dir = TempDir::new().unwrap();
    let access = "mcp-access-token-value-123";
    let refresh = "mcp-refresh-token-value-456";
    let metadata = "issuer-metadata-value-789";
    let raw = serde_json::json!({
        "access_token": access,
        "refresh_token": refresh,
        "expires_at": metadata,
    })
    .to_string();
    let table = RedactionTable::build_with_env_and_secrets(
        &cfg,
        dir.path(),
        &HashMap::new(),
        [("mcp:example".to_string(), raw)],
    )
    .unwrap();

    let scrubbed = table.scrub(&format!("{access} {refresh} {metadata}"));
    assert!(!scrubbed.contains(access));
    assert!(!scrubbed.contains(refresh));
    assert!(
        scrubbed.contains(metadata),
        "non-sensitive metadata is not a token leaf"
    );
}

#[test]
fn disabled_passes_through() {
    let mut cfg = enabled_cfg();
    cfg.enabled = false;
    let dir = TempDir::new().unwrap();
    let t = RedactionTable::build(&cfg, dir.path()).unwrap();
    assert!(t.disabled());
    assert_eq!(t.scrub("sk-secret-token"), "sk-secret-token");
}

#[test]
fn empty_passes_through() {
    let cfg = enabled_cfg();
    let dir = TempDir::new().unwrap();
    let t = RedactionTable::build(&cfg, dir.path()).unwrap();
    assert!(t.is_empty());
    assert_eq!(t.scrub("anything goes"), "anything goes");
}

#[test]
fn dotenv_values_redacted() {
    let dir = TempDir::new().unwrap();
    let env_path = dir.path().join(".env");
    std::fs::write(
            &env_path,
            "API_KEY=sk-super-secret-token-1234\nUSER_VAR=ignored-short\n# comment\nQUOTED=\"another-long-secret-here\"\n",
        )
        .unwrap();
    let mut cfg = enabled_cfg();
    cfg.scan_dotenv = true;
    let t = RedactionTable::build(&cfg, dir.path()).unwrap();
    let body = "got sk-super-secret-token-1234 and another-long-secret-here";
    let scrubbed = t.scrub(body);
    assert!(!scrubbed.contains("sk-super-secret-token-1234"));
    assert!(!scrubbed.contains("another-long-secret-here"));
    assert!(scrubbed.contains("***REDACT***"));
}

#[test]
fn dotenv_stray_line_does_not_void_file() {
    let dir = TempDir::new().unwrap();
    let env_path = dir.path().join(".env");
    std::fs::write(
        &env_path,
        "export DEBUG\nAPI_KEY=sk-super-secret-token-1234\n",
    )
    .unwrap();
    let mut cfg = enabled_cfg();
    cfg.scan_dotenv = true;
    let t = RedactionTable::build(&cfg, dir.path()).unwrap();

    assert_eq!(t.scrub("sk-super-secret-token-1234"), "***REDACT***");
    assert!(t.unsupported_files().is_empty());
    assert!(!t.is_empty());
}

#[test]
fn dotenv_no_equals_line_skipped_others_kept() {
    let dir = TempDir::new().unwrap();
    let env_path = dir.path().join(".env");
    std::fs::write(
        &env_path,
        "source ./other.env\nDB_PASSWORD=a-long-secret-value-1234\n",
    )
    .unwrap();
    let mut cfg = enabled_cfg();
    cfg.scan_dotenv = true;
    let t = RedactionTable::build(&cfg, dir.path()).unwrap();

    assert_eq!(t.scrub("a-long-secret-value-1234"), "***REDACT***");
    assert!(t.unsupported_files().is_empty());
}

#[test]
fn dotenv_invalid_key_line_skipped() {
    let dir = TempDir::new().unwrap();
    let env_path = dir.path().join(".env");
    std::fs::write(
        &env_path,
        "FOO-BAR=ignored-long-secret-value\nGOOD_KEY=another-long-secret-value\n",
    )
    .unwrap();
    let mut cfg = enabled_cfg();
    cfg.scan_dotenv = true;
    let t = RedactionTable::build(&cfg, dir.path()).unwrap();

    assert_eq!(t.scrub("another-long-secret-value"), "***REDACT***");
    assert_eq!(
        t.scrub("ignored-long-secret-value"),
        "ignored-long-secret-value"
    );
    assert!(t.unsupported_files().is_empty());
}

#[test]
fn dotenv_only_stray_lines_falls_through_to_unsupported() {
    let dir = TempDir::new().unwrap();
    let env_path = dir.path().join(".env");
    std::fs::write(&env_path, "\u{0}\u{1}: [unterminated\n\tno close").unwrap();
    let mut cfg = enabled_cfg();
    cfg.scan_dotenv = true;
    let t = RedactionTable::build(&cfg, dir.path()).unwrap();

    assert_eq!(t.unsupported_files().len(), 1);
    assert!(t.is_empty());
}

#[test]
fn dotenv_allowlisted_assignment_still_detects_dotenv() {
    let entries = parse_dotenv("PATH=/secret/bin\n", "test.env", &[]);
    assert!(matches!(entries, Some(entries) if entries.is_empty()));
}

/// `scrub` is deterministic and byte-stable within a session: the same
/// input scrubbed twice yields identical bytes. This is load-bearing for
/// prompt caching (prompt `prompt-caching-strategy.md`) — a non-stable
/// prefix would bust the provider cache every turn. `aho-corasick`
/// `LeftmostLongest` `replace_all` with a fixed placeholder is
/// deterministic, and this guards against a regression.
#[test]
fn scrub_is_deterministic_within_a_session() {
    let dir = TempDir::new().unwrap();
    let env_path = dir.path().join(".env");
    std::fs::write(
        &env_path,
        "API_KEY=sk-super-secret-token-1234\nOTHER=another-long-secret-here\n",
    )
    .unwrap();
    let mut cfg = enabled_cfg();
    cfg.scan_dotenv = true;
    let t = RedactionTable::build(&cfg, dir.path()).unwrap();

    let body = "prefix sk-super-secret-token-1234 middle another-long-secret-here suffix \
                    sk-super-secret-token-1234 end";
    let first = t.scrub(body);
    // Many repeated passes must all produce byte-identical output.
    for _ in 0..32 {
        assert_eq!(t.scrub(body), first, "scrub output varied across passes");
    }
    // And it actually redacted (not a trivial pass-through).
    assert!(!first.contains("sk-super-secret-token-1234"));
    assert!(first.contains("***REDACT***"));
}

#[test]
fn short_values_skipped() {
    let dir = TempDir::new().unwrap();
    let env_path = dir.path().join(".env");
    std::fs::write(&env_path, "SHORT=abc\nLONG=long-enough-value-here\n").unwrap();
    let mut cfg = enabled_cfg();
    cfg.scan_dotenv = true;
    cfg.min_secret_length = 8;
    let t = RedactionTable::build(&cfg, dir.path()).unwrap();
    // The 3-char value would have created a useless pattern; check
    // that benign substrings aren't replaced.
    assert_eq!(t.scrub("abc def"), "abc def");
    assert_eq!(t.scrub("long-enough-value-here"), "***REDACT***");
}

#[test]
fn short_credential_shaped_key_value_respects_hard_floor() {
    let dir = TempDir::new().unwrap();
    let env_path = dir.path().join(".env");
    std::fs::write(&env_path, "MY_PIN=abc\nSHORT=def\n").unwrap();
    let mut cfg = enabled_cfg();
    cfg.scan_dotenv = true;
    cfg.min_secret_length = 8;
    let t = RedactionTable::build(&cfg, dir.path()).unwrap();

    assert_eq!(t.scrub("pin abc"), "pin abc");
    assert_eq!(t.scrub("short def"), "short def");
}

#[cfg(feature = "remote")]
#[test]
fn stored_flycockpit_instance_token_is_forced_redaction_candidate() {
    let tmp = tempfile::TempDir::new().unwrap();
    crate::auth::flycockpit::with_redaction_token_override("fci_secret_token_12345", || {
        let cfg = RedactConfig {
            min_secret_length: 128,
            ..Default::default()
        };
        let table = RedactionTable::build(&cfg, tmp.path()).unwrap();
        let scrubbed = table.scrub("token=fci_secret_token_12345");
        assert!(!scrubbed.contains("fci_secret_token_12345"));
        assert!(scrubbed.contains("**REDACTED BY COCKPIT - DO NOT TRY TO OBTAIN BY WORKAROUND**"));
    });
}

#[cfg(unix)]
#[test]
fn non_unicode_env_values_are_lossy_scanned_without_panic() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    let key = "COCKPIT_TEST_NONUNICODE_SECRET";
    let value = OsString::from_vec(b"nonunicode-secret-\xFF-value-1234".to_vec());
    let lossy = value.to_string_lossy().into_owned();
    let env = crate::test_env::lock();
    env.set_var(key, &value);

    let mut cfg = enabled_cfg();
    cfg.scan_environment = true;
    let dir = TempDir::new().unwrap();
    let table = RedactionTable::build(&cfg, dir.path()).unwrap();
    let scrubbed = table.scrub(&format!("value={lossy}"));
    assert!(!scrubbed.contains(&lossy));
    assert!(scrubbed.contains(&cfg.placeholder));
}

#[test]
fn env_value_redacts_encoded_variants() {
    let mut cfg = enabled_cfg();
    cfg.scan_environment = true;
    let dir = TempDir::new().unwrap();
    let secret = "env/variant secret 001";
    let env = HashMap::from([("COCKPIT_TEST_VARIANT_TOKEN".to_string(), secret.to_string())]);
    let table = RedactionTable::build_with_env(&cfg, dir.path(), &env).unwrap();

    let mut body = format!("raw {secret}");
    for variant in encoded_secret_variants(secret) {
        body.push(' ');
        body.push_str(&variant);
    }
    let scrubbed = table.scrub(&body);
    assert!(!scrubbed.contains(secret));
    for variant in encoded_secret_variants(secret) {
        assert!(!scrubbed.contains(&variant));
    }
}

#[test]
fn dotenv_value_redacts_encoded_variants() {
    let dir = TempDir::new().unwrap();
    let secret = "dotenv/variant secret 001";
    std::fs::write(
        dir.path().join(".env"),
        format!(
            "TOKEN={secret}
"
        ),
    )
    .unwrap();
    let mut cfg = enabled_cfg();
    cfg.scan_dotenv = true;
    let table = RedactionTable::build(&cfg, dir.path()).unwrap();

    let mut body = format!("raw {secret}");
    for variant in encoded_secret_variants(secret) {
        body.push(' ');
        body.push_str(&variant);
    }
    let scrubbed = table.scrub(&body);
    assert!(!scrubbed.contains(secret));
    for variant in encoded_secret_variants(secret) {
        assert!(!scrubbed.contains(&variant));
    }
}

#[test]
fn credential_shaped_values_register_case_variants_only_for_that_key_shape() {
    let mut cfg = enabled_cfg();
    cfg.scan_environment = true;
    let dir = TempDir::new().unwrap();
    let sensitive = "CaseSecretValue123";
    let ordinary = "CaseOrdinaryValue123";
    let env = HashMap::from([
        ("MY_PASSWORD".to_string(), sensitive.to_string()),
        ("NORMAL_NAME".to_string(), ordinary.to_string()),
    ]);
    let table = RedactionTable::build_with_env(&cfg, dir.path(), &env).unwrap();

    assert_eq!(
        table.scrub(&sensitive.to_ascii_lowercase()),
        cfg.placeholder
    );
    assert_eq!(
        table.scrub(&sensitive.to_ascii_uppercase()),
        cfg.placeholder
    );
    assert_eq!(
        table.scrub(&ordinary.to_ascii_lowercase()),
        ordinary.to_ascii_lowercase()
    );
}

#[test]
fn non_adjacent_duplicate_values_are_deduplicated() {
    let dir = TempDir::new().unwrap();
    std::fs::write(
        dir.path().join(".env"),
        "FIRST=shared/secret/0001
MIDDLE=other/secret/0002
LAST=shared/secret/0001
",
    )
    .unwrap();
    let mut cfg = enabled_cfg();
    cfg.scan_dotenv = true;
    let table = RedactionTable::build(&cfg, dir.path()).unwrap();

    assert_eq!(table.entries_for_debug().len(), 10);
    assert_eq!(table.scrub("shared/secret/0001"), cfg.placeholder);
    assert_eq!(table.scrub("other/secret/0002"), cfg.placeholder);
}

#[test]
fn denylisted_value_redacts_encoded_variants() {
    let mut cfg = enabled_cfg();
    cfg.min_secret_length = 8;
    cfg.denylist = vec!["a/bc".into()];
    let dir = TempDir::new().unwrap();
    let t = RedactionTable::build(&cfg, dir.path()).unwrap();

    let scrubbed = t.scrub("raw a/bc base64 YS9iYw== hex 612f6263 url a%2Fbc");
    assert!(!scrubbed.contains("YS9iYw=="));
    assert!(!scrubbed.contains("612f6263"));
    assert!(!scrubbed.contains("a%2Fbc"));
    assert!(!scrubbed.contains(" raw a/bc "));
}

#[test]
fn substring_matches() {
    let dir = TempDir::new().unwrap();
    let env_path = dir.path().join(".env");
    std::fs::write(&env_path, "TOKEN=embedded-secret-abc\n").unwrap();
    let mut cfg = enabled_cfg();
    cfg.scan_dotenv = true;
    let t = RedactionTable::build(&cfg, dir.path()).unwrap();
    let scrubbed = t.scrub("the URL is https://api.example.com?t=embedded-secret-abc&u=x");
    assert!(scrubbed.contains("***REDACT***"));
    assert!(!scrubbed.contains("embedded-secret-abc"));
}

#[test]
fn protected_path_uses_session_env_home_not_process_env() {
    let dir = TempDir::new().unwrap();
    let cwd = dir.path().join("project");
    std::fs::create_dir_all(&cwd).unwrap();
    let home = path_string(&dir.path().join("session-home-does-not-exist"));
    let env = HashMap::from([
        ("HOME".to_string(), home.clone()),
        ("SESSION_HOME_COPY".to_string(), home.clone()),
    ]);
    let cfg = protected_cfg();

    let table = build_with_session_env(&cfg, &cwd, &env);

    assert_eq!(table.scrub(&home), home);
    assert_origin_absent(&table, "$SESSION_HOME_COPY");
}

#[test]
fn protected_path_ancestor_valued_env_var_is_not_registered() {
    let dir = TempDir::new().unwrap();
    let cwd = dir.path().join("workspace").join("project");
    std::fs::create_dir_all(&cwd).unwrap();
    let ancestor = path_string(dir.path());
    let env = HashMap::from([("ANCESTOR_SECRET".to_string(), ancestor.clone())]);
    let cfg = protected_cfg();

    let table = build_with_session_env(&cfg, &cwd, &env);

    assert_eq!(table.scrub(&ancestor), ancestor);
    assert_origin_absent(&table, "$ANCESTOR_SECRET");
}

#[test]
fn protected_path_existing_absolute_directory_value_is_not_registered() {
    let dir = TempDir::new().unwrap();
    let cwd = dir.path().join("project");
    let other = dir.path().join("other-existing-dir");
    std::fs::create_dir_all(&cwd).unwrap();
    std::fs::create_dir_all(&other).unwrap();
    let other = path_string(&other);
    let env = HashMap::from([("ABSOLUTE_DIR_SECRET".to_string(), other.clone())]);
    let cfg = protected_cfg();

    let table = build_with_session_env(&cfg, &cwd, &env);

    assert_eq!(table.scrub(&other), other);
    assert_origin_absent(&table, "$ABSOLUTE_DIR_SECRET");
}

#[test]
fn protected_path_nonexistent_absolute_value_is_still_registered() {
    let dir = TempDir::new().unwrap();
    let cwd = dir.path().join("project");
    std::fs::create_dir_all(&cwd).unwrap();
    let value = path_string(&dir.path().join("missing-absolute-secret"));
    let env = HashMap::from([("ABSOLUTE_TOKEN".to_string(), value.clone())]);
    let cfg = protected_cfg();

    let table = build_with_session_env(&cfg, &cwd, &env);

    assert_ne!(table.scrub(&value), value);
    assert!(entry_origins(&table).iter().any(|o| o == "$ABSOLUTE_TOKEN"));
}

#[test]
fn protected_path_relative_existing_filename_is_still_registered() {
    let dir = TempDir::new().unwrap();
    let cwd = dir.path().join("project");
    std::fs::create_dir_all(&cwd).unwrap();
    let value = "relative-existing-secret-file";
    std::fs::write(cwd.join(value), "not relevant").unwrap();
    let env = HashMap::from([("RELATIVE_TOKEN".to_string(), value.to_string())]);
    let cfg = protected_cfg();

    let table = build_with_session_env(&cfg, &cwd, &env);

    assert_ne!(table.scrub(value), value);
    assert!(entry_origins(&table).iter().any(|o| o == "$RELATIVE_TOKEN"));
}

#[test]
fn protected_path_scrub_is_identity_for_every_protected_path() {
    let dir = TempDir::new().unwrap();
    let cwd = dir.path().join("workspace").join("project");
    std::fs::create_dir_all(&cwd).unwrap();
    let home = dir.path().join("session-home");
    let tmp = dir.path().join("session-tmp");
    let mut env = HashMap::from([
        ("HOME".to_string(), path_string(&home)),
        ("TMPDIR".to_string(), path_string(&tmp)),
    ]);
    let paths = protected_paths(&cwd, &env);
    for (idx, path) in paths.iter().enumerate() {
        env.insert(format!("PROTECTED_PATH_{idx}_SECRET"), path.clone());
    }
    let cfg = protected_cfg();

    let table = build_with_session_env(&cfg, &cwd, &env);

    for path in paths {
        assert_eq!(table.scrub(&path), path);
    }
}

#[test]
fn protected_path_invariant_survives_union() {
    let first_dir = TempDir::new().unwrap();
    let second_dir = TempDir::new().unwrap();
    let first_cwd = first_dir.path().join("project");
    let second_cwd = second_dir.path().join("project");
    std::fs::create_dir_all(&first_cwd).unwrap();
    std::fs::create_dir_all(&second_cwd).unwrap();
    let first_home = path_string(&first_dir.path().join("session-home"));
    let second_home = path_string(&second_dir.path().join("session-home"));
    let first_env = HashMap::from([
        ("HOME".to_string(), first_home.clone()),
        ("FIRST_HOME_COPY".to_string(), first_home.clone()),
    ]);
    let second_env = HashMap::from([
        ("HOME".to_string(), second_home.clone()),
        ("SECOND_HOME_COPY".to_string(), second_home.clone()),
    ]);
    let cfg = protected_cfg();

    let first = build_with_session_env(&cfg, &first_cwd, &first_env);
    let second = build_with_session_env(&cfg, &second_cwd, &second_env);
    let unioned = first.union(&second).unwrap();

    assert_eq!(unioned.scrub(&first_home), first_home);
    assert_eq!(unioned.scrub(&second_home), second_home);
    assert_origin_absent(&unioned, "$FIRST_HOME_COPY");
    assert_origin_absent(&unioned, "$SECOND_HOME_COPY");
}

#[test]
fn protected_path_invariant_survives_persist_roundtrip() {
    let dir = TempDir::new().unwrap();
    let cwd = dir.path().join("project");
    std::fs::create_dir_all(&cwd).unwrap();
    let home = path_string(&dir.path().join("session-home"));
    let env = HashMap::from([
        ("HOME".to_string(), home.clone()),
        ("SESSION_HOME_COPY".to_string(), home.clone()),
    ]);
    let cfg = protected_cfg();
    let table = build_with_session_env(&cfg, &cwd, &env);
    let json = table.to_persisted_json().unwrap();
    let mut snapshot: serde_json::Value = serde_json::from_str(&json).unwrap();
    snapshot["entries"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!({"value": home.clone(), "class": "ordinary", "origin": "$SESSION_HOME_COPY"}));

    let restored = RedactionTable::from_persisted_json(&snapshot.to_string()).unwrap();

    assert_eq!(restored.scrub(&home), home);
    assert_origin_absent(&restored, "$SESSION_HOME_COPY");
}

#[test]
fn protected_path_legacy_poisoned_persisted_table_self_heals_on_union() {
    let dir = TempDir::new().unwrap();
    let cwd = dir.path().join("project");
    std::fs::create_dir_all(&cwd).unwrap();
    let home = path_string(&dir.path().join("session-home"));
    let legacy = serde_json::json!({
        "entries": [{"value": home.clone(), "class": "ordinary", "origin": "$SESSION_HOME_COPY"}],
        "placeholder": "***REDACT***",
        "disabled": false,
        "unsupported_files": []
    });
    let restored = RedactionTable::from_persisted_json(&legacy.to_string()).unwrap();
    let env = HashMap::from([
        ("HOME".to_string(), home.clone()),
        ("SESSION_HOME_COPY".to_string(), home.clone()),
    ]);
    let cfg = protected_cfg();
    let fresh = build_with_session_env(&cfg, &cwd, &env);

    assert_ne!(restored.scrub(&home), home);
    let unioned = restored.union(&fresh).unwrap();
    assert_eq!(unioned.scrub(&home), home);
    assert_origin_absent(&unioned, "$SESSION_HOME_COPY");
}

#[test]
fn protected_path_denylist_entry_still_wins_over_protected_path() {
    let dir = TempDir::new().unwrap();
    let cwd = dir.path().join("project");
    std::fs::create_dir_all(&cwd).unwrap();
    let home = path_string(&dir.path().join("session-home"));
    let env = HashMap::from([("HOME".to_string(), home.clone())]);
    let mut cfg = protected_cfg();
    cfg.denylist = vec![home.clone()];

    let table = build_with_session_env(&cfg, &cwd, &env);

    assert_ne!(table.scrub(&home), home);
    assert_eq!(table.protected_path_conflicts(), &["$denylist".to_string()]);
}

#[test]
fn protected_path_named_secret_equal_to_path_still_wins() {
    let dir = TempDir::new().unwrap();
    let cwd = dir.path().join("project");
    std::fs::create_dir_all(&cwd).unwrap();
    let home = path_string(&dir.path().join("session-home"));
    let env = HashMap::from([("HOME".to_string(), home.clone())]);
    let cfg = protected_cfg();

    let table = RedactionTable::build_with_env_and_secrets(
        &cfg,
        &cwd,
        &env,
        [("session-home".to_string(), home.clone())],
    )
    .unwrap();

    assert_ne!(table.scrub(&home), home);
    assert_eq!(
        table.protected_path_conflicts(),
        &["$secret:session-home".to_string()]
    );
}

#[test]
fn protected_path_conflict_records_origin_never_value() {
    let dir = TempDir::new().unwrap();
    let cwd = dir.path().join("project");
    std::fs::create_dir_all(&cwd).unwrap();
    let home = path_string(&dir.path().join("session-home"));
    let env = HashMap::from([("HOME".to_string(), home.clone())]);
    let mut cfg = protected_cfg();
    cfg.denylist = vec![home.clone()];

    let table = build_with_session_env(&cfg, &cwd, &env);
    let conflicts = table.protected_path_conflicts();

    assert_eq!(conflicts, &["$denylist".to_string()]);
    assert!(!format!("{conflicts:?}").contains(&home));
    assert!(!format!("{table:?}").contains(&home));
}

#[test]
fn protected_path_rejected_entries_absent_from_debug_and_persisted_json() {
    let dir = TempDir::new().unwrap();
    let cwd = dir.path().join("project");
    std::fs::create_dir_all(&cwd).unwrap();
    let home = path_string(&dir.path().join("session-home"));
    let env = HashMap::from([
        ("HOME".to_string(), home.clone()),
        ("SESSION_HOME_COPY".to_string(), home),
    ]);
    let cfg = protected_cfg();

    let table = build_with_session_env(&cfg, &cwd, &env);
    let snapshot: serde_json::Value =
        serde_json::from_str(&table.to_persisted_json().unwrap()).unwrap();
    let entries = snapshot["entries"].as_array().unwrap();

    assert_origin_absent(&table, "$SESSION_HOME_COPY");
    assert!(
        entries
            .iter()
            .all(|entry| !entry.to_string().contains("$SESSION_HOME_COPY")),
        "rejected protected-path entry persisted: {entries:?}"
    );
}

#[test]
fn default_placeholder_is_the_explicit_string() {
    // The user-visible placeholder is part of the spec; if anyone
    // edits the default, this test fails on purpose.
    let cfg = RedactConfig::default();
    assert_eq!(
        cfg.placeholder,
        "**REDACTED BY COCKPIT - DO NOT TRY TO OBTAIN BY WORKAROUND**"
    );
}

#[test]
fn env_var_value_redacted_with_default_placeholder() {
    // Set a dedicated env var and confirm it lands in the table and
    // gets scrubbed to the default placeholder. Use a value name
    // unique enough that prior env state can't fight us.
    let key = "COCKPIT_TEST_SECRET_TOKEN_XYZ";
    let val = "supersecret-token-value-1234";
    let env = crate::test_env::lock();
    env.set_var(key, val);
    let cfg = RedactConfig {
        enabled: true,
        scan_environment: true,
        scan_dotenv: false,
        scan_ssh_keys: false,
        ssh_key_dir: None,
        dotenv_patterns: crate::config::extended::default_dotenv_patterns(),
        extra_dotenv_paths: vec![],
        secret_path_patterns: vec![],
        min_secret_length: 8,
        placeholder: RedactConfig::default().placeholder,
        denylist: vec![],
        allowlist: vec![],
    };
    let dir = TempDir::new().unwrap();
    let t = RedactionTable::build(&cfg, dir.path()).unwrap();
    let scrubbed = t.scrub(&format!("the token is {val} ok"));
    assert!(scrubbed.contains("**REDACTED BY COCKPIT - DO NOT TRY TO OBTAIN BY WORKAROUND**"));
    assert!(!scrubbed.contains(val));
}

#[test]
fn build_with_env_redacts_env_only_secret_without_process_env() {
    let key = "COCKPIT_TEST_SESSION_ONLY_SECRET";
    let val = "session-only-secret-value-1234";
    let env = crate::test_env::lock();
    env.remove_var(key);
    let mut cfg = enabled_cfg();
    cfg.scan_environment = true;
    cfg.scan_dotenv = false;
    cfg.scan_ssh_keys = false;
    cfg.min_secret_length = 8;
    let dir = TempDir::new().unwrap();
    let env = HashMap::from([(key.to_string(), val.to_string())]);
    let table = RedactionTable::build_with_env(&cfg, dir.path(), &env).unwrap();
    let scrubbed = table.scrub(&format!("secret={val}"));
    assert!(!scrubbed.contains(val));
    assert!(scrubbed.contains(&cfg.placeholder));
}

#[test]
fn store_secrets_join_redaction_table() {
    use crate::config::providers::{ModelEntry, ModelTrust, ProviderEntry, ProvidersConfig};
    use crate::engine::model::Model;
    use std::sync::Arc;

    let cfg = enabled_cfg();
    let dir = TempDir::new().unwrap();
    let secret = "sk-stored-secret-value-123456";
    let table = Arc::new(
        RedactionTable::build_with_env_and_secrets(
            &cfg,
            dir.path(),
            &HashMap::new(),
            [("openai".to_string(), secret.to_string())],
        )
        .unwrap(),
    );
    assert!(!table.scrub(secret).contains(secret));

    let mut providers = ProvidersConfig::default();
    providers.providers.insert(
        "untrusted".into(),
        ProviderEntry {
            models: vec![ModelEntry {
                id: "model".into(),
                trust: Some(ModelTrust::Untrusted),
                ..Default::default()
            }],
            ..Default::default()
        },
    );
    providers.providers.insert(
        "trusted".into(),
        ProviderEntry {
            models: vec![ModelEntry {
                id: "model".into(),
                trust: Some(ModelTrust::Trusted),
                ..Default::default()
            }],
            ..Default::default()
        },
    );

    let untrusted = Model::effective_redact_table_for_configured(
        &providers,
        "untrusted",
        "model",
        table.clone(),
    );
    let trusted =
        Model::effective_redact_table_for_configured(&providers, "trusted", "model", table);
    assert!(!untrusted.scrub(secret).contains(secret));
    assert!(!trusted.scrub(secret).contains(secret));
}

#[test]
fn short_env_values_not_redacted() {
    let key = "COCKPIT_TEST_SHORT_VALUE";
    let val = "abc";
    let env = crate::test_env::lock();
    env.set_var(key, val);
    let mut cfg = enabled_cfg();
    cfg.scan_environment = true;
    cfg.min_secret_length = 8;
    let dir = TempDir::new().unwrap();
    let t = RedactionTable::build(&cfg, dir.path()).unwrap();
    // The 3-char value must not contribute a pattern.
    assert_eq!(t.scrub("the value is abc here"), "the value is abc here");
}

#[test]
fn allowlisted_path_not_redacted_even_when_long() {
    // PATH is almost always long enough to clear min_secret_length;
    // confirm $PATH (and the LC_/LANG/XDG_ families) are never in
    // the table even with min_secret_length lowered all the way.
    // Filesystem paths are additionally protected by value before the
    // matcher is built; this test only verifies name allowlisting.
    let mut cfg = enabled_cfg();
    cfg.scan_environment = true;
    cfg.min_secret_length = 1;
    let dir = TempDir::new().unwrap();
    let t = RedactionTable::build(&cfg, dir.path()).unwrap();
    let origins = t.entries_for_debug();
    for skipped in ["$PATH", "$HOME", "$LANG", "$LC_ALL", "$XDG_RUNTIME_DIR"] {
        assert!(
            !origins.iter().any(|o| o == skipped),
            "expected allowlisted origin `{skipped}` to be absent"
        );
    }
    for name in ["LC_ALL", "LANG", "XDG_RUNTIME_DIR"] {
        assert!(
            is_allowlisted(name, &[]),
            "expected `{name}` to be allowlisted by prefix"
        );
    }
}

#[test]
fn denylist_bypasses_configured_floor_but_not_hard_floor() {
    let mut cfg = enabled_cfg();
    cfg.scan_environment = false;
    cfg.scan_dotenv = false;
    cfg.min_secret_length = 16; // huge threshold so length can't help
    cfg.denylist = vec!["sekr".into()];
    let dir = TempDir::new().unwrap();
    let t = RedactionTable::build(&cfg, dir.path()).unwrap();
    assert_eq!(
        t.scrub("the keyword sekr appears here"),
        format!("the keyword {} appears here", cfg.placeholder)
    );
}

#[test]
fn hard_floor_rejects_short_entries_from_every_table_ingress() {
    let dir = TempDir::new().unwrap();
    let mut cfg = enabled_cfg();
    cfg.min_secret_length = 1;
    cfg.denylist = vec!["0".into()];
    let from_build = build_with_session_env(
        &cfg,
        dir.path(),
        &HashMap::from([("API_SECRET".into(), "1".into())]),
    );
    assert!(from_build.is_empty());

    let from_forced = from_build
        .with_forced_literal("2".into(), "sealed:test".into())
        .unwrap();
    assert!(from_forced.is_empty());

    let restored = RedactionTable::from_persisted_json(
        r#"{"entries":[{"value":"3","class":"ordinary","origin":"legacy"}],"placeholder":"***REDACT***","disabled":false,"unsupported_files":[],"protected":[]}"#,
    )
    .unwrap();
    assert!(restored.is_empty());

    let table = from_forced.union(&restored).unwrap();

    assert!(
        table
            .entries
            .iter()
            .all(|entry| entry.value.len() >= MIN_REDACTION_ENTRY_LENGTH)
    );
    assert_eq!(
        table.scrub("tool `x` did not return within 120s and was abandoned"),
        "tool `x` did not return within 120s and was abandoned"
    );
}

#[test]
fn denylist_overrides_allowlisted_env_var() {
    // Even if the user added FOO to the allowlist, putting its
    // literal value on the denylist forces redaction.
    let mut cfg = enabled_cfg();
    cfg.scan_environment = false;
    cfg.scan_dotenv = false;
    cfg.denylist = vec!["my-allowlisted-value".into()];
    cfg.allowlist = vec!["FOO".into()];
    let dir = TempDir::new().unwrap();
    let t = RedactionTable::build(&cfg, dir.path()).unwrap();
    let scrubbed = t.scrub("got my-allowlisted-value back");
    assert!(scrubbed.contains("***REDACT***"));
    assert!(!scrubbed.contains("my-allowlisted-value"));
}

#[test]
fn user_allowlist_skips_dotenv_entry() {
    let dir = TempDir::new().unwrap();
    let env_path = dir.path().join(".env");
    std::fs::write(&env_path, "USER_TOKEN=very-long-allowed-value\n").unwrap();
    let mut cfg = enabled_cfg();
    cfg.scan_dotenv = true;
    cfg.allowlist = vec!["USER_TOKEN".into()];
    let t = RedactionTable::build(&cfg, dir.path()).unwrap();
    assert_eq!(
        t.scrub("got very-long-allowed-value"),
        "got very-long-allowed-value"
    );
}

#[test]
fn allowlisted_env_var_names_not_in_table() {
    // The allowlist works by *name*: even with scan_environment
    // on, `$PATH`/`$HOME`/`$SHELL` etc. must not contribute
    // patterns to the matcher. Filesystem-path values are rejected
    // separately by the protected-path guard.
    let cfg = RedactConfig {
        enabled: true,
        scan_environment: true,
        scan_dotenv: false,
        scan_ssh_keys: false,
        ssh_key_dir: None,
        dotenv_patterns: crate::config::extended::default_dotenv_patterns(),
        extra_dotenv_paths: vec![],
        secret_path_patterns: vec![],
        min_secret_length: 1,
        placeholder: "***".into(),
        denylist: vec![],
        allowlist: vec![],
    };
    let dir = TempDir::new().unwrap();
    let t = RedactionTable::build(&cfg, dir.path()).unwrap();
    let origins = t.entries_for_debug();
    for name in ENV_ALLOWLIST {
        let key = format!("${name}");
        assert!(
            !origins.iter().any(|origin| origin == &key),
            "allowlisted env var {name} leaked into the redaction table"
        );
    }
}

// ── Prune list (§6.3) ───────────────────────────────────────────────

#[test]
fn prune_drops_literals_and_short_values_keeps_long_numeric_secrets() {
    for lit in NEVER_SCRUB_LITERALS {
        assert!(is_pruned(lit, 8), "`{lit}` literal must be pruned");
        assert!(
            is_pruned(&lit.to_uppercase(), 8),
            "`{lit}` literal must be pruned case-insensitively"
        );
    }
    // Short ints / floats stay below the default floor and are pruned.
    assert!(is_pruned("42", 8));
    assert!(is_pruned("5432", 8));
    assert!(is_pruned("3.14", 8));
    // Long numeric values that clear the floor can be credentials.
    assert!(!is_pruned("100000000", 8));
    assert!(!is_pruned("12345678901234567890", 8));
    assert!(!is_pruned("1.234567e89", 8));
    // Too short.
    assert!(is_pruned("short", 8));
    // A plausible secret survives.
    assert!(!is_pruned("sk-long-enough-secret", 8));
}

#[test]
fn never_scrub_literals_not_in_table() {
    let dir = TempDir::new().unwrap();
    let env_path = dir.path().join(".env");
    std::fs::write(
        &env_path,
        "DEBUG=true\nFEATURE=off\nCOUNT=4200000\nRATIO=3.14\nSECRET=a-real-long-secret-here\n",
    )
    .unwrap();
    let mut cfg = enabled_cfg();
    cfg.scan_dotenv = true;
    cfg.min_secret_length = 8;
    let t = RedactionTable::build(&cfg, dir.path()).unwrap();
    // The literal and short numeric values pass through unscrubbed.
    assert_eq!(t.scrub("true off 4200000 3.14"), "true off 4200000 3.14");
    // The real secret is scrubbed.
    assert_eq!(t.scrub("a-real-long-secret-here"), "***REDACT***");
}

#[test]
fn long_numeric_dotenv_value_is_redacted() {
    let dir = TempDir::new().unwrap();
    let env_path = dir.path().join(".env");
    std::fs::write(&env_path, "NUMERIC_TOKEN=12345678901234567890\n").unwrap();
    let mut cfg = enabled_cfg();
    cfg.scan_dotenv = true;
    let t = RedactionTable::build(&cfg, dir.path()).unwrap();

    assert_eq!(t.scrub("token=12345678901234567890"), "token=***REDACT***");
}

#[test]
fn long_numeric_env_value_is_redacted() {
    let dir = TempDir::new().unwrap();
    let cfg = RedactConfig {
        enabled: true,
        scan_environment: true,
        scan_dotenv: false,
        scan_ssh_keys: false,
        ssh_key_dir: None,
        dotenv_patterns: crate::config::extended::default_dotenv_patterns(),
        extra_dotenv_paths: vec![],
        secret_path_patterns: vec![],
        min_secret_length: 8,
        placeholder: "***REDACT***".into(),
        denylist: vec![],
        allowlist: vec![],
    };
    let key = "COCKPIT_TEST_NUMERIC_SECRET";
    let val = "98765432109876543210";
    let env = crate::test_env::lock();
    env.set_var(key, val);
    let t = RedactionTable::build(&cfg, dir.path()).unwrap();

    assert_eq!(t.scrub(&format!("token={val}")), "token=***REDACT***");
}

// ── Format auto-detection (§4) ───────────────────────────────────────

#[test]
fn json_leaf_strings_redacted_keys_never() {
    let dir = TempDir::new().unwrap();
    let p = dir.path().join("config.env");
    std::fs::write(
            &p,
            r#"{"database":{"password":"json-secret-password","port":5432},"flags":["enabled-feature-x"]}"#,
        )
        .unwrap();
    let mut cfg = enabled_cfg();
    cfg.scan_dotenv = true;
    // Match the `.env`-suffixed file by an explicit glob.
    cfg.dotenv_patterns = vec!["config.env".into()];
    let t = RedactionTable::build(&cfg, dir.path()).unwrap();
    assert_eq!(t.scrub("json-secret-password"), "***REDACT***");
    // Non-secret-keyed array leaves are not candidates.
    assert_eq!(t.scrub("enabled-feature-x"), "enabled-feature-x");
    // The key `password` is never scrubbed; the int `5432` is pruned.
    assert_eq!(t.scrub("password 5432"), "password 5432");
}

#[test]
fn structured_toml_plain_values_are_not_registered() {
    let dir = TempDir::new().unwrap();
    let p = dir.path().join(".env");
    std::fs::write(
        &p,
        "\"display-name\" = \"Christopher\"\n\"aws-region\" = \"us-east-1\"\n",
    )
    .unwrap();
    let mut cfg = enabled_cfg();
    cfg.scan_dotenv = true;

    let table = RedactionTable::build(&cfg, dir.path()).unwrap();

    assert_eq!(table.scrub("Christopher"), "Christopher");
    assert_eq!(table.scrub("us-east-1"), "us-east-1");
    assert!(table.is_empty());
}

#[test]
fn structured_json_registers_only_secret_keyed_values() {
    let dir = TempDir::new().unwrap();
    let p = dir.path().join("config.env");
    std::fs::write(
        &p,
        r#"{"password":"hunter2","name":"Christopher","url":"https://example.test/service"}"#,
    )
    .unwrap();
    let mut cfg = enabled_cfg();
    cfg.scan_dotenv = true;
    cfg.dotenv_patterns = vec!["config.env".into()];
    cfg.min_secret_length = 1;

    let table = RedactionTable::build(&cfg, dir.path()).unwrap();

    assert_eq!(table.scrub("hunter2"), cfg.placeholder);
    assert_eq!(table.scrub("Christopher"), "Christopher");
    assert_eq!(
        table.scrub("https://example.test/service"),
        "https://example.test/service"
    );
}

#[test]
fn structured_yaml_secret_subtree_is_registered() {
    let dir = TempDir::new().unwrap();
    let p = dir.path().join(".env");
    std::fs::write(
        &p,
        "credentials:\n  user: service-user\n  token: yaml-subtree-token\nmetadata:\n  region: us-east-1\n",
    )
    .unwrap();
    let mut cfg = enabled_cfg();
    cfg.scan_dotenv = true;

    let table = RedactionTable::build(&cfg, dir.path()).unwrap();

    assert_eq!(table.scrub("service-user"), cfg.placeholder);
    assert_eq!(table.scrub("yaml-subtree-token"), cfg.placeholder);
    assert_eq!(table.scrub("us-east-1"), "us-east-1");
}

#[test]
fn structured_array_registration_follows_enclosing_key() {
    let dir = TempDir::new().unwrap();
    let p = dir.path().join("config.env");
    std::fs::write(
        &p,
        r#"{"tokens":["array-token-one","array-token-two"],"regions":["us-east-1-long"]}"#,
    )
    .unwrap();
    let mut cfg = enabled_cfg();
    cfg.scan_dotenv = true;
    cfg.dotenv_patterns = vec!["config.env".into()];

    let table = RedactionTable::build(&cfg, dir.path()).unwrap();

    assert_eq!(table.scrub("array-token-one"), cfg.placeholder);
    assert_eq!(table.scrub("array-token-two"), cfg.placeholder);
    assert_eq!(table.scrub("us-east-1-long"), "us-east-1-long");
}

#[test]
fn structured_length_exemption_unchanged() {
    let dir = TempDir::new().unwrap();
    let p = dir.path().join("config.env");
    std::fs::write(
        &p,
        "\"user_pin\" = \"short-pin-value\"\n\"pin\" = \"bare-pin-value\"\n",
    )
    .unwrap();
    let mut cfg = enabled_cfg();
    cfg.scan_dotenv = true;
    cfg.dotenv_patterns = vec!["config.env".into()];
    cfg.min_secret_length = 32;

    let table = RedactionTable::build(&cfg, dir.path()).unwrap();

    assert_eq!(table.scrub("short-pin-value"), cfg.placeholder);
    assert_eq!(table.scrub("bare-pin-value"), "bare-pin-value");
}

#[test]
fn yaml_leaf_strings_redacted_keys_never() {
    let dir = TempDir::new().unwrap();
    let p = dir.path().join(".env");
    std::fs::write(
        &p,
        "database:\n  password: yaml-secret-password\n  port: 5432\nname: short\n",
    )
    .unwrap();
    let mut cfg = enabled_cfg();
    cfg.scan_dotenv = true;
    let t = RedactionTable::build(&cfg, dir.path()).unwrap();
    assert_eq!(t.scrub("yaml-secret-password"), "***REDACT***");
    // Key `password` never scrubbed.
    assert_eq!(t.scrub("password"), "password");
}

#[test]
fn toml_leaf_strings_redacted_keys_never() {
    let dir = TempDir::new().unwrap();
    let p = dir.path().join(".env");
    std::fs::write(
        &p,
        "[database]\npassword = \"toml-secret-password\"\nport = 5432\n",
    )
    .unwrap();
    let mut cfg = enabled_cfg();
    cfg.scan_dotenv = true;
    let t = RedactionTable::build(&cfg, dir.path()).unwrap();
    assert_eq!(t.scrub("toml-secret-password"), "***REDACT***");
    assert_eq!(t.scrub("password 5432"), "password 5432");
}

#[test]
fn unsupported_format_is_skipped_and_recorded() {
    let dir = TempDir::new().unwrap();
    let p = dir.path().join(".env");
    // Binary-ish / non-parseable content that is neither dotenv,
    // JSON, TOML, nor YAML.
    std::fs::write(&p, "\u{0}\u{1}: [unterminated\n\tno close").unwrap();
    let mut cfg = enabled_cfg();
    cfg.scan_dotenv = true;
    let t = RedactionTable::build(&cfg, dir.path()).unwrap();
    assert_eq!(t.unsupported_files().len(), 1);
    // Nothing scrubbed (no candidates).
    assert!(t.is_empty());
}

// ── Inline disable marker (§5) ───────────────────────────────────────

#[test]
fn dotenv_marker_excludes_long_value() {
    let dir = TempDir::new().unwrap();
    let p = dir.path().join(".env");
    std::fs::write(
            &p,
            "# enable debug\nDEBUG=true # COCKPIT_DISABLE_REDACT\nMARKED=a-long-secret-but-disabled # COCKPIT_DISABLE_REDACT\nKEPT=another-long-secret-here\n",
        )
        .unwrap();
    let mut cfg = enabled_cfg();
    cfg.scan_dotenv = true;
    let t = RedactionTable::build(&cfg, dir.path()).unwrap();
    // The long marked value is left intact.
    assert_eq!(
        t.scrub("a-long-secret-but-disabled"),
        "a-long-secret-but-disabled"
    );
    // The unmarked secret is still scrubbed.
    assert_eq!(t.scrub("another-long-secret-here"), "***REDACT***");
}

#[test]
fn dotenv_unterminated_quotes_are_scanned_conservatively() {
    let dir = TempDir::new().unwrap();
    let p = dir.path().join(".env");
    std::fs::write(
        &p,
        r#"TOKEN="unterminated-secret-value-001
OTHER='unterminated-secret-value-002
"#,
    )
    .unwrap();
    let mut cfg = enabled_cfg();
    cfg.scan_dotenv = true;
    let table = RedactionTable::build(&cfg, dir.path()).unwrap();

    assert_eq!(
        table.scrub("unterminated-secret-value-001"),
        cfg.placeholder
    );
    assert_eq!(
        table.scrub("unterminated-secret-value-002"),
        cfg.placeholder
    );
    assert!(table.unsupported_files().is_empty());
}

#[tokio::test]
async fn dotenv_hash_inside_quoted_value_is_not_a_comment() {
    let dir = TempDir::new().unwrap();
    let p = dir.path().join(".env");
    std::fs::write(&p, "TOKEN=\"value#with#hashes-long\"\n").unwrap();
    let mut cfg = enabled_cfg();
    cfg.scan_dotenv = true;
    let t = RedactionTable::build(&cfg, dir.path()).unwrap();
    assert_eq!(t.scrub("value#with#hashes-long"), "***REDACT***");
}

#[tokio::test]
async fn structured_disable_marker_is_scoped_to_one_duplicate_value_occurrence() {
    let dir = TempDir::new().unwrap();
    let p = dir.path().join(".env");
    std::fs::write(
        &p,
        r#""marked_secret" = "shared-structured-secret" # COCKPIT_DISABLE_REDACT
"kept_secret" = "shared-structured-secret"
"#,
    )
    .unwrap();
    let mut cfg = enabled_cfg();
    cfg.scan_dotenv = true;
    let table = RedactionTable::build(&cfg, dir.path()).unwrap();

    assert_eq!(table.scrub("shared-structured-secret"), cfg.placeholder);
}

#[tokio::test]
async fn toml_marker_excludes_long_value() {
    let dir = TempDir::new().unwrap();
    let p = dir.path().join(".env");
    std::fs::write(
        &p,
        "\"marked_secret\" = \"toml-marked-long-secret\" # COCKPIT_DISABLE_REDACT\n\"kept_secret\" = \"toml-kept-long-secret\"\n",
    )
    .unwrap();
    let mut cfg = enabled_cfg();
    cfg.scan_dotenv = true;
    let t = RedactionTable::build(&cfg, dir.path()).unwrap();
    assert_eq!(
        t.scrub("toml-marked-long-secret"),
        "toml-marked-long-secret"
    );
    assert_eq!(t.scrub("toml-kept-long-secret"), "***REDACT***");
}

#[tokio::test]
async fn yaml_marker_excludes_long_value() {
    let dir = TempDir::new().unwrap();
    let p = dir.path().join(".env");
    std::fs::write(
        &p,
        "marked_secret: yaml-marked-long-secret # COCKPIT_DISABLE_REDACT\nkept_secret: yaml-kept-long-secret\n",
    )
    .unwrap();
    let mut cfg = enabled_cfg();
    cfg.scan_dotenv = true;
    let t = RedactionTable::build(&cfg, dir.path()).unwrap();
    assert_eq!(
        t.scrub("yaml-marked-long-secret"),
        "yaml-marked-long-secret"
    );
    assert_eq!(t.scrub("yaml-kept-long-secret"), "***REDACT***");
}

#[tokio::test]
async fn json_has_no_comment_marker() {
    // JSON is exempt from the marker: a `# COCKPIT_DISABLE_REDACT`
    // would make the doc invalid JSON, so it parses as JSON only
    // without one and secret-keyed leaf strings stay candidates.
    let dir = TempDir::new().unwrap();
    let p = dir.path().join("c.env");
    std::fs::write(&p, r#"{"token":"json-no-marker-secret"}"#).unwrap();
    let mut cfg = enabled_cfg();
    cfg.scan_dotenv = true;
    cfg.dotenv_patterns = vec!["c.env".into()];
    let t = RedactionTable::build(&cfg, dir.path()).unwrap();
    assert_eq!(t.scrub("json-no-marker-secret"), "***REDACT***");
}

// ── gitignore-pattern matching, cwd-downward (§3) ────────────────────

#[tokio::test]
async fn patterns_match_cwd_downward_across_subdirs() {
    let dir = TempDir::new().unwrap();
    let root = dir.path();
    std::fs::create_dir_all(root.join("a/b")).unwrap();
    std::fs::write(root.join(".env"), "ROOT=root-secret-value-long\n").unwrap();
    std::fs::write(root.join("a/.env.local"), "SUB=sub-local-secret-value\n").unwrap();
    std::fs::write(root.join("a/b/.env"), "DEEP=deep-secret-value-here\n").unwrap();
    // A non-matching file is ignored.
    std::fs::write(root.join("a/other.txt"), "OTHER=not-an-env-file-value\n").unwrap();

    let paths = matched_dotenv_paths(
        root,
        &crate::config::extended::default_dotenv_patterns(),
        &[],
    );
    assert!(paths.iter().any(|p| p.ends_with(".env")));
    assert!(paths.iter().any(|p| p.ends_with("a/.env.local")));
    assert!(paths.iter().any(|p| p.ends_with("a/b/.env")));
    assert!(!paths.iter().any(|p| p.ends_with("other.txt")));

    // End-to-end: every matched file's secret is scrubbed.
    let mut cfg = enabled_cfg();
    cfg.scan_dotenv = true;
    let t = RedactionTable::build(&cfg, root).unwrap();
    for secret in [
        "root-secret-value-long",
        "sub-local-secret-value",
        "deep-secret-value-here",
    ] {
        assert_eq!(
            t.scrub(secret),
            "***REDACT***",
            "expected `{secret}` scrubbed"
        );
    }
    assert_eq!(t.scrub("not-an-env-file-value"), "not-an-env-file-value");
}

#[test]
fn git_object_store_not_descended() {
    let dir = TempDir::new().unwrap();
    let root = dir.path();
    std::fs::create_dir_all(root.join(".git")).unwrap();
    std::fs::write(root.join(".git/.env"), "GIT=inside-git-secret-value\n").unwrap();
    std::fs::write(root.join(".env"), "TOP=top-level-secret-value\n").unwrap();
    let paths = matched_dotenv_paths(
        root,
        &crate::config::extended::default_dotenv_patterns(),
        &[],
    );
    assert!(paths.iter().any(|p| p.ends_with(".env")));
    assert!(
        !paths.iter().any(|p| p.to_string_lossy().contains(".git")),
        "must not descend into .git/"
    );
}

#[test]
fn extra_dotenv_paths_still_honored() {
    let dir = TempDir::new().unwrap();
    let root = dir.path();
    let extra = root.join("custom.secrets");
    std::fs::write(&extra, "EXTRA=extra-path-secret-value\n").unwrap();
    let mut cfg = enabled_cfg();
    cfg.scan_dotenv = true;
    cfg.extra_dotenv_paths = vec![extra];
    let t = RedactionTable::build(&cfg, root).unwrap();
    assert_eq!(t.scrub("extra-path-secret-value"), "***REDACT***");
}

#[test]
fn dotenv_scan_refuses_filesystem_root_but_honors_explicit_extra_paths() {
    let dir = TempDir::new().unwrap();
    let extra = dir.path().join("explicit.env");
    std::fs::write(&extra, "EXTRA=explicit-secret-value\n").unwrap();

    let paths = matched_dotenv_paths(
        Path::new("/"),
        &crate::config::extended::default_dotenv_patterns(),
        std::slice::from_ref(&extra),
    );

    assert_eq!(paths, vec![extra]);
}

#[test]
fn dotenv_scan_refuses_home_without_project_marker() {
    let home = dirs::home_dir().expect("home directory");

    assert!(
        dotenv_scan_start_is_unbounded(&home),
        "home directory itself is an unbounded scan start"
    );
}

#[test]
fn dotenv_max_depth_caps_outside_repo_unbounded_inside() {
    // Inside a git repo: unbounded so no `.env` is ever missed.
    assert_eq!(dotenv_max_depth(true), None);
    // Outside a repo: capped at depth 8 (the giant-dir pathological
    // case; `.env` files live near the root in practice).
    assert_eq!(dotenv_max_depth(false), Some(8));
}

/// Build a temp tree with a `.env` nine directory levels below the root
/// (`a/b/c/d/e/f/g/h/i/.env`). `walkdir` counts the root as depth 0, so
/// `a`=1 … `i`=9: the `.env` file itself sits at depth 10's parent — it
/// is only reachable by descending into `i` (depth 9), past a `max_depth`
/// of 8. Returns `(TempDir, root)`.
fn deep_env_tree() -> (TempDir, PathBuf) {
    let dir = TempDir::new().unwrap();
    let root = dir.path().to_path_buf();
    let deep = root.join("a/b/c/d/e/f/g/h/i");
    std::fs::create_dir_all(&deep).unwrap();
    std::fs::write(deep.join(".env"), "DEEP=deep-nested-secret-value\n").unwrap();
    // A shallow `.env` at the root is always in range — sanity anchor.
    std::fs::write(root.join(".env"), "TOP=top-level-secret-value\n").unwrap();
    (dir, root)
}

#[test]
fn walker_depth8_drops_depth9_env() {
    // Simulate the non-repo branch directly (the helper decided depth 8)
    // by walking with `max_depth(Some(8))`.
    use ignore::WalkBuilder;
    use ignore::overrides::OverrideBuilder;

    let (_dir, root) = deep_env_tree();
    let mut ob = OverrideBuilder::new(&root);
    for pat in crate::config::extended::default_dotenv_patterns() {
        ob.add(&pat).unwrap();
    }
    let overrides = ob.build().unwrap();
    let mut builder = WalkBuilder::new(&root);
    builder
        .standard_filters(false)
        .max_depth(Some(8))
        .overrides(overrides);
    let mut found: Vec<PathBuf> = builder
        .build()
        .flatten()
        .filter(|e| e.file_type().is_some_and(|t| t.is_file()))
        .map(|e| e.into_path())
        .collect();
    found.sort();
    // The root `.env` is in range; the depth-9 nested one is not.
    assert!(found.iter().any(|p| p == &root.join(".env")));
    assert!(
        !found.iter().any(|p| p.ends_with("a/b/c/d/e/f/g/h/i/.env")),
        "depth-9 `.env` must be dropped by max_depth(8): {found:?}"
    );
}

#[test]
fn walker_unbounded_finds_depth9_env() {
    // Simulate the in-repo branch directly (unbounded walk).
    use ignore::WalkBuilder;
    use ignore::overrides::OverrideBuilder;

    let (_dir, root) = deep_env_tree();
    let mut ob = OverrideBuilder::new(&root);
    for pat in crate::config::extended::default_dotenv_patterns() {
        ob.add(&pat).unwrap();
    }
    let overrides = ob.build().unwrap();
    let mut builder = WalkBuilder::new(&root);
    builder
        .standard_filters(false)
        .max_depth(None)
        .overrides(overrides);
    let found: Vec<PathBuf> = builder
        .build()
        .flatten()
        .filter(|e| e.file_type().is_some_and(|t| t.is_file()))
        .map(|e| e.into_path())
        .collect();
    assert!(
        found.iter().any(|p| p.ends_with("a/b/c/d/e/f/g/h/i/.env")),
        "unbounded walk must find the depth-9 `.env`: {found:?}"
    );
}

// ── Private SSH keys (`scan_ssh_keys`) ───────────────────────────────

/// A realistic OpenSSH private-key body. The header is what `build`
/// content-matches on; the body is just enough to clear `min_secret_length`
/// and exercise multi-line key material.
const ED25519_PRIVATE_KEY: &str = concat!(
    "-----BEGIN OPENSSH PRIVATE KEY-----\n", // pragma: allowlist secret
    "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n",
    "QyNTUxOQAAACDfake-key-material-for-test-not-a-real-key-0001AAAAAA\n",
    "-----END OPENSSH PRIVATE KEY-----",
);

const ED25519_PUBLIC_KEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5fake-public-key-material-001 user@host";

/// Build a config with only `scan_ssh_keys` on, pointed at `dir` via the
/// `ssh_key_dir` override so the test never touches the real home.
fn ssh_cfg(dir: &Path) -> RedactConfig {
    let mut cfg = enabled_cfg();
    cfg.scan_ssh_keys = true;
    cfg.ssh_key_dir = Some(dir.to_path_buf());
    cfg
}

#[test]
fn ssh_private_key_redacted_public_key_not() {
    let dir = TempDir::new().unwrap();
    std::fs::write(dir.path().join("id_ed25519"), ED25519_PRIVATE_KEY).unwrap();
    std::fs::write(dir.path().join("id_ed25519.pub"), ED25519_PUBLIC_KEY).unwrap();

    let t = RedactionTable::build(&ssh_cfg(dir.path()), dir.path()).unwrap();

    // The private key body is scrubbed wherever it appears.
    let scrubbed = t.scrub(ED25519_PRIVATE_KEY);
    assert!(
        !scrubbed.contains("fake-key-material-for-test"),
        "private key body must be scrubbed: {scrubbed:?}"
    );
    assert!(scrubbed.contains("***REDACT***"));

    // The sibling public key content is left intact.
    assert_eq!(t.scrub(ED25519_PUBLIC_KEY), ED25519_PUBLIC_KEY);
}

#[test]
fn ssh_private_key_redacted_inside_arbitrary_text() {
    // Simulates a key pasted into a tool result (`cat ~/.ssh/id_ed25519`).
    let dir = TempDir::new().unwrap();
    std::fs::write(dir.path().join("id_rsa"), ED25519_PRIVATE_KEY).unwrap();

    let t = RedactionTable::build(&ssh_cfg(dir.path()), dir.path()).unwrap();
    let body = format!("here is the output:\n{ED25519_PRIVATE_KEY}\n— end of file");
    let scrubbed = t.scrub(&body);
    assert!(!scrubbed.contains("fake-key-material-for-test"));
    assert!(!scrubbed.contains("BEGIN OPENSSH PRIVATE KEY"));
    assert!(scrubbed.contains("***REDACT***"));
    // Surrounding prose is preserved.
    assert!(scrubbed.contains("here is the output:"));
    assert!(scrubbed.contains("— end of file"));
}

#[test]
fn ssh_non_key_files_not_registered() {
    let dir = TempDir::new().unwrap();
    // None of these carry a PEM private-key header, and all are name-skipped.
    std::fs::write(
        dir.path().join("known_hosts"),
        "github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5known-hosts-entry-001\n",
    )
    .unwrap();
    std::fs::write(
        dir.path().join("authorized_keys"),
        "ssh-rsa AAAAB3NzaC1authorized-keys-entry-value-001 user@host\n",
    )
    .unwrap();
    std::fs::write(
        dir.path().join("config"),
        "Host example\n  HostName example.com-config-value-001\n",
    )
    .unwrap();

    let t = RedactionTable::build(&ssh_cfg(dir.path()), dir.path()).unwrap();
    // Nothing was registered: the table is empty and content passes through.
    assert!(t.is_empty());
    assert_eq!(
        t.scrub("github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5known-hosts-entry-001"),
        "github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5known-hosts-entry-001"
    );
}

#[test]
fn ssh_keys_skipped_when_disabled() {
    let dir = TempDir::new().unwrap();
    std::fs::write(dir.path().join("id_ed25519"), ED25519_PRIVATE_KEY).unwrap();
    let mut cfg = ssh_cfg(dir.path());
    cfg.scan_ssh_keys = false;
    let t = RedactionTable::build(&cfg, dir.path()).unwrap();
    // With the source off, the key is not in the table.
    assert!(t.is_empty());
    assert_eq!(t.scrub(ED25519_PRIVATE_KEY), ED25519_PRIVATE_KEY);
}

#[test]
fn ssh_missing_dir_is_silent() {
    let dir = TempDir::new().unwrap();
    let missing = dir.path().join("no-such-ssh-dir");
    let mut cfg = enabled_cfg();
    cfg.scan_ssh_keys = true;
    cfg.ssh_key_dir = Some(missing);
    // Build succeeds (no error) with an empty table.
    let t = RedactionTable::build(&cfg, dir.path()).unwrap();
    assert!(t.is_empty());
}

#[test]
fn ssh_encrypted_private_key_still_registered() {
    let dir = TempDir::new().unwrap();
    let encrypted = concat!(
        "-----BEGIN ENCRYPTED PRIVATE KEY-----\n", // pragma: allowlist secret
        "MIIFHzBJBgkqhkiG9w0BBQ0wPDencrypted-key-material-for-test-001\n",
        "-----END ENCRYPTED PRIVATE KEY-----",
    );
    std::fs::write(dir.path().join("encrypted_key"), encrypted).unwrap();
    let t = RedactionTable::build(&ssh_cfg(dir.path()), dir.path()).unwrap();
    let scrubbed = t.scrub(encrypted);
    assert!(!scrubbed.contains("encrypted-key-material-for-test"));
    assert!(scrubbed.contains("***REDACT***"));
}

#[test]
fn ssh_private_key_lines_are_redacted_individually() {
    let dir = TempDir::new().unwrap();
    std::fs::write(dir.path().join("id_ed25519"), ED25519_PRIVATE_KEY).unwrap();
    let table = RedactionTable::build(&ssh_cfg(dir.path()), dir.path()).unwrap();

    for line in ED25519_PRIVATE_KEY.lines().filter(|line| !line.is_empty()) {
        let scrubbed = table.scrub(line);
        assert!(!scrubbed.contains(line));
        assert_eq!(scrubbed, "***REDACT***");
    }
}

#[test]
fn ssh_private_key_crlf_lines_are_redacted_individually() {
    let dir = TempDir::new().unwrap();
    let crlf_key = ED25519_PRIVATE_KEY.replace('\n', "\r\n");
    std::fs::write(dir.path().join("id_ed25519"), &crlf_key).unwrap();
    let table = RedactionTable::build(&ssh_cfg(dir.path()), dir.path()).unwrap();

    for line in ED25519_PRIVATE_KEY.lines().filter(|line| !line.is_empty()) {
        let scrubbed = table.scrub(line);
        assert!(!scrubbed.contains(line));
        assert_eq!(scrubbed, "***REDACT***");
    }
}

#[test]
fn ssh_crlf_and_lf_echoes_both_match() {
    // A key on disk with CRLF line endings: both the verbatim CRLF echo
    // and an LF-normalized echo must scrub (the normalized variant is
    // registered alongside the trimmed original).
    let dir = TempDir::new().unwrap();
    let crlf_key = ED25519_PRIVATE_KEY.replace('\n', "\r\n");
    std::fs::write(dir.path().join("id_ed25519"), &crlf_key).unwrap();
    let t = RedactionTable::build(&ssh_cfg(dir.path()), dir.path()).unwrap();

    let lf_echo = ED25519_PRIVATE_KEY; // LF
    assert!(
        !t.scrub(lf_echo).contains("fake-key-material-for-test"),
        "LF echo must scrub"
    );
    assert!(
        !t.scrub(crlf_key.trim())
            .contains("fake-key-material-for-test"),
        "CRLF echo must scrub"
    );
}

#[test]
fn is_pem_private_key_matches_headers_only() {
    for h in PEM_PRIVATE_KEY_HEADERS {
        assert!(is_pem_private_key(&format!("{h}\nbody\n")));
        // Leading whitespace is tolerated.
        assert!(is_pem_private_key(&format!("\n  {h}\nbody\n")));
    }
    assert!(!is_pem_private_key("ssh-ed25519 AAAA... user@host"));
    assert!(!is_pem_private_key("ssh-rsa AAAA..."));
    assert!(!is_pem_private_key("not a key at all"));
}

#[test]
fn configured_denylist_scrubs_multiple_layer_values() {
    let mut cfg = enabled_cfg();
    cfg.placeholder = "[redacted]".to_string();
    cfg.denylist = vec!["home-secret".to_string(), "project-secret".to_string()];
    let dir = TempDir::new().unwrap();
    let table = RedactionTable::build(&cfg, dir.path()).unwrap();

    let scrubbed = table.scrub("home-secret and project-secret");
    assert!(!scrubbed.contains("home-secret"));
    assert!(!scrubbed.contains("project-secret"));
    assert_eq!(scrubbed.matches("[redacted]").count(), 2);
}

#[test]
fn ssh_entries_are_not_persisted() {
    let dir = TempDir::new().unwrap();
    let key = "-----BEGIN PRIVATE KEY-----\nvery-private-ssh-material-123456789\n-----END PRIVATE KEY-----\n"; // allowlist secret: redaction fixture
    std::fs::write(dir.path().join("id_test"), key).unwrap();
    let table = RedactionTable::build(&ssh_cfg(dir.path()), dir.path()).unwrap();
    let json = table.to_persisted_json().unwrap();
    assert!(!json.contains("very-private-ssh-material-123456789"));
    assert_ne!(table.scrub(key), key);
}

#[test]
fn dotenv_entries_are_not_persisted() {
    let dir = TempDir::new().unwrap();
    let secret = "dotenv-persistence-secret-123456";
    std::fs::write(dir.path().join(".env"), format!("TOKEN={secret}\n")).unwrap();
    let mut cfg = enabled_cfg();
    cfg.scan_dotenv = true;
    let table = RedactionTable::build(&cfg, dir.path()).unwrap();
    let persisted = table.to_persisted_json().unwrap();
    assert!(!persisted.contains(secret));
    assert_eq!(
        RedactionTable::persisted_disk_derived_origins(&persisted).unwrap(),
        vec![format!(
            "$dotenv:{}:TOKEN",
            dir.path().join(".env").display()
        )],
    );
    assert_ne!(table.scrub(secret), secret);
}

#[test]
fn resumed_session_redacts_disk_derived_values() {
    let dir = TempDir::new().unwrap();
    let secret = "dotenv-resume-secret-123456";
    std::fs::write(dir.path().join(".env"), format!("TOKEN={secret}\n")).unwrap();
    let mut cfg = enabled_cfg();
    cfg.scan_dotenv = true;
    let fresh = RedactionTable::build(&cfg, dir.path()).unwrap();
    let resumed = RedactionTable::from_persisted_json(&fresh.to_persisted_json().unwrap()).unwrap();
    let rederived = resumed
        .union(&RedactionTable::build(&cfg, dir.path()).unwrap())
        .unwrap();
    assert_ne!(rederived.scrub(secret), secret);
}

#[test]
fn failed_rederivation_is_reported() {
    let secret = "legacy-file-secret-123456";
    let legacy = serde_json::json!({
        "entries": [{"value": secret, "class": "ordinary", "origin": "$ssh:id_missing"}],
        "placeholder": "***REDACT***", "disabled": false, "unsupported_files": []
    });
    let origins = RedactionTable::persisted_disk_derived_origins(&legacy.to_string()).unwrap();
    assert_eq!(origins, vec!["$ssh:id_missing"]);
    let purged = RedactionTable::from_persisted_json(&legacy.to_string()).unwrap();
    assert_eq!(purged.scrub(secret), secret);
}

#[test]
fn provider_credentials_are_redacted() {
    let dir = TempDir::new().unwrap();
    let api_key = "provider-api-key-123456";
    let oauth_token = "oauth-access-token-123456";
    let table = RedactionTable::build_with_env_and_secrets(
        &enabled_cfg(),
        dir.path(),
        &HashMap::new(),
        vec![
            ("$credentials:openai.api_key".into(), api_key.into()),
            (
                "$credentials:codex-oauth.access_token".into(),
                oauth_token.into(),
            ),
        ],
    )
    .unwrap();
    assert_ne!(table.scrub(api_key), api_key);
    assert_ne!(table.scrub(oauth_token), oauth_token);
}

#[test]
fn short_entries_are_refused_from_all_sources() {
    let dir = TempDir::new().unwrap();
    std::fs::write(dir.path().join(".env"), "TOKEN=x\n").unwrap();
    std::fs::write(
        dir.path().join("id_test"),
        "-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----\n", // allowlist secret: redaction fixture
    )
    .unwrap();
    let mut cfg = ssh_cfg(dir.path());
    cfg.scan_dotenv = true;
    cfg.min_secret_length = 1;
    let table = RedactionTable::build_with_env_and_secrets(
        &cfg,
        dir.path(),
        &HashMap::new(),
        vec![("$credentials:openai.api_key".into(), "x".into())],
    )
    .unwrap();
    assert_eq!(table.scrub("x"), "x");
}

#[test]
fn legacy_persisted_disk_entries_are_purged() {
    let secret = "legacy-dotenv-secret-123456";
    let legacy = serde_json::json!({
        "entries": [{"value": secret, "class": "ordinary", "origin": "$TOKEN (/project/.env)"}],
        "placeholder": "***REDACT***", "disabled": false, "unsupported_files": []
    });
    let restored = RedactionTable::from_persisted_json(&legacy.to_string()).unwrap();
    assert_eq!(restored.scrub(secret), secret);
    assert!(!restored.to_persisted_json().unwrap().contains(secret));
}

#[test]
fn approved_secret_file_read_registers_values() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("credentials");
    std::fs::write(&path, "TOKEN=long-approved-secret\n").unwrap();
    let cfg = enabled_cfg();
    let table = build_with_session_env(&cfg, dir.path(), &HashMap::new())
        .with_approved_secret_file(&cfg, &path)
        .unwrap();
    assert_eq!(table.scrub("long-approved-secret"), "***REDACT***");
}

#[test]
fn short_values_from_secret_files_are_not_registered() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("credentials");
    std::fs::write(&path, "TOKEN=x\n").unwrap();
    let cfg = enabled_cfg();
    let table = build_with_session_env(&cfg, dir.path(), &HashMap::new())
        .with_approved_secret_file(&cfg, &path)
        .unwrap();
    assert_eq!(table.scrub("x"), "x");
}

#[test]
fn secret_file_registration_uses_parsed_values() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("credentials");
    let contents = "TOKEN=long-approved-secret\n";
    std::fs::write(&path, contents).unwrap();
    let cfg = enabled_cfg();
    let table = build_with_session_env(&cfg, dir.path(), &HashMap::new())
        .with_approved_secret_file(&cfg, &path)
        .unwrap();
    assert_eq!(table.scrub(contents), "TOKEN=***REDACT***\n");
}

#[test]
fn sealed_bindings_and_noninference_process_egress_are_absent_env_scrub() {
    // AC2: SEALED_* is treated as sensitive for every child env scrub path.
    assert!(crate::redact::env_scrub_patterns("SEALED_PROD_TOKEN"));
    assert!(crate::redact::env_scrub_patterns("SEALED_DBURL_PROD"));
    assert!(!crate::redact::env_scrub_patterns("PATH"));
}

// ---------------------------------------------------------------------------
// sealed-value-untrusted-inference-marker: typed replacement architecture
// ---------------------------------------------------------------------------

use crate::redact::{Replacement, sealed_untrusted_inference_marker};

fn legacy_sealed_identity(name: &str) -> crate::sealed::identity::SealedRedactionIdentity {
    crate::sealed::identity::SealedRedactionIdentity {
        scope: crate::sealed::identity::SealedScopeKind::Session,
        record_id: None,
        name: crate::sealed::identity::SealedName::canonical(name).unwrap(),
        version: 0,
    }
}

/// The version-scoped active-set key for a legacy (version-0) session entry —
/// what `active_sealed_value_ids` derives on the grant side. Tests build their
/// active set through these helpers so the matcher's version binding is exercised
/// (a bare name / bare record id no longer matches a version-scoped entry).
fn legacy_active(name: &str) -> String {
    crate::sealed::identity::sealed_legacy_active_key(name, 0)
}

/// The version-scoped active-set key for a scoped entry at a given version.
fn scoped_active(record_id: &str, version: u32) -> String {
    crate::sealed::identity::sealed_scoped_active_key(record_id, version)
}

#[test]
fn sealed_untrusted_inference_marker_renders_exact_protocol_string() {
    // The marker is a protocol-level instruction with exact spelling:
    // Unicode em dash, lowercase, backtick-delimited value id.
    let marker = sealed_untrusted_inference_marker("prod_token");
    assert_eq!(
        marker,
        "**redacted by cockpit — to use this value, reference sealed value `prod_token`**"
    );
    // The value id is data, not assembled Markdown: it cannot inject headings,
    // links, or code-fence syntax because the sealed-value contract constrains
    // it to lowercase letters, digits, `-`, `_`.
    let marker2 = sealed_untrusted_inference_marker("db-prod-1");
    assert!(marker2.contains("`db-prod-1`"));
    assert!(!marker2.contains("]"));
}

#[test]
fn sealed_untrusted_inference_marker_generic_for_ordinary_secrets() {
    // The persisted table uses Generic replacement for every entry, including
    // sealed entries. Active authorization is never persisted in a redaction
    // entry — it is resolved at egress time.
    let cfg = enabled_cfg();
    let dir = TempDir::new().unwrap();
    let table = build_with_session_env(&cfg, dir.path(), &HashMap::new());
    let sealed_literal = "high-entropy-sealed-token-xyz";
    let table = table
        .with_forced_sealed_literal(
            sealed_literal.to_string(),
            legacy_sealed_identity("prod_token"),
        )
        .unwrap();
    // Without sealed replacements activated, the sealed entry renders the
    // generic placeholder — same as an ordinary secret.
    let scrubbed = table.scrub(&format!("use {sealed_literal} now"));
    assert!(scrubbed.contains("***REDACT***"));
    assert!(!scrubbed.contains(sealed_literal));
    assert!(!scrubbed.contains("reference sealed value"));
}

#[test]
fn sealed_untrusted_inference_marker_exact_for_active_grant() {
    // At egress time, with_sealed_replacements activates the actionable marker
    // for sealed entries whose canonical value id has an active exact grant.
    let cfg = enabled_cfg();
    let dir = TempDir::new().unwrap();
    let table = build_with_session_env(&cfg, dir.path(), &HashMap::new());
    let sealed_literal = "high-entropy-sealed-token-xyz";
    let table = table
        .with_forced_sealed_literal(
            sealed_literal.to_string(),
            legacy_sealed_identity("prod_token"),
        )
        .unwrap();
    let mut active = std::collections::HashSet::new();
    active.insert(legacy_active("prod_token"));
    let egress = table.with_sealed_replacements(&active);
    let scrubbed = egress.scrub(&format!("use {sealed_literal} now"));
    assert!(scrubbed.contains("reference sealed value `prod_token`"));
    assert!(!scrubbed.contains(sealed_literal));
}

#[test]
fn sealed_untrusted_inference_marker_inactive_grant_falls_back_generic() {
    // A sealed entry without an active exact grant (revoked, expired, ungranted)
    // receives the generic placeholder, never a stale actionable handle.
    let cfg = enabled_cfg();
    let dir = TempDir::new().unwrap();
    let table = build_with_session_env(&cfg, dir.path(), &HashMap::new());
    let sealed_literal = "high-entropy-sealed-token-xyz";
    let table = table
        .with_forced_sealed_literal(
            sealed_literal.to_string(),
            legacy_sealed_identity("prod_token"),
        )
        .unwrap();
    // No active grants — empty set.
    let active = std::collections::HashSet::<String>::new();
    let egress = table.with_sealed_replacements(&active);
    let scrubbed = egress.scrub(&format!("use {sealed_literal} now"));
    assert!(scrubbed.contains("***REDACT***"));
    assert!(!scrubbed.contains(sealed_literal));
    assert!(!scrubbed.contains("reference sealed value"));
}

#[test]
fn sealed_untrusted_inference_marker_mixed_sealed_and_ordinary() {
    // A request containing a sealed literal beside an ordinary secret preserves
    // text order and replaces each occurrence with the entry's own renderer.
    // An ordinary secret must never acquire a sealed ID, and a sealed literal
    // must never fall back to the ordinary marker (when its grant is active).
    let cfg = enabled_cfg();
    let dir = TempDir::new().unwrap();
    let table = build_with_session_env(&cfg, dir.path(), &HashMap::new());
    let sealed_literal = "high-entropy-sealed-token-xyz";
    let ordinary_secret = "ordinary-api-key-12345678";
    let table = table
        .with_forced_sealed_literal(
            sealed_literal.to_string(),
            legacy_sealed_identity("prod_token"),
        )
        .unwrap()
        .with_forced_literal(ordinary_secret.to_string(), "$SECRET".to_string())
        .unwrap();
    let mut active = std::collections::HashSet::new();
    active.insert(legacy_active("prod_token"));
    let egress = table.with_sealed_replacements(&active);
    let input = format!("sealed={sealed_literal} ordinary={ordinary_secret} done");
    let scrubbed = egress.scrub(&input);
    // The sealed literal gets the actionable marker.
    assert!(scrubbed.contains("reference sealed value `prod_token`"));
    // The ordinary secret gets the generic placeholder.
    assert!(scrubbed.contains("***REDACT***"));
    // No literal leaks.
    assert!(!scrubbed.contains(sealed_literal));
    assert!(!scrubbed.contains(ordinary_secret));
    // Text order is preserved: sealed marker appears before ordinary marker.
    let sealed_pos = scrubbed.find("reference sealed value").unwrap();
    let ordinary_pos = scrubbed.rfind("***REDACT***").unwrap();
    assert!(sealed_pos < ordinary_pos, "text order must be preserved");
}

#[test]
fn sealed_untrusted_inference_marker_multiple_occurrences_same_marker() {
    // Multiple occurrences of the same sealed literal each receive the same
    // complete marker. A marker produced on an earlier pass is idempotent.
    let cfg = enabled_cfg();
    let dir = TempDir::new().unwrap();
    let table = build_with_session_env(&cfg, dir.path(), &HashMap::new());
    let sealed_literal = "high-entropy-sealed-token-xyz";
    let table = table
        .with_forced_sealed_literal(
            sealed_literal.to_string(),
            legacy_sealed_identity("prod_token"),
        )
        .unwrap();
    let mut active = std::collections::HashSet::new();
    active.insert(legacy_active("prod_token"));
    let egress = table.with_sealed_replacements(&active);
    let input = format!("{sealed_literal} and {sealed_literal} again");
    let scrubbed = egress.scrub(&input);
    let marker = sealed_untrusted_inference_marker("prod_token");
    let count = scrubbed.matches(&marker).count();
    assert_eq!(count, 2, "each occurrence gets the complete marker");
    // Idempotency: re-scrubbing the already-scrubbed text does not nest,
    // truncate, or change the marker.
    let re_scrubbed = egress.scrub(&scrubbed);
    assert_eq!(re_scrubbed, scrubbed, "marker is idempotent under re-scrub");
}

#[test]
fn sealed_untrusted_inference_marker_per_entry_independent_rendering() {
    // AC4: in a mixed multi-sealed untrusted turn, each entry is independently
    // rendered. Only literals with an active exact grant receive the marker;
    // revoked/ungranted literals receive generic replacement.
    let cfg = enabled_cfg();
    let dir = TempDir::new().unwrap();
    let table = build_with_session_env(&cfg, dir.path(), &HashMap::new());
    let granted_literal = "granted-sealed-token-aaaa";
    let revoked_literal = "revoked-sealed-token-bbbb";
    let table = table
        .with_forced_sealed_literal(
            granted_literal.to_string(),
            legacy_sealed_identity("granted"),
        )
        .unwrap()
        .with_forced_sealed_literal(
            revoked_literal.to_string(),
            legacy_sealed_identity("revoked"),
        )
        .unwrap();
    // Only "granted" has an active exact grant; "revoked" does not.
    let mut active = std::collections::HashSet::new();
    active.insert(legacy_active("granted"));
    let egress = table.with_sealed_replacements(&active);
    let input = format!("granted={granted_literal} revoked={revoked_literal}");
    let scrubbed = egress.scrub(&input);
    // Granted: actionable marker.
    assert!(scrubbed.contains("reference sealed value `granted`"));
    assert!(!scrubbed.contains(granted_literal));
    // Revoked: generic placeholder, no actionable handle.
    assert!(scrubbed.contains("***REDACT***"));
    assert!(!scrubbed.contains("reference sealed value `revoked`"));
    assert!(!scrubbed.contains(revoked_literal));
}

#[test]
fn sealed_untrusted_inference_marker_scoped_origin_resolves_by_record_id() {
    // Scoped sealed values carry richer typed identity (scope + record id +
    // version + name). The renderer keys the marker on the canonical record_id
    // read directly from the typed entry, not the name — and never by parsing a
    // diagnostic-origin string.
    use crate::sealed::identity::{SealedName, SealedRecordId, SealedRedactionIdentity};
    use cockpit_db::db::sealed_scope::SealedScopeKind;

    let cfg = enabled_cfg();
    let dir = TempDir::new().unwrap();
    let table = build_with_session_env(&cfg, dir.path(), &HashMap::new());
    let sealed_literal = "scoped-sealed-token-cccc";
    let record_id = SealedRecordId::generate();
    let name = SealedName::canonical("deploy_key").unwrap();
    let identity = SealedRedactionIdentity {
        scope: SealedScopeKind::Project,
        record_id: Some(record_id),
        name,
        version: 1,
    };
    let table = table
        .with_forced_sealed_literal(sealed_literal.to_string(), identity)
        .unwrap();
    // The active set is keyed by the version-scoped scoped key over the
    // canonical record_id (UUID string) at this entry's version.
    let mut active = std::collections::HashSet::new();
    active.insert(scoped_active(&record_id.to_string(), 1));
    let egress = table.with_sealed_replacements(&active);
    let scrubbed = egress.scrub(&format!("use {sealed_literal}"));
    assert!(scrubbed.contains(&format!("reference sealed value `{record_id}`")));
    assert!(!scrubbed.contains(sealed_literal));
    // The name must not appear as the value id in the marker.
    assert!(!scrubbed.contains("reference sealed value `deploy_key`"));
}

#[test]
fn redaction_destination_renderer_is_explicit() {
    // AC13: the typed replacement selection is explicit and closed.
    // Generic/local: no sealed replacements → ordinary placeholder.
    let cfg = enabled_cfg();
    let dir = TempDir::new().unwrap();
    let table = build_with_session_env(&cfg, dir.path(), &HashMap::new());
    let sealed_literal = "destination-test-sealed-token";
    let table = table
        .with_forced_sealed_literal(sealed_literal.to_string(), legacy_sealed_identity("dest"))
        .unwrap();

    // Generic/local rendering: no active grants → generic placeholder.
    let generic = table.with_sealed_replacements(&std::collections::HashSet::new());
    let generic_out = generic.scrub(sealed_literal);
    assert!(generic_out.contains("***REDACT***"));
    assert!(!generic_out.contains("reference sealed value"));

    // Interactive-with-exact-connector-capability: active grant → marker.
    let mut active = std::collections::HashSet::new();
    active.insert(legacy_active("dest"));
    let interactive = table.with_sealed_replacements(&active);
    let interactive_out = interactive.scrub(sealed_literal);
    assert!(interactive_out.contains("reference sealed value `dest`"));

    // Interactive-without-capability: no active grant → generic (same as above).
    // (Already covered by `generic`.)

    // An empty table has no registered literal to scrub. This is a table
    // property, not a trusted-model egress mode.
    let empty = crate::redact::RedactionTable::empty();
    assert_eq!(empty.scrub(sealed_literal), sealed_literal);

    // The Replacement descriptor types are exhaustive: Generic and Sealed.
    let generic_repl = Replacement::Generic;
    assert!(!generic_repl.is_sealed());
    let sealed_repl = Replacement::Sealed {
        value_id: "dest".to_string(),
    };
    assert!(sealed_repl.is_sealed());
    assert_eq!(
        sealed_repl.render("***REDACT***"),
        sealed_untrusted_inference_marker("dest")
    );
    assert_eq!(generic_repl.render("***REDACT***"), "***REDACT***");
}

#[test]
fn sealed_registration_paths_use_typed_entries() {
    // AC7: every sealed-literal registration route uses the TYPED registration
    // API (`with_forced_sealed_literal`), and egress reads the classification
    // directly from the entry — never by parsing a diagnostic-origin string.
    //
    // The three production registration sites are:
    //   1. Session::set_sealed_value (session/sealed_values.rs)
    //   2. InterruptHub::seal_redaction_with_identity (engine/interrupt.rs)
    //   3. SealedRuntime via SessionRedactionSink (sealed/runtime.rs)
    //
    // This asserts the table stores typed identity and the historical inventory
    // reads it back from `sealed_identities`, and that an ordinary forced
    // literal is NOT classified sealed.
    use crate::sealed::historical_redaction_inventory;
    use crate::sealed::identity::{SealedName, SealedRecordId, SealedRedactionIdentity};
    use cockpit_db::db::sealed_scope::SealedScopeKind;

    let cfg = enabled_cfg();
    let dir = TempDir::new().unwrap();
    let table = build_with_session_env(&cfg, dir.path(), &HashMap::new());
    let literal = "typed-registration-test-token";
    let ordinary_literal = "ordinary-registration-token";
    let record_id = SealedRecordId::generate();
    let name = SealedName::canonical("prod_db").unwrap();
    let identity = SealedRedactionIdentity {
        scope: SealedScopeKind::Project,
        record_id: Some(record_id),
        name,
        version: 1,
    };
    let table = table
        .with_forced_sealed_literal(literal.to_string(), identity)
        .unwrap()
        .with_forced_literal(ordinary_literal.to_string(), "$SECRET".to_string())
        .unwrap();

    // The typed identity is stored and read back directly (no origin parsing).
    let identities = table.sealed_identities();
    assert_eq!(identities.len(), 1, "only the sealed entry is typed sealed");
    assert_eq!(identities[0].record_id, Some(record_id));
    assert_eq!(identities[0].name.as_str(), "prod_db");
    assert_eq!(identities[0].version, 1);

    // The historical inventory reads the same typed identity.
    let inventory = historical_redaction_inventory(&table);
    assert!(inventory.iter().any(|id| id.record_id == Some(record_id)));

    // The ordinary forced literal is NOT classified sealed and never receives
    // a marker even with a matching-name active set.
    let mut active = std::collections::HashSet::new();
    active.insert("$SECRET".to_string());
    let egress = table.with_sealed_replacements(&active);
    assert!(
        !egress
            .scrub(ordinary_literal)
            .contains("reference sealed value")
    );
    assert!(egress.scrub(ordinary_literal).contains("***REDACT***"));
}

#[test]
fn redaction_entry_classification_is_typed_and_single_vector() {
    // AC7: `RedactionTable` holds one vector of typed entries (value +
    // classification + per-target replacement). There is no parallel
    // origins/replacements vector — the struct field is a single
    // `Vec<RedactionEntry>` (a compile-time guarantee), and the matcher's
    // pattern list is derived from it 1:1.
    let cfg = enabled_cfg();
    let dir = TempDir::new().unwrap();
    let table = build_with_session_env(&cfg, dir.path(), &HashMap::new());
    let sealed_literal = "typed-single-vector-sealed-token";
    let ordinary_literal = "typed-single-vector-ordinary-secret";
    let table = table
        .with_forced_sealed_literal(sealed_literal.to_string(), legacy_sealed_identity("vault"))
        .unwrap()
        .with_forced_literal(ordinary_literal.to_string(), "$ORD".to_string())
        .unwrap();

    // Exactly one entry is classified sealed; every entry carries a class and a
    // replacement descriptor, and the matcher patterns are 1:1 with the vector.
    let sealed_count = table
        .entries
        .iter()
        .filter(|entry| matches!(entry.class, EntryClass::Sealed(_)))
        .count();
    assert_eq!(sealed_count, 1, "one typed sealed entry");
    assert!(
        table
            .entries
            .iter()
            .all(|entry| entry.replacement == Replacement::Generic),
        "the base table freezes no active sealed replacement"
    );
    assert_eq!(table.sealed_identities().len(), 1);

    // `with_sealed_replacements` selects `Replacement::Sealed` from the typed
    // identity only. The sealed value id resolves; the ordinary origin never
    // does, even if its diagnostic label appears in the active set.
    let mut active = std::collections::HashSet::new();
    active.insert(legacy_active("vault"));
    let egress = table.with_sealed_replacements(&active);
    assert!(
        egress
            .scrub(sealed_literal)
            .contains("reference sealed value `vault`")
    );
    let mut ord_active = std::collections::HashSet::new();
    ord_active.insert("$ORD".to_string());
    let ord_egress = table.with_sealed_replacements(&ord_active);
    assert!(
        !ord_egress
            .scrub(ordinary_literal)
            .contains("reference sealed value")
    );
    assert!(ord_egress.scrub(ordinary_literal).contains("***REDACT***"));

    // Structural: the egress replacement selection reads the typed
    // `EntryClass::Sealed`, never a parsed diagnostic-origin string. This
    // accompanies (never replaces) the runtime assertions above.
    let production = include_str!("mod.rs");
    assert!(
        production.contains("EntryClass::Sealed(identity) =>"),
        "with_sealed_replacements must read typed identity"
    );
    assert!(
        !production.contains("parse_sealed_redaction_origin("),
        "egress must not parse diagnostic-origin strings"
    );
}

#[test]
fn sealed_marker_requires_exact_action_grant() {
    // AC14: the sealed marker requires an active exact (value, version, action)
    // grant. A missing, wrong, or revoked grant falls back to generic.
    let cfg = enabled_cfg();
    let dir = TempDir::new().unwrap();
    let table = build_with_session_env(&cfg, dir.path(), &HashMap::new());
    let literal = "exact-grant-test-sealed-token";
    let table = table
        .with_forced_sealed_literal(literal.to_string(), legacy_sealed_identity("exact"))
        .unwrap();

    // Missing grant (empty set) → generic.
    let egress_none = table.with_sealed_replacements(&std::collections::HashSet::new());
    assert!(egress_none.scrub(literal).contains("***REDACT***"));

    // Wrong value id (different from "exact") → generic.
    let mut wrong = std::collections::HashSet::new();
    wrong.insert("other_value".to_string());
    let egress_wrong = table.with_sealed_replacements(&wrong);
    assert!(egress_wrong.scrub(literal).contains("***REDACT***"));
    assert!(
        !egress_wrong
            .scrub(literal)
            .contains("reference sealed value `exact`")
    );

    // Exact grant → marker.
    let mut exact = std::collections::HashSet::new();
    exact.insert(legacy_active("exact"));
    let egress_exact = table.with_sealed_replacements(&exact);
    assert!(
        egress_exact
            .scrub(literal)
            .contains("reference sealed value `exact`")
    );
}

#[test]
fn noninteractive_sealed_value_stays_generic() {
    // AC12: embeddings, utilities, and tandem/observer egress are generic-only.
    // The interactive marker is selected only for actual untrusted interactive
    // wire requests with an active exact grant. Noninteractive paths never call
    // with_sealed_replacements, so they always see the generic placeholder.
    let cfg = enabled_cfg();
    let dir = TempDir::new().unwrap();
    let table = build_with_session_env(&cfg, dir.path(), &HashMap::new());
    let sealed_literal = "noninteractive-test-sealed-token";
    let table = table
        .with_forced_sealed_literal(
            sealed_literal.to_string(),
            legacy_sealed_identity("noninteractive"),
        )
        .unwrap();
    // Precondition — a live grant WOULD activate the marker on the interactive
    // path: applying with_sealed_replacements for this value id renders the
    // actionable marker. So the generic result below is not because the entry
    // is unsealed or the grant is dead — it is because the noninteractive path
    // never derives it.
    let mut active = std::collections::HashSet::new();
    active.insert(legacy_active("noninteractive"));
    let interactive = table
        .with_sealed_replacements(&active)
        .scrub(sealed_literal);
    assert!(
        interactive.contains("reference sealed value `noninteractive`"),
        "with an active grant the interactive path would render the marker: {interactive}"
    );

    // The real utility egress path (`OutboundGuard::scrub`) holds the table
    // as-is (no with_sealed_replacements), so it renders the generic placeholder
    // even though a grant is active for the value.
    let guard = crate::engine::model::OutboundGuard::new(std::sync::Arc::new(table));
    let scrubbed = guard.scrub(sealed_literal);
    assert!(scrubbed.contains("***REDACT***"));
    assert!(!scrubbed.contains("reference sealed value"));
}

#[test]
fn untrusted_embedding_sealed_value_stays_generic() {
    // AC12: embeddings are generic-only. The embedding send boundary resolves
    // provider/model trust independently and uses OutboundGuard::scrub_many,
    // which calls the generic RedactionTable::scrub — never the interactive
    // marker path. This test verifies that the generic scrub path does not
    // produce the sealed marker even when the table has a sealed entry.
    let cfg = enabled_cfg();
    let dir = TempDir::new().unwrap();
    let table = build_with_session_env(&cfg, dir.path(), &HashMap::new());
    let sealed_literal = "embedding-test-sealed-token";
    let table = table
        .with_forced_sealed_literal(
            sealed_literal.to_string(),
            legacy_sealed_identity("embedding"),
        )
        .unwrap();
    // Precondition — a live grant WOULD activate the marker interactively.
    let mut active = std::collections::HashSet::new();
    active.insert(legacy_active("embedding"));
    let interactive = table
        .with_sealed_replacements(&active)
        .scrub(sealed_literal);
    assert!(
        interactive.contains("reference sealed value `embedding`"),
        "with an active grant the interactive path would render the marker: {interactive}"
    );

    // The embedding path uses OutboundGuard::scrub_many, which delegates to
    // RedactionTable::scrub — the generic path, not with_sealed_replacements —
    // so no marker appears even though the grant is active for the value.
    let guard = crate::engine::model::OutboundGuard::new(std::sync::Arc::new(table));
    let redacted = guard.scrub_many(&[sealed_literal, "clean text"]);
    assert!(redacted[0].contains("***REDACT***"));
    assert!(!redacted[0].contains("reference sealed value"));
    assert_eq!(redacted[1], "clean text");
}

#[tokio::test]
async fn noninteractive_tandem_egress_stays_generic_with_live_grant() {
    // AC9: the tandem/observer egress derives the interactive sealed marker
    // NOWHERE. Driven through the REAL production path `Model::complete_tandem`
    // (not `OutboundGuard` in isolation) with a table whose sealed entry WOULD
    // render the actionable marker on the interactive path under a live grant —
    // so a generic result here proves the tandem path never derives it.
    use crate::config::providers::{ModelEntry, ModelTrust, ProviderEntry, ProvidersConfig};
    use crate::engine::message::Message;
    use crate::engine::model::{Model, ModelParams};
    use std::sync::Arc;

    let cfg = enabled_cfg();
    let dir = TempDir::new().unwrap();
    let table = build_with_session_env(&cfg, dir.path(), &HashMap::new());
    let sealed_literal = "tandem-live-grant-sealed-token";
    let table = table
        .with_forced_sealed_literal(sealed_literal.to_string(), legacy_sealed_identity("tandem"))
        .unwrap();

    // Precondition — a live grant WOULD activate the marker on the interactive
    // path, so the generic tandem result below is not because the entry is
    // unsealed or the grant is dead.
    let mut active = std::collections::HashSet::new();
    active.insert(legacy_active("tandem"));
    let interactive = table
        .with_sealed_replacements(&active)
        .scrub(sealed_literal);
    assert!(
        interactive.contains("reference sealed value `tandem`"),
        "with an active grant the interactive path would render the marker: {interactive}"
    );

    // An untrusted tandem model at a dead URL: the send fails fast, but
    // `outcome.request` is the locally assembled wire body either way.
    let mut providers = ProvidersConfig::default();
    providers.providers.insert(
        "cloud".into(),
        ProviderEntry {
            url: "http://127.0.0.1:1/v1".into(),
            models: vec![ModelEntry {
                id: "cloud-model".into(),
                trust: Some(ModelTrust::Untrusted),
                ..ModelEntry::default()
            }],
            ..ProviderEntry::default()
        },
    );
    let model = Model::for_provider(&providers, "cloud", "cloud-model", Arc::new(table)).unwrap();
    let outcome = model
        .complete_tandem(
            "system",
            &[Message::user(format!("the token is {sealed_literal}"))],
            &Message::user("go"),
            &[],
            &ModelParams::default(),
        )
        .await;
    let body = serde_json::to_string(&outcome.request).unwrap();
    assert!(
        body.contains("***REDACT***"),
        "tandem egress renders the generic placeholder: {body}"
    );
    assert!(
        !body.contains("reference sealed value"),
        "tandem egress never derives the marker: {body}"
    );
    assert!(
        !body.contains(sealed_literal),
        "no raw sealed literal on the tandem wire: {body}"
    );
}

#[tokio::test]
async fn untrusted_embedding_chokepoint_stays_generic_with_live_grant() {
    // AC9: the embeddings chokepoint (`OpenAiCompatEmbedder::embed`) derives the
    // interactive marker nowhere. Driven through the REAL embedder send path with
    // a live-grant sealed table and a `ScriptedProvider` wire capture — the
    // captured request body carries the generic placeholder, never the marker.
    use crate::embeddings::{Embedder, OpenAiCompatEmbedder};
    use crate::engine::model::OutboundGuard;
    use crate::providers::models_fetch::ResolvedRequest;
    use cockpit_test_support::provider::{ScriptedProvider, Turn};
    use std::sync::Arc;

    let cfg = enabled_cfg();
    let dir = TempDir::new().unwrap();
    let table = build_with_session_env(&cfg, dir.path(), &HashMap::new());
    let sealed_literal = "embedding-chokepoint-sealed-token";
    let table = table
        .with_forced_sealed_literal(
            sealed_literal.to_string(),
            legacy_sealed_identity("embedchoke"),
        )
        .unwrap();
    // Precondition — a live grant WOULD render the marker interactively.
    let mut active = std::collections::HashSet::new();
    active.insert(legacy_active("embedchoke"));
    assert!(
        table
            .with_sealed_replacements(&active)
            .scrub(sealed_literal)
            .contains("reference sealed value `embedchoke`")
    );

    let mut provider = ScriptedProvider::builder()
        .turn(Turn::RawJson(serde_json::json!({
            "data": [
                { "index": 0, "embedding": [1.0] },
                { "index": 1, "embedding": [1.0] }
            ]
        })))
        .start()
        .await;
    let guard = OutboundGuard::new(Arc::new(table));
    let embedder = OpenAiCompatEmbedder::from_resolved_request(
        ResolvedRequest {
            base_url: provider.base_url(),
            headers: vec![],
            is_codex_credential: false,
        },
        "text-embedding-3-small".into(),
        None,
        guard,
    )
    .unwrap();
    let _ = embedder.embed(&[sealed_literal, "clean text"]).await;

    // The captured wire body carries only the generic placeholder.
    let captured = provider.next_request().await;
    let body = captured.body.to_string();
    assert!(
        body.contains("***REDACT***"),
        "embedding wire renders the generic placeholder: {body}"
    );
    assert!(
        !body.contains("reference sealed value"),
        "embedding chokepoint never derives the marker: {body}"
    );
    assert!(
        !body.contains(sealed_literal),
        "no raw sealed literal on the embedding wire: {body}"
    );
}

#[test]
fn untrusted_inference_keeps_mandatory_sensitive_baseline_when_redaction_is_disabled() {
    // AC15: when discretionary redaction is disabled (redact.enabled = false),
    // environment, credential-store, and sealed sentinels remain absent from
    // every untrusted wire/capture field. The `enforced` view ignores the
    // config-level opt-out so untrusted egress still scrubs.
    let mut cfg = enabled_cfg();
    cfg.enabled = false; // discretionary redaction disabled
    let dir = TempDir::new().unwrap();
    let table = build_with_session_env(&cfg, dir.path(), &HashMap::new());
    let sealed_literal = "disabled-redaction-sealed-token";
    let ordinary_secret = "disabled-redaction-ordinary-key";
    let table = table
        .with_forced_sealed_literal(
            sealed_literal.to_string(),
            legacy_sealed_identity("disabled"),
        )
        .unwrap()
        .with_forced_literal(ordinary_secret.to_string(), "$SECRET".to_string())
        .unwrap();
    // The table is built with disabled=true, so the raw table passes through.
    assert_eq!(table.scrub(sealed_literal), sealed_literal);
    // But the enforced view (untrusted egress) ignores the opt-out.
    let enforced = table.enforced();
    let scrubbed_sealed = enforced.scrub(sealed_literal);
    let scrubbed_ordinary = enforced.scrub(ordinary_secret);
    assert!(!scrubbed_sealed.contains(sealed_literal));
    assert!(!scrubbed_ordinary.contains(ordinary_secret));
    assert!(scrubbed_sealed.contains("***REDACT***"));
    assert!(scrubbed_ordinary.contains("***REDACT***"));
}

// ---- Redacting Debug over sensitive-content structs ------------------------

#[test]
fn redaction_entry_debug_redacts_literal() {
    let secret = "super-secret-redaction-entry-value-123";
    let entry = RedactionEntry::ordinary(
        secret.to_string(),
        "$SECRET".to_string(),
        OrdinarySource::Credential,
    );
    let rendered = format!("{entry:?}");
    assert!(!rendered.contains(secret), "leaked literal: {rendered}");
    assert!(rendered.contains("REDACTED"), "missing marker: {rendered}");
    // Non-secret structural fields stay visible for diagnostics.
    assert!(rendered.contains("$SECRET"), "dropped class: {rendered}");
}

#[test]
fn candidate_debug_redacts_value() {
    let secret = "candidate-secret-value-abcdef-456";
    let candidate = Candidate::prunable(secret.to_string(), "$VAR".to_string(), false);
    let rendered = format!("{candidate:?}");
    assert!(!rendered.contains(secret), "leaked value: {rendered}");
    assert!(rendered.contains("REDACTED"), "missing marker: {rendered}");
    assert!(rendered.contains("$VAR"), "dropped origin: {rendered}");
}

#[test]
fn persisted_entry_debug_redacts_value() {
    let secret = "persisted-entry-secret-value-xyz-789";
    let entry = RedactionEntry::ordinary(
        secret.to_string(),
        "$SECRET".to_string(),
        OrdinarySource::Credential,
    );
    let persisted = PersistedEntry::from_entry(&entry);
    let rendered = format!("{persisted:?}");
    assert!(!rendered.contains(secret), "leaked value: {rendered}");
    assert!(rendered.contains("REDACTED"), "missing marker: {rendered}");
}

#[test]
fn max_match_len_reports_longest_registered_literal() {
    // Empty/no-op table: nothing can match, so the finite bound is 0. A caller
    // computing an (M - 1) truncation margin must guard M <= 1, and this pins the
    // value it guards on.
    assert_eq!(RedactionTable::empty().max_match_len(), 0);

    // With several literals of differing lengths, the max is the longest one's
    // byte length — the exact M the harness child-output scrub relies on to size
    // its boundary-straddle margin. There is no regex/unbounded matcher, so this
    // is a real finite ceiling on any possible match.
    let short = "abcd"; // 4 bytes (the hard minimum entry length)
    let long = "sk-live-longest-registered-literal-0123456789"; // 45 bytes
    let table = RedactionTable::empty()
        .with_forced_literal(short.to_string(), "$leak:short".to_string())
        .unwrap()
        .with_forced_literal(long.to_string(), "$leak:long".to_string())
        .unwrap();
    assert_eq!(table.max_match_len(), long.len());
    // The enforced view shares the same entries, so its ceiling is identical —
    // this is the view the harness output scrub actually calls.
    assert_eq!(table.enforced().max_match_len(), long.len());
}

#[test]
fn straddle_fixpoint_cut_advances_past_overlapping_literals() {
    // Two OVERLAPPING registered literals: `abcdefghij` [5,15) and
    // `cdefghijWXYZ` [7,19). aho-corasick's emitted set contains only the
    // leftmost-longest `abcdefghij`, so snapping to a single emitted match end
    // (15) would leave `cdefghijWXYZ` straddling the new cut. The fixpoint must
    // advance to the FURTHEST straddling end (19).
    let table = RedactionTable::empty()
        .with_forced_literal("abcdefghij".to_string(), "$leak:a".to_string())
        .unwrap()
        .with_forced_literal("cdefghijWXYZ".to_string(), "$leak:b".to_string())
        .unwrap();
    let body = "PPPPPabcdefghijWXYZ....";
    assert_eq!(table.straddle_fixpoint_cut(body, 11), 19);
    // An offset outside every occurrence is returned unchanged (char-boundary).
    assert_eq!(table.straddle_fixpoint_cut(body, 21), 21);
    // A no-op (empty) table never advances.
    assert_eq!(RedactionTable::empty().straddle_fixpoint_cut(body, 3), 3);

    // SELF-overlap: `aaaa` occurs at [0,4) and [1,5); only the latter straddles
    // cut=4. A non-overlapping scan would miss it and return 4; overlapping
    // enumeration advances to 5. (`zzzzz` sets M=5 so the window covers [1,5).)
    let self_overlap = RedactionTable::empty()
        .with_forced_literal("zzzzz".to_string(), "$leak:m".to_string())
        .unwrap()
        .with_forced_literal("aaaa".to_string(), "$leak:a".to_string())
        .unwrap();
    assert_eq!(self_overlap.straddle_fixpoint_cut("aaaaaQQQQ", 4), 5);
}

#[test]
fn straddle_fixpoint_cut_back_retreats_past_overlapping_literals() {
    // The BACK mirror of the forward fixpoint. Two OVERLAPPING literals ending at
    // the head end: `abcdefghij` [4,14) and `WXYZabcdef` [0,10) both straddle a
    // back cut inside them. aho-corasick emits only leftmost-longest, so a single
    // snap to one emitted match start would leave the other straddling the new
    // cut. The back fixpoint must retreat to the EARLIEST straddling start (0).
    let table = RedactionTable::empty()
        .with_forced_literal("abcdefghij".to_string(), "$leak:a".to_string())
        .unwrap()
        .with_forced_literal("WXYZabcdef".to_string(), "$leak:b".to_string())
        .unwrap();
    // body: `WXYZabcdefghij....` — `WXYZabcdef` [0,10), `abcdefghij` [4,14).
    let body = "WXYZabcdefghij....";
    // A cut at 8 straddles both (0<8<10 and 4<8<14); retreat below both to 0.
    assert_eq!(table.straddle_fixpoint_cut_back(body, 8), 0);
    // A cut outside every occurrence is returned unchanged (char boundary).
    assert_eq!(table.straddle_fixpoint_cut_back(body, 15), 15);
    // A no-op (empty) table never retreats.
    assert_eq!(
        RedactionTable::empty().straddle_fixpoint_cut_back(body, 8),
        8
    );

    // SELF-overlap mirror of the forward `aaaaaQQQQ` case: trailing `aaaaa` in
    // `QQQQaaaaa`, with `aaaa` at [4,8) and [5,9). A cut at 5 straddles [4,8);
    // a non-overlapping scan alone would then stop, but the fixpoint must keep
    // retreating past every straddling occurrence until the whole run of `a`s is
    // dropped — down to 4 (keeping `QQQQ`). (`zzzzz` sets M=5 so the window
    // reaches the straddlers.)
    let self_overlap = RedactionTable::empty()
        .with_forced_literal("zzzzz".to_string(), "$leak:m".to_string())
        .unwrap()
        .with_forced_literal("aaaa".to_string(), "$leak:a".to_string())
        .unwrap();
    assert_eq!(self_overlap.straddle_fixpoint_cut_back("QQQQaaaaa", 5), 4);
}

// ---------------------------------------------------------------------------
// scrub: overlapping registered literals are fully covered
//
// `MatchKind::LeftmostLongest` `replace_all` emits only NON-overlapping matches
// and resumes PAST each one, so a second registered literal that shares a run
// with the first leaks its non-overlapping tail. These exercise the production
// `scrub`/`scrub_cow` entry points and each FAILS against the old single-pass
// `replace_all` implementation.
// ---------------------------------------------------------------------------

#[test]
fn scrub_covers_cross_entry_overlapping_literals() {
    // `abcdefghij` [3,13) and `cdefghijWXYZ` [5,17) overlap in the body. The old
    // leftmost-longest `replace_all` emits only `abcdefghij` and resumes at 13,
    // so the second literal's tail `WXYZ` survives UN-redacted. The overlap-aware
    // scrub must cover the whole run with a single placeholder.
    let table = RedactionTable::empty()
        .with_forced_literal("abcdefghij".to_string(), "$leak:a".to_string())
        .unwrap()
        .with_forced_literal("cdefghijWXYZ".to_string(), "$leak:b".to_string())
        .unwrap();
    let ph = table.placeholder().to_string();
    let out = table.scrub("PREabcdefghijWXYZPOST");
    assert!(!out.contains("abcdefghij"), "first secret survived: {out}");
    assert!(
        !out.contains("cdefghijWXYZ"),
        "second secret survived: {out}"
    );
    // The specific regression: leftmost-longest leaks this non-overlapping tail.
    assert!(!out.contains("WXYZ"), "leaked overlapping tail: {out}");
    assert_eq!(out, format!("PRE{ph}POST"));
}

#[test]
fn scrub_covers_self_overlapping_literal() {
    // `aaaa` occurs at [2,6) and [3,7) in `XXaaaaaYY`. Leftmost-longest emits
    // [2,6) and resumes at 6, leaving the trailing `a` (the [3,7) tail) intact.
    let table = RedactionTable::empty()
        .with_forced_literal("aaaa".to_string(), "$leak:a".to_string())
        .unwrap();
    let ph = table.placeholder().to_string();
    let out = table.scrub("XXaaaaaYY");
    // The placeholder carries no lowercase `a`, so any surviving `a` is a leak.
    assert!(
        !ph.contains('a'),
        "test precondition: placeholder has no `a`"
    );
    assert!(
        !out.contains('a'),
        "an `a` from the secret run survived: {out}"
    );
    assert_eq!(out, format!("XX{ph}YY"));
}

#[test]
fn scrub_covers_chained_overlapping_literals() {
    // Three literals overlapping pairwise tile one run: `abcdef` [2,8),
    // `cdefgh` [4,10), `efghij` [6,12) in `<<abcdefghij>>`. Leftmost-longest
    // emits `abcdef` and resumes at 8, leaking the `ghij` tail.
    let table = RedactionTable::empty()
        .with_forced_literal("abcdef".to_string(), "$leak:1".to_string())
        .unwrap()
        .with_forced_literal("cdefgh".to_string(), "$leak:2".to_string())
        .unwrap()
        .with_forced_literal("efghij".to_string(), "$leak:3".to_string())
        .unwrap();
    let ph = table.placeholder().to_string();
    let out = table.scrub("<<abcdefghij>>");
    for frag in ["abcdef", "cdefgh", "efghij", "ghij"] {
        assert!(!out.contains(frag), "fragment `{frag}` survived: {out}");
    }
    assert_eq!(out, format!("<<{ph}>>"));
}

#[test]
fn scrub_non_overlapping_input_matches_legacy_behavior() {
    // No-regression: separated distinct secrets each collapse to their own
    // placeholder; a body with no secret returns BORROWED (unchanged bytes);
    // and adjacent (touching, non-overlapping) secrets stay TWO placeholders,
    // exactly as the old leftmost-longest `replace_all` produced.
    let table = RedactionTable::empty()
        .with_forced_literal("first-secret-value".to_string(), "$leak:1".to_string())
        .unwrap()
        .with_forced_literal("second-secret-value".to_string(), "$leak:2".to_string())
        .unwrap();
    let ph = table.placeholder().to_string();
    assert_eq!(
        table.scrub("a first-secret-value b second-secret-value c"),
        format!("a {ph} b {ph} c")
    );
    // No secret present → borrowed (no allocation), byte-identical.
    let clean = "nothing sensitive here at all";
    match table.scrub_cow(clean) {
        std::borrow::Cow::Borrowed(s) => assert_eq!(s, clean),
        std::borrow::Cow::Owned(_) => panic!("no-match body must borrow, not allocate"),
    }
    // Touching-but-disjoint distinct secrets: `aaaaaa` [1,7) then `bbbbbb` [7,13)
    // share no byte, so they stay two placeholders (touching spans are not
    // merged — this is what the old `replace_all` emitted).
    let adjacent = RedactionTable::empty()
        .with_forced_literal("aaaaaa".to_string(), "$leak:a".to_string())
        .unwrap()
        .with_forced_literal("bbbbbb".to_string(), "$leak:b".to_string())
        .unwrap();
    let ph2 = adjacent.placeholder().to_string();
    assert_eq!(adjacent.scrub("Zaaaaaabbbbbb Z"), format!("Z{ph2}{ph2} Z"));
}

#[test]
fn scrub_single_sealed_range_keeps_marker_but_overlap_falls_back_to_generic() {
    let cfg = enabled_cfg();
    let dir = TempDir::new().unwrap();

    // A single-entry sealed range with an active grant still renders the
    // actionable marker (unchanged from the old single-pass scrub).
    let sealed_literal = "sealed-alpha-token-value";
    let table = build_with_session_env(&cfg, dir.path(), &HashMap::new())
        .with_forced_sealed_literal(sealed_literal.to_string(), legacy_sealed_identity("alpha"))
        .unwrap();
    let mut active = std::collections::HashSet::new();
    active.insert(legacy_active("alpha"));
    let out = table
        .with_sealed_replacements(&active)
        .scrub(&format!("use {sealed_literal} now"));
    assert!(
        out.contains("reference sealed value `alpha`"),
        "single-entry sealed marker missing: {out}"
    );
    assert!(
        !out.contains(sealed_literal),
        "sealed value survived: {out}"
    );

    // A range where a SEALED literal genuinely OVERLAPS an ORDINARY one spans two
    // entries: `grantoken-shared-tail` [1,22) and `shared-tail-extra` [11,28) in
    // `<grantoken-shared-tail-extra>`. It must render the conservative GLOBAL
    // placeholder, never a partial sealed marker over a multi-secret blob — and
    // the ordinary literal's `-extra` tail (which leftmost-longest would leak)
    // must be covered.
    let sealed2 = "grantoken-shared-tail";
    let ordinary2 = "shared-tail-extra";
    let mixed = build_with_session_env(&cfg, dir.path(), &HashMap::new())
        .with_forced_sealed_literal(sealed2.to_string(), legacy_sealed_identity("beta"))
        .unwrap()
        .with_forced_literal(ordinary2.to_string(), "$SECRET".to_string())
        .unwrap();
    let ph = mixed.placeholder().to_string();
    let mut active2 = std::collections::HashSet::new();
    active2.insert(legacy_active("beta"));
    let mixed_out = mixed
        .with_sealed_replacements(&active2)
        .scrub("<grantoken-shared-tail-extra>");
    assert!(
        !mixed_out.contains("reference sealed value"),
        "sealed marker rendered over a multi-secret overlap: {mixed_out}"
    );
    assert!(
        !mixed_out.contains("grantoken"),
        "sealed secret survived: {mixed_out}"
    );
    assert!(
        !mixed_out.contains("extra"),
        "leaked overlapping ordinary tail: {mixed_out}"
    );
    assert_eq!(mixed_out, format!("<{ph}>"));
}

#[test]
fn scrub_covers_contained_literal() {
    // `bcd` [2,5) is fully CONTAINED in `abcde` [1,6) in `Xabcde Y`.
    // `find_overlapping_iter` reports both; the merge covers the whole `abcde`
    // run, and the contained `bcd` never leaks.
    let table = RedactionTable::empty()
        .with_forced_literal("abcde".to_string(), "$leak:outer".to_string())
        .unwrap()
        .with_forced_literal("bcd".to_string(), "$leak:inner".to_string())
        .unwrap();
    let ph = table.placeholder().to_string();
    let out = table.scrub("Xabcde Y");
    assert!(!out.contains("abcde"), "outer secret survived: {out}");
    assert!(!out.contains("bcd"), "contained secret leaked: {out}");
    assert_eq!(out, format!("X{ph} Y"));
}

#[test]
fn scrub_self_overlapping_sealed_entry_renders_marker_once() {
    // A SELF-overlapping sealed literal with an active grant: `abcabc` occurs at
    // [2,8) and [5,11) in `xxabcabcabcyy`. The two occurrences merge into one
    // range from a SINGLE entry, so it renders the actionable marker exactly
    // ONCE over the whole run — not duplicated, and not collapsed to the generic
    // placeholder (a single-entry range keeps its typed replacement).
    let cfg = enabled_cfg();
    let dir = TempDir::new().unwrap();
    let sealed_literal = "abcabc";
    let table = build_with_session_env(&cfg, dir.path(), &HashMap::new())
        .with_forced_sealed_literal(sealed_literal.to_string(), legacy_sealed_identity("selfov"))
        .unwrap();
    let mut active = std::collections::HashSet::new();
    active.insert(legacy_active("selfov"));
    let marker = sealed_untrusted_inference_marker("selfov");
    let out = table
        .with_sealed_replacements(&active)
        .scrub("xxabcabcabcyy");
    assert_eq!(
        out.matches(&marker).count(),
        1,
        "sealed marker must render exactly once over the merged self-overlap: {out}"
    );
    assert!(
        !out.contains("abc"),
        "self-overlapping secret leaked: {out}"
    );
    assert_eq!(out, format!("xx{marker}yy"));
}

#[test]
fn scrub_covers_multibyte_utf8_overlapping_literals() {
    // Two literals of multibyte (2-byte) Greek chars that OVERLAP on a char
    // boundary: `αβγδ` [1,9) and `γδεζ` [5,13) share `γδ` in `XαβγδεζY`. The
    // overlapping scan and the byte-offset merge must cover the whole run
    // without ever bisecting a char (which would panic on the slice).
    let a = "αβγδ";
    let b = "γδεζ";
    // Precondition: they genuinely overlap on a shared multibyte run.
    assert!(a.ends_with("γδ") && b.starts_with("γδ"));
    let table = RedactionTable::empty()
        .with_forced_literal(a.to_string(), "$leak:a".to_string())
        .unwrap()
        .with_forced_literal(b.to_string(), "$leak:b".to_string())
        .unwrap();
    let ph = table.placeholder().to_string();
    let out = table.scrub("XαβγδεζY");
    assert!(!out.contains(a), "first multibyte secret survived: {out}");
    assert!(!out.contains(b), "second multibyte secret survived: {out}");
    assert!(!out.contains("γδ"), "shared multibyte run leaked: {out}");
    assert_eq!(out, format!("X{ph}Y"));
}
