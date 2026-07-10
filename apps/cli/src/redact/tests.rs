use super::*;
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
        min_secret_length: 8,
        placeholder: "***REDACT***".into(),
        denylist: vec![],
        allowlist: vec![],
    }
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
fn short_credential_shaped_key_value_is_redacted() {
    let dir = TempDir::new().unwrap();
    let env_path = dir.path().join(".env");
    std::fs::write(&env_path, "MY_PIN=abc\nSHORT=def\n").unwrap();
    let mut cfg = enabled_cfg();
    cfg.scan_dotenv = true;
    cfg.min_secret_length = 8;
    let t = RedactionTable::build(&cfg, dir.path()).unwrap();

    assert_eq!(t.scrub("pin abc"), "pin ***REDACT***");
    assert_eq!(t.scrub("short def"), "short def");
}

#[test]
fn stored_flycockpit_instance_token_is_forced_redaction_candidate() {
    let tmp = tempfile::TempDir::new().unwrap();
    crate::auth::flycockpit::with_redaction_token_override("fci_secret_token_12345", || {
        let mut cfg = RedactConfig::default();
        cfg.min_secret_length = 128;
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
    unsafe {
        std::env::set_var(key, &value);
    }

    let mut cfg = enabled_cfg();
    cfg.scan_environment = true;
    let dir = TempDir::new().unwrap();
    let table = RedactionTable::build(&cfg, dir.path()).unwrap();
    let scrubbed = table.scrub(&format!("value={lossy}"));
    assert!(!scrubbed.contains(&lossy));
    assert!(scrubbed.contains(&cfg.placeholder));

    unsafe {
        std::env::remove_var(key);
    }
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

    assert_eq!(table.entries_for_debug().len(), 8);
    assert_eq!(table.scrub("shared/secret/0001"), cfg.placeholder);
    assert_eq!(table.scrub("other/secret/0002"), cfg.placeholder);
}

#[test]
fn denylisted_value_redacts_encoded_variants() {
    let mut cfg = enabled_cfg();
    cfg.min_secret_length = 8;
    cfg.denylist = vec!["a/b".into()];
    let dir = TempDir::new().unwrap();
    let t = RedactionTable::build(&cfg, dir.path()).unwrap();

    let scrubbed = t.scrub("raw a/b base64 YS9i hex 612f62 url a%2Fb");
    assert!(!scrubbed.contains("YS9i"));
    assert!(!scrubbed.contains("612f62"));
    assert!(!scrubbed.contains("a%2Fb"));
    assert!(!scrubbed.contains(" raw a/b "));
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
    // SAFETY: tests run single-threaded enough that env mutation
    // here is acceptable; the same pattern is used elsewhere in the
    // test suite.
    unsafe {
        std::env::set_var(key, val);
    }
    let cfg = RedactConfig {
        enabled: true,
        scan_environment: true,
        scan_dotenv: false,
        scan_ssh_keys: false,
        ssh_key_dir: None,
        dotenv_patterns: crate::config::extended::default_dotenv_patterns(),
        extra_dotenv_paths: vec![],
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
    unsafe {
        std::env::remove_var(key);
    }
}

#[test]
fn build_with_env_redacts_env_only_secret_without_process_env() {
    let key = "COCKPIT_TEST_SESSION_ONLY_SECRET";
    let val = "session-only-secret-value-1234";
    unsafe {
        std::env::remove_var(key);
    }
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
fn short_env_values_not_redacted() {
    let key = "COCKPIT_TEST_SHORT_VALUE";
    let val = "abc";
    unsafe {
        std::env::set_var(key, val);
    }
    let mut cfg = enabled_cfg();
    cfg.scan_environment = true;
    cfg.min_secret_length = 8;
    let dir = TempDir::new().unwrap();
    let t = RedactionTable::build(&cfg, dir.path()).unwrap();
    // The 3-char value must not contribute a pattern.
    assert_eq!(t.scrub("the value is abc here"), "the value is abc here");
    unsafe {
        std::env::remove_var(key);
    }
}

#[test]
fn allowlisted_path_not_redacted_even_when_long() {
    // PATH is almost always long enough to clear min_secret_length;
    // confirm $PATH (and the LC_/LANG/XDG_ families) are never in
    // the table even with min_secret_length lowered all the way.
    // (Other env vars' values may still be substrings of PATH —
    // that's an inherent property of substring redaction and is
    // covered by `allowlisted_env_var_names_not_in_table`.)
    let mut cfg = enabled_cfg();
    cfg.scan_environment = true;
    cfg.min_secret_length = 1;
    let dir = TempDir::new().unwrap();
    let t = RedactionTable::build(&cfg, dir.path()).unwrap();
    let origins = t.entries_for_debug();
    for skipped in ["$PATH", "$HOME", "$LANG", "$LC_ALL", "$XDG_RUNTIME_DIR"] {
        assert!(
            !origins.contains(&skipped),
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
fn denylisted_value_always_redacted_including_short() {
    let mut cfg = enabled_cfg();
    cfg.scan_environment = false;
    cfg.scan_dotenv = false;
    cfg.min_secret_length = 16; // huge threshold so length can't help
    cfg.denylist = vec!["sek".into()]; // 3 chars — would normally fail
    let dir = TempDir::new().unwrap();
    let t = RedactionTable::build(&cfg, dir.path()).unwrap();
    let scrubbed = t.scrub("the keyword sek appears here");
    assert!(scrubbed.contains("***REDACT***"));
    assert!(!scrubbed.contains(" sek "));
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
    // patterns to the matcher. (Substring overlap with other env
    // vars is a separate concern and an inherent property of
    // substring redaction; that's fine — we just don't want PATH
    // itself catalogued.)
    let cfg = RedactConfig {
        enabled: true,
        scan_environment: true,
        scan_dotenv: false,
        scan_ssh_keys: false,
        ssh_key_dir: None,
        dotenv_patterns: crate::config::extended::default_dotenv_patterns(),
        extra_dotenv_paths: vec![],
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
            !origins.contains(&key.as_str()),
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
        min_secret_length: 8,
        placeholder: "***REDACT***".into(),
        denylist: vec![],
        allowlist: vec![],
    };
    let key = "COCKPIT_TEST_NUMERIC_SECRET";
    let val = "98765432109876543210";
    // SAFETY: this mirrors the existing env-mutation tests in this
    // module; the key is unique to this test and removed before return.
    unsafe {
        std::env::set_var(key, val);
    }
    let t = RedactionTable::build(&cfg, dir.path()).unwrap();

    assert_eq!(t.scrub(&format!("token={val}")), "token=***REDACT***");
    unsafe {
        std::env::remove_var(key);
    }
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
    // Nested array leaf string is also a candidate.
    assert_eq!(t.scrub("enabled-feature-x"), "***REDACT***");
    // The key `password` is never scrubbed; the int `5432` is pruned.
    assert_eq!(t.scrub("password 5432"), "password 5432");
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

#[test]
fn dotenv_hash_inside_quoted_value_is_not_a_comment() {
    let dir = TempDir::new().unwrap();
    let p = dir.path().join(".env");
    std::fs::write(&p, "TOKEN=\"value#with#hashes-long\"\n").unwrap();
    let mut cfg = enabled_cfg();
    cfg.scan_dotenv = true;
    let t = RedactionTable::build(&cfg, dir.path()).unwrap();
    assert_eq!(t.scrub("value#with#hashes-long"), "***REDACT***");
}

#[test]
fn structured_disable_marker_is_scoped_to_one_duplicate_value_occurrence() {
    let dir = TempDir::new().unwrap();
    let p = dir.path().join(".env");
    std::fs::write(
        &p,
        r#"marked = "shared-structured-secret" # COCKPIT_DISABLE_REDACT
kept = "shared-structured-secret"
"#,
    )
    .unwrap();
    let mut cfg = enabled_cfg();
    cfg.scan_dotenv = true;
    let table = RedactionTable::build(&cfg, dir.path()).unwrap();

    assert_eq!(table.scrub("shared-structured-secret"), cfg.placeholder);
}

#[test]
fn toml_marker_excludes_long_value() {
    let dir = TempDir::new().unwrap();
    let p = dir.path().join(".env");
    std::fs::write(
            &p,
            "marked = \"toml-marked-long-secret\" # COCKPIT_DISABLE_REDACT\nkept = \"toml-kept-long-secret\"\n",
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

#[test]
fn yaml_marker_excludes_long_value() {
    let dir = TempDir::new().unwrap();
    let p = dir.path().join(".env");
    std::fs::write(
        &p,
        "marked: yaml-marked-long-secret # COCKPIT_DISABLE_REDACT\nkept: yaml-kept-long-secret\n",
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

#[test]
fn json_has_no_comment_marker() {
    // JSON is exempt from the marker: a `# COCKPIT_DISABLE_REDACT`
    // would make the doc invalid JSON, so it parses as JSON only
    // without one and every leaf string stays a candidate.
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

#[test]
fn patterns_match_cwd_downward_across_subdirs() {
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
const ED25519_PRIVATE_KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----\n\
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n\
QyNTUxOQAAACDfake-key-material-for-test-not-a-real-key-0001AAAAAA\n\
-----END OPENSSH PRIVATE KEY-----";

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
    let encrypted = "-----BEGIN ENCRYPTED PRIVATE KEY-----\n\
MIIFHzBJBgkqhkiG9w0BBQ0wPDencrypted-key-material-for-test-001\n\
-----END ENCRYPTED PRIVATE KEY-----";
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
