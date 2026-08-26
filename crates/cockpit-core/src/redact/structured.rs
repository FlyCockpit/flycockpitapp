use super::*;

/// Recursively collect secret-keyed leaf string scalars in a JSON document.
/// Object keys are never collected. JSON has no comments, so the §5 marker
/// doesn't apply.
pub(super) fn collect_json_strings(
    value: &serde_json::Value,
    display: &str,
    length_exempt: bool,
    under_secret_key: bool,
    out: &mut Vec<Candidate>,
) {
    match value {
        serde_json::Value::String(s) if under_secret_key => {
            let mut candidate =
                Candidate::prunable(s.clone(), format!("{display} (json)"), length_exempt);
            // SEC-F3 consistency: values under a secret-shaped key register their
            // case-transformed echoes, mirroring the env-scan collector in
            // `mod.rs`. Reuses the already-computed `under_secret_key` gate rather
            // than recomputing `is_secret_shaped_key`. Decoupled from
            // `length_exempt` (kept narrow) so the `min_secret_length` prune still
            // keeps short values — and their case echoes — out of the table.
            candidate.register_case_variants = under_secret_key;
            out.push(candidate);
        }
        serde_json::Value::Array(items) => {
            for item in items {
                collect_json_strings(item, display, length_exempt, under_secret_key, out);
            }
        }
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                collect_json_strings(
                    v,
                    display,
                    length_exempt || credential_shaped_key(k),
                    under_secret_key || is_secret_shaped_key(k),
                    out,
                );
            }
        }
        _ => {}
    }
}

/// Recursively collect secret-keyed leaf string scalars in a TOML document.
/// Table keys are never collected; a value on a line bearing the §5 marker is
/// excluded via `marked`.
pub(super) fn collect_toml_strings(
    value: &toml::Value,
    display: &str,
    marked: &mut HashMap<String, usize>,
    length_exempt: bool,
    under_secret_key: bool,
    out: &mut Vec<Candidate>,
) {
    match value {
        toml::Value::String(s) => {
            let marked = consume_marked_value(marked, s);
            if under_secret_key && !marked {
                let mut candidate =
                    Candidate::prunable(s.clone(), format!("{display} (toml)"), length_exempt);
                // SEC-F3 consistency (see the JSON collector): reuse the
                // already-computed `under_secret_key` gate to register case
                // echoes. Left decoupled from `length_exempt` so the
                // `min_secret_length` prune still excludes short values.
                candidate.register_case_variants = under_secret_key;
                out.push(candidate);
            }
        }
        toml::Value::Array(items) => {
            for item in items {
                collect_toml_strings(item, display, marked, length_exempt, under_secret_key, out);
            }
        }
        toml::Value::Table(table) => {
            for (k, v) in table {
                collect_toml_strings(
                    v,
                    display,
                    marked,
                    length_exempt || credential_shaped_key(k),
                    under_secret_key || is_secret_shaped_key(k),
                    out,
                );
            }
        }
        _ => {}
    }
}

/// Recursively collect secret-keyed leaf string scalars in a YAML document. Map
/// keys are never collected; a value on a line bearing the §5 marker is
/// excluded via `marked`.
pub(super) fn collect_yaml_strings(
    value: &serde_yaml::Value,
    display: &str,
    marked: &mut HashMap<String, usize>,
    length_exempt: bool,
    under_secret_key: bool,
    out: &mut Vec<Candidate>,
) {
    match value {
        serde_yaml::Value::String(s) => {
            let marked = consume_marked_value(marked, s);
            if under_secret_key && !marked {
                let mut candidate =
                    Candidate::prunable(s.clone(), format!("{display} (yaml)"), length_exempt);
                // SEC-F3 consistency (see the JSON collector): reuse the
                // already-computed `under_secret_key` gate to register case
                // echoes. Left decoupled from `length_exempt` so the
                // `min_secret_length` prune still excludes short values.
                candidate.register_case_variants = under_secret_key;
                out.push(candidate);
            }
        }
        serde_yaml::Value::Sequence(items) => {
            for item in items {
                collect_yaml_strings(item, display, marked, length_exempt, under_secret_key, out);
            }
        }
        serde_yaml::Value::Mapping(map) => {
            for (k, v) in map {
                let key_exempt = k.as_str().map(credential_shaped_key).unwrap_or(false);
                let secret_key = k.as_str().map(is_secret_shaped_key).unwrap_or(false);
                collect_yaml_strings(
                    v,
                    display,
                    marked,
                    length_exempt || key_exempt,
                    under_secret_key || secret_key,
                    out,
                );
            }
        }
        _ => {}
    }
}

/// Strip one layer of matching surrounding quotes (`"` or `'`) if present.
pub(super) fn strip_quotes(s: &str) -> &str {
    if (s.starts_with('"') && s.ends_with('"') && s.len() >= 2)
        || (s.starts_with('\'') && s.ends_with('\'') && s.len() >= 2)
    {
        &s[1..s.len() - 1]
    } else {
        s
    }
}

#[cfg(test)]
mod case_variant_tests {
    use crate::config::extended::{RedactConfig, default_dotenv_patterns};
    use crate::redact::RedactionTable;

    fn cfg() -> RedactConfig {
        RedactConfig {
            enabled: true,
            scan_environment: false,
            scan_dotenv: true,
            scan_ssh_keys: false,
            ssh_key_dir: None,
            dotenv_patterns: default_dotenv_patterns(),
            extra_dotenv_paths: vec![],
            secret_path_patterns: vec![],
            min_secret_length: 8,
            placeholder: "***REDACT***".into(),
            denylist: vec![],
            allowlist: vec![],
        }
    }

    // JSON content in a scanned env file: the `collect_env_file_candidates`
    // auto-detector falls through dotenv to JSON. A value under a secret-shaped
    // key (`api_token`) is collected, and — via the `under_secret_key` reuse —
    // now registers its uppercased/capitalized echoes. `api_token` is NOT
    // `credential_shaped_key`, so those echoes went unscrubbed before SEC-F3:
    // fails pre-change, passes after.
    #[test]
    fn structured_secret_key_scrubs_uppercase_and_capitalized_echoes() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(
            dir.path().join(".env"),
            "{\n  \"api_token\": \"CaseTokenValue123\",\n  \"short_key\": \"abc\"\n}\n",
        )
        .unwrap();
        let cfg = cfg();
        let table = RedactionTable::build(&cfg, dir.path()).unwrap();

        // Raw value scrubs before and after the change (base entry).
        assert_eq!(table.scrub("CaseTokenValue123"), cfg.placeholder);
        // Uppercased echo — only registered once the collector gates case
        // variants on the `under_secret_key` value.
        assert_eq!(table.scrub("CASETOKENVALUE123"), cfg.placeholder);
        // Capitalized (Title-case first letter of the lowercased form) echo.
        assert_eq!(table.scrub("Casetokenvalue123"), cfg.placeholder);
    }

    // The narrow `length_exempt` floor is untouched: `short_key`'s 3-char value
    // is pruned by `min_secret_length`, so neither it nor its case echoes ever
    // register. Guards against over-redaction.
    #[test]
    fn short_structured_value_does_not_register_case_variants() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(
            dir.path().join(".env"),
            "{\n  \"api_token\": \"CaseTokenValue123\",\n  \"short_key\": \"abc\"\n}\n",
        )
        .unwrap();
        let cfg = cfg();
        let table = RedactionTable::build(&cfg, dir.path()).unwrap();

        // Below the 8-char floor: not redacted, and its uppercase echo is not
        // over-redacted either.
        assert_eq!(table.scrub("abc"), "abc");
        assert_eq!(table.scrub("ABC"), "ABC");
    }
}
