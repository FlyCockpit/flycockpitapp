use super::*;

/// Recursively collect every leaf string scalar in a JSON document.
/// Object keys are never collected. JSON has no comments, so the §5
/// marker doesn't apply.
pub(super) fn collect_json_strings(
    value: &serde_json::Value,
    display: &str,
    length_exempt: bool,
    out: &mut Vec<Candidate>,
) {
    match value {
        serde_json::Value::String(s) => {
            out.push(Candidate::prunable(
                s.clone(),
                format!("{display} (json)"),
                length_exempt,
            ));
        }
        serde_json::Value::Array(items) => {
            for item in items {
                collect_json_strings(item, display, length_exempt, out);
            }
        }
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                collect_json_strings(v, display, length_exempt || credential_shaped_key(k), out);
            }
        }
        _ => {}
    }
}

/// Recursively collect every leaf string scalar in a TOML document. Table
/// keys are never collected; a value on a line bearing the §5 marker is
/// excluded via `marked`.
pub(super) fn collect_toml_strings(
    value: &toml::Value,
    display: &str,
    marked: &mut HashMap<String, usize>,
    length_exempt: bool,
    out: &mut Vec<Candidate>,
) {
    match value {
        toml::Value::String(s) => {
            if !consume_marked_value(marked, s) {
                out.push(Candidate::prunable(
                    s.clone(),
                    format!("{display} (toml)"),
                    length_exempt,
                ));
            }
        }
        toml::Value::Array(items) => {
            for item in items {
                collect_toml_strings(item, display, marked, length_exempt, out);
            }
        }
        toml::Value::Table(table) => {
            for (k, v) in table {
                collect_toml_strings(
                    v,
                    display,
                    marked,
                    length_exempt || credential_shaped_key(k),
                    out,
                );
            }
        }
        _ => {}
    }
}

/// Recursively collect every leaf string scalar in a YAML document. Map
/// keys are never collected; a value on a line bearing the §5 marker is
/// excluded via `marked`.
pub(super) fn collect_yaml_strings(
    value: &serde_yaml::Value,
    display: &str,
    marked: &mut HashMap<String, usize>,
    length_exempt: bool,
    out: &mut Vec<Candidate>,
) {
    match value {
        serde_yaml::Value::String(s) => {
            if !consume_marked_value(marked, s) {
                out.push(Candidate::prunable(
                    s.clone(),
                    format!("{display} (yaml)"),
                    length_exempt,
                ));
            }
        }
        serde_yaml::Value::Sequence(items) => {
            for item in items {
                collect_yaml_strings(item, display, marked, length_exempt, out);
            }
        }
        serde_yaml::Value::Mapping(map) => {
            for (k, v) in map {
                let key_exempt = k.as_str().map(credential_shaped_key).unwrap_or(false);
                collect_yaml_strings(v, display, marked, length_exempt || key_exempt, out);
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
