use std::path::{Component, Path};

use serde::Deserialize as _;

use crate::config::extended::DataSyntaxConfig;

const INVALID_TRAILER: &str =
    "The file was written exactly as given; if this was unintended, fix it and rewrite.";
const MAX_DETAIL_CHARS: usize = 500;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DataFormat {
    Json,
    Jsonc,
    Ndjson,
    Yaml,
    Toml,
    Csv,
    Tsv,
}

impl DataFormat {
    fn label(self) -> &'static str {
        match self {
            Self::Json => "JSON",
            Self::Jsonc => "JSONC",
            Self::Ndjson => "NDJSON",
            Self::Yaml => "YAML",
            Self::Toml => "TOML",
            Self::Csv => "CSV",
            Self::Tsv => "TSV",
        }
    }
}

pub fn data_syntax_note(
    redact: &crate::redact::RedactionTable,
    path: &Path,
    content: &str,
    config: &DataSyntaxConfig,
) -> Option<String> {
    if !config.enabled || content.len() > config.max_bytes {
        return None;
    }
    let format = detect_format(path)?;
    match format {
        DataFormat::Json => Some(validate_json(redact, content)),
        DataFormat::Jsonc => Some(validate_jsonc(redact, content)),
        DataFormat::Ndjson => Some(validate_ndjson(redact, content)),
        DataFormat::Yaml => Some(validate_yaml(redact, content)),
        DataFormat::Toml => Some(validate_toml(redact, content)),
        DataFormat::Csv => validate_delimited(redact, content, b',', DataFormat::Csv),
        DataFormat::Tsv => validate_delimited(redact, content, b'\t', DataFormat::Tsv),
    }
}

fn detect_format(path: &Path) -> Option<DataFormat> {
    let file_name = path.file_name()?.to_string_lossy().to_ascii_lowercase();
    let extension = path
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext.to_ascii_lowercase());

    if file_name == "tsconfig.json" || file_name == "jsconfig.json" || is_vscode_json(path) {
        return Some(DataFormat::Jsonc);
    }

    match extension.as_deref()? {
        "json" => Some(DataFormat::Json),
        "jsonc" => Some(DataFormat::Jsonc),
        "ndjson" | "jsonl" => Some(DataFormat::Ndjson),
        "yaml" | "yml" => Some(DataFormat::Yaml),
        "toml" => Some(DataFormat::Toml),
        "csv" => Some(DataFormat::Csv),
        "tsv" => Some(DataFormat::Tsv),
        _ => None,
    }
}

fn is_vscode_json(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case("json"))
        && path.components().any(|component| match component {
            Component::Normal(part) => part.to_string_lossy().eq_ignore_ascii_case(".vscode"),
            _ => false,
        })
}

fn validate_json(redact: &crate::redact::RedactionTable, content: &str) -> String {
    match serde_json::from_str::<serde_json::Value>(content) {
        Ok(_) => "\nsyntax OK (JSON)".to_string(),
        Err(error) => invalid_note(redact, DataFormat::Json, error.to_string()),
    }
}

fn validate_jsonc(redact: &crate::redact::RedactionTable, content: &str) -> String {
    match jsonc_parser::parse_to_value(content, &jsonc_parser::ParseOptions::default()) {
        Ok(_) => "\nsyntax OK (JSONC)".to_string(),
        Err(error) => invalid_note(redact, DataFormat::Jsonc, error.to_string()),
    }
}

fn validate_ndjson(redact: &crate::redact::RedactionTable, content: &str) -> String {
    let mut valid_lines = 0usize;
    let mut errors = Vec::new();
    for (idx, line) in content.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<serde_json::Value>(line) {
            Ok(_) => valid_lines += 1,
            Err(error) if errors.len() < 3 => {
                errors.push(format!("line {}: {error}", idx + 1));
            }
            Err(_) => {}
        }
    }
    if errors.is_empty() {
        format!("\nsyntax OK (NDJSON, {valid_lines} lines)")
    } else {
        invalid_note(redact, DataFormat::Ndjson, errors.join("; "))
    }
}

fn validate_yaml(redact: &crate::redact::RedactionTable, content: &str) -> String {
    let mut documents = 0usize;
    for document in serde_yaml::Deserializer::from_str(content) {
        match serde_yaml::Value::deserialize(document) {
            Ok(_) => documents += 1,
            Err(error) => return invalid_note(redact, DataFormat::Yaml, error.to_string()),
        }
    }
    if documents == 0 {
        documents = 1;
    }
    let noun = if documents == 1 {
        "document"
    } else {
        "documents"
    };
    format!("\nparses as YAML ({documents} {noun})")
}

fn validate_toml(redact: &crate::redact::RedactionTable, content: &str) -> String {
    match toml::from_str::<toml::Value>(content) {
        Ok(_) => "\nsyntax OK (TOML)".to_string(),
        Err(error) => invalid_note(redact, DataFormat::Toml, error.to_string()),
    }
}

fn validate_delimited(
    redact: &crate::redact::RedactionTable,
    content: &str,
    delimiter: u8,
    format: DataFormat,
) -> Option<String> {
    let mut reader = csv::ReaderBuilder::new()
        .has_headers(false)
        .flexible(false)
        .delimiter(delimiter)
        .from_reader(content.as_bytes());
    for result in reader.records() {
        if let Err(error) = result {
            return Some(invalid_note(redact, format, csv_error_message(&error)));
        }
    }
    None
}

fn csv_error_message(error: &csv::Error) -> String {
    match error.kind() {
        csv::ErrorKind::UnequalLengths {
            pos,
            expected_len,
            len,
        } => {
            let row = pos.as_ref().map(|pos| pos.line()).unwrap_or(0);
            format!("row {row} has {len} fields; earlier rows have {expected_len}")
        }
        _ => error.to_string(),
    }
}

fn invalid_note(
    redact: &crate::redact::RedactionTable,
    format: DataFormat,
    detail: String,
) -> String {
    let detail = truncate_detail(redact, detail);
    format!(
        "\nwarning: content is not valid {} — {}. {}",
        format.label(),
        detail.trim_end_matches('.'),
        INVALID_TRAILER
    )
}

fn truncate_detail(redact: &crate::redact::RedactionTable, detail: String) -> String {
    if detail.chars().count() <= MAX_DETAIL_CHARS {
        return detail;
    }

    let kept: String = detail.chars().take(MAX_DETAIL_CHARS).collect();
    // The cut keeps a head and drops the tail: a parser detail quoting file
    // content could straddle a registered secret here, leaving only its
    // PREFIX — past what the downstream whole-value scrub can match. Elide
    // the retained head's back margin before appending the ellipsis
    // (no-op for an empty table). Issue #294.
    let safe = crate::tools::common::drop_back_margin(redact, &kept);
    format!("{safe}…")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> DataSyntaxConfig {
        DataSyntaxConfig::default()
    }

    #[test]
    fn detects_jsonc_special_cases() {
        assert_eq!(
            detect_format(Path::new("tsconfig.json")),
            Some(DataFormat::Jsonc)
        );
        assert_eq!(
            detect_format(Path::new("a/.vscode/settings.json")),
            Some(DataFormat::Jsonc)
        );
        assert_eq!(detect_format(Path::new("foo.json")), Some(DataFormat::Json));
    }

    #[test]
    fn json_success_and_failure() {
        assert_eq!(
            data_syntax_note(
                &crate::redact::RedactionTable::empty(),
                Path::new("a.JSON"),
                "{}",
                &cfg()
            )
            .unwrap(),
            "\nsyntax OK (JSON)"
        );
        let note = data_syntax_note(
            &crate::redact::RedactionTable::empty(),
            Path::new("a.json"),
            "{",
            &cfg(),
        )
        .unwrap();
        assert!(note.contains("warning: content is not valid JSON"));
        assert!(note.contains("line 1 column"));
    }

    #[test]
    fn jsonc_comments_and_errors() {
        let ok = data_syntax_note(
            &crate::redact::RedactionTable::empty(),
            Path::new("tsconfig.json"),
            "{ // c\n \"x\": 1,\n}",
            &cfg(),
        )
        .unwrap();
        assert_eq!(ok, "\nsyntax OK (JSONC)");
        let plain = data_syntax_note(
            &crate::redact::RedactionTable::empty(),
            Path::new("foo.json"),
            "{ // c\n \"x\": 1\n}",
            &cfg(),
        )
        .unwrap();
        assert!(plain.contains("warning: content is not valid JSON"));
        let bad = data_syntax_note(
            &crate::redact::RedactionTable::empty(),
            Path::new("foo.jsonc"),
            "{ \"x\": ",
            &cfg(),
        )
        .unwrap();
        assert!(bad.contains("warning: content is not valid JSONC"));
        assert!(bad.contains("line"));
        assert!(bad.contains("column"));
    }

    #[test]
    fn ndjson_counts_and_reports_lines() {
        let ok = data_syntax_note(
            &crate::redact::RedactionTable::empty(),
            Path::new("a.ndjson"),
            "{}\n\n{\"a\":1}\n[]\n",
            &cfg(),
        )
        .unwrap();
        assert_eq!(ok, "\nsyntax OK (NDJSON, 3 lines)");
        let bad = data_syntax_note(
            &crate::redact::RedactionTable::empty(),
            Path::new("a.jsonl"),
            "{}\n{\n[]\n",
            &cfg(),
        )
        .unwrap();
        assert!(bad.contains("line 2:"));
    }

    #[test]
    fn yaml_documents_and_failure() {
        let ok = data_syntax_note(
            &crate::redact::RedactionTable::empty(),
            Path::new("a.yaml"),
            "---\na: 1\n---\nb: 2\n",
            &cfg(),
        )
        .unwrap();
        assert_eq!(ok, "\nparses as YAML (2 documents)");
        let bad = data_syntax_note(
            &crate::redact::RedactionTable::empty(),
            Path::new("a.yml"),
            "a: [1\n",
            &cfg(),
        )
        .unwrap();
        assert!(bad.contains("warning: content is not valid YAML"));
    }

    #[test]
    fn toml_success_and_failure() {
        assert_eq!(
            data_syntax_note(
                &crate::redact::RedactionTable::empty(),
                Path::new("a.toml"),
                "a = 1",
                &cfg()
            )
            .unwrap(),
            "\nsyntax OK (TOML)"
        );
        let bad = data_syntax_note(
            &crate::redact::RedactionTable::empty(),
            Path::new("a.toml"),
            "a = ",
            &cfg(),
        )
        .unwrap();
        assert!(bad.contains("warning: content is not valid TOML"));
    }

    #[test]
    fn invalid_note_truncates_long_parser_details() {
        let detail = "x".repeat(MAX_DETAIL_CHARS + 10);
        let note = invalid_note(
            &crate::redact::RedactionTable::empty(),
            DataFormat::Toml,
            detail,
        );
        let capped = format!("{}…", "x".repeat(MAX_DETAIL_CHARS));

        assert!(note.contains(&capped));
        assert!(note.contains(INVALID_TRAILER));
        assert_eq!(
            note.chars().count(),
            "\nwarning: content is not valid TOML — ".chars().count()
                + capped.chars().count()
                + ". ".chars().count()
                + INVALID_TRAILER.chars().count()
        );
    }

    #[test]
    fn invalid_note_does_not_truncate_short_parser_details() {
        let note = invalid_note(
            &crate::redact::RedactionTable::empty(),
            DataFormat::Json,
            "short parser detail".to_string(),
        );

        assert!(note.contains("short parser detail"));
        assert!(!note.contains('…'));
    }

    #[test]
    fn invalid_note_truncates_on_char_boundaries() {
        let detail = "世".repeat(MAX_DETAIL_CHARS + 1);
        let note = invalid_note(DataFormat::Yaml, detail);
        let capped = format!("{}…", "世".repeat(MAX_DETAIL_CHARS));

        assert!(note.contains(&capped));
        assert!(note.is_char_boundary(note.len()));
    }

    #[test]
    fn csv_warns_only_on_errors() {
        assert!(
            data_syntax_note(
                &crate::redact::RedactionTable::empty(),
                Path::new("a.csv"),
                "a,b\nc,d\n",
                &cfg()
            )
            .is_none()
        );
        let bad = data_syntax_note(
            &crate::redact::RedactionTable::empty(),
            Path::new("a.csv"),
            "a,b\nc\n",
            &cfg(),
        )
        .unwrap();
        assert!(bad.contains("row 2 has 1 fields; earlier rows have 2"));
    }

    #[test]
    fn unknown_disabled_and_oversize_are_silent() {
        assert!(
            data_syntax_note(
                &crate::redact::RedactionTable::empty(),
                Path::new("a.rs"),
                "{",
                &cfg()
            )
            .is_none()
        );
        assert!(
            data_syntax_note(
                &crate::redact::RedactionTable::empty(),
                Path::new("Makefile"),
                "{",
                &cfg()
            )
            .is_none()
        );
        let mut disabled = cfg();
        disabled.enabled = false;
        assert!(
            data_syntax_note(
                &crate::redact::RedactionTable::empty(),
                Path::new("a.json"),
                "{}",
                &disabled
            )
            .is_none()
        );
        let mut tiny = cfg();
        tiny.max_bytes = 1;
        assert!(
            data_syntax_note(
                &crate::redact::RedactionTable::empty(),
                Path::new("a.json"),
                "{}",
                &tiny
            )
            .is_none()
        );
    }
    // A parser detail quoting file content can straddle a registered secret
    // at the detail cap; the cut must elide the retained head's back margin
    // so no partial survives into the tool note (issue #294).
    #[test]
    fn truncate_detail_elides_back_margin_of_straddling_secret() {
        const SECRET: &str = "sk-live-DATASYNTAX-0123456789abcd"; // 33 bytes
        let table = crate::redact::RedactionTable::empty()
            .with_forced_literal(SECRET.to_string(), "$leak:datasyntax".to_string())
            .unwrap();
        // Cut at MAX_DETAIL_CHARS (500) with the secret starting at 490: a
        // boundary-blind cut keeps 10 of its 33 bytes.
        let detail = format!("{}{SECRET}{}", "d".repeat(490), "e".repeat(300));
        let truncated = truncate_detail(&table, detail);
        let scrubbed = table.scrub(&truncated);
        assert!(
            !scrubbed.contains("sk-live-DATASYNTAX"),
            "straddling prefix leaked into the data-syntax note: {scrubbed}"
        );
        assert!(!scrubbed.contains("0123456789abcd"));
    }
}
