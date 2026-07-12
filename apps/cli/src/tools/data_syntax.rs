use std::path::{Component, Path};

use serde::Deserialize as _;

use crate::config::extended::DataSyntaxConfig;

const INVALID_TRAILER: &str =
    "The file was written exactly as given; if this was unintended, fix it and rewrite.";

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

pub fn data_syntax_note(path: &Path, content: &str, config: &DataSyntaxConfig) -> Option<String> {
    if !config.enabled || content.len() > config.max_bytes {
        return None;
    }
    let format = detect_format(path)?;
    match format {
        DataFormat::Json => Some(validate_json(content)),
        DataFormat::Jsonc => Some(validate_jsonc(content)),
        DataFormat::Ndjson => Some(validate_ndjson(content)),
        DataFormat::Yaml => Some(validate_yaml(content)),
        DataFormat::Toml => Some(validate_toml(content)),
        DataFormat::Csv => validate_delimited(content, b',', DataFormat::Csv),
        DataFormat::Tsv => validate_delimited(content, b'\t', DataFormat::Tsv),
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

fn validate_json(content: &str) -> String {
    match serde_json::from_str::<serde_json::Value>(content) {
        Ok(_) => "\nsyntax OK (JSON)".to_string(),
        Err(error) => invalid_note(DataFormat::Json, error.to_string()),
    }
}

fn validate_jsonc(content: &str) -> String {
    match jsonc_parser::parse_to_value(content, &jsonc_parser::ParseOptions::default()) {
        Ok(_) => "\nsyntax OK (JSONC)".to_string(),
        Err(error) => invalid_note(DataFormat::Jsonc, error.to_string()),
    }
}

fn validate_ndjson(content: &str) -> String {
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
        invalid_note(DataFormat::Ndjson, errors.join("; "))
    }
}

fn validate_yaml(content: &str) -> String {
    let mut documents = 0usize;
    for document in serde_yaml::Deserializer::from_str(content) {
        match serde_yaml::Value::deserialize(document) {
            Ok(_) => documents += 1,
            Err(error) => return invalid_note(DataFormat::Yaml, error.to_string()),
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

fn validate_toml(content: &str) -> String {
    match toml::from_str::<toml::Value>(content) {
        Ok(_) => "\nsyntax OK (TOML)".to_string(),
        Err(error) => invalid_note(DataFormat::Toml, error.to_string()),
    }
}

fn validate_delimited(content: &str, delimiter: u8, format: DataFormat) -> Option<String> {
    let mut reader = csv::ReaderBuilder::new()
        .has_headers(false)
        .flexible(false)
        .delimiter(delimiter)
        .from_reader(content.as_bytes());
    for result in reader.records() {
        if let Err(error) = result {
            return Some(invalid_note(format, csv_error_message(&error)));
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

fn invalid_note(format: DataFormat, detail: String) -> String {
    format!(
        "\nwarning: content is not valid {} — {}. {}",
        format.label(),
        detail.trim_end_matches('.'),
        INVALID_TRAILER
    )
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
            data_syntax_note(Path::new("a.JSON"), "{}", &cfg()).unwrap(),
            "\nsyntax OK (JSON)"
        );
        let note = data_syntax_note(Path::new("a.json"), "{", &cfg()).unwrap();
        assert!(note.contains("warning: content is not valid JSON"));
        assert!(note.contains("line 1 column"));
    }

    #[test]
    fn jsonc_comments_and_errors() {
        let ok =
            data_syntax_note(Path::new("tsconfig.json"), "{ // c\n \"x\": 1,\n}", &cfg()).unwrap();
        assert_eq!(ok, "\nsyntax OK (JSONC)");
        let plain =
            data_syntax_note(Path::new("foo.json"), "{ // c\n \"x\": 1\n}", &cfg()).unwrap();
        assert!(plain.contains("warning: content is not valid JSON"));
        let bad = data_syntax_note(Path::new("foo.jsonc"), "{ \"x\": ", &cfg()).unwrap();
        assert!(bad.contains("warning: content is not valid JSONC"));
    }

    #[test]
    fn ndjson_counts_and_reports_lines() {
        let ok = data_syntax_note(Path::new("a.ndjson"), "{}\n\n{\"a\":1}\n[]\n", &cfg()).unwrap();
        assert_eq!(ok, "\nsyntax OK (NDJSON, 3 lines)");
        let bad = data_syntax_note(Path::new("a.jsonl"), "{}\n{\n[]\n", &cfg()).unwrap();
        assert!(bad.contains("line 2:"));
    }

    #[test]
    fn yaml_documents_and_failure() {
        let ok = data_syntax_note(Path::new("a.yaml"), "---\na: 1\n---\nb: 2\n", &cfg()).unwrap();
        assert_eq!(ok, "\nparses as YAML (2 documents)");
        let bad = data_syntax_note(Path::new("a.yml"), "a: [1\n", &cfg()).unwrap();
        assert!(bad.contains("warning: content is not valid YAML"));
    }

    #[test]
    fn toml_success_and_failure() {
        assert_eq!(
            data_syntax_note(Path::new("a.toml"), "a = 1", &cfg()).unwrap(),
            "\nsyntax OK (TOML)"
        );
        let bad = data_syntax_note(Path::new("a.toml"), "a = ", &cfg()).unwrap();
        assert!(bad.contains("warning: content is not valid TOML"));
    }

    #[test]
    fn csv_warns_only_on_errors() {
        assert!(data_syntax_note(Path::new("a.csv"), "a,b\nc,d\n", &cfg()).is_none());
        let bad = data_syntax_note(Path::new("a.csv"), "a,b\nc\n", &cfg()).unwrap();
        assert!(bad.contains("row 2 has 1 fields; earlier rows have 2"));
    }

    #[test]
    fn unknown_disabled_and_oversize_are_silent() {
        assert!(data_syntax_note(Path::new("a.rs"), "{", &cfg()).is_none());
        assert!(data_syntax_note(Path::new("Makefile"), "{", &cfg()).is_none());
        let mut disabled = cfg();
        disabled.enabled = false;
        assert!(data_syntax_note(Path::new("a.json"), "{}", &disabled).is_none());
        let mut tiny = cfg();
        tiny.max_bytes = 1;
        assert!(data_syntax_note(Path::new("a.json"), "{}", &tiny).is_none());
    }
}
