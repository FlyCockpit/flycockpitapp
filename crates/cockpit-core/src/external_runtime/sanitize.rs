//! Bounded, redacted version-evidence normalization.

use std::path::{Component, Path};

use super::schema::VERSION_EVIDENCE_BUDGET;

const REDACTED: &str = "[redacted]";

/// Normalize combined probe stdout/stderr into a single sanitized evidence line.
///
/// - Strips control characters
/// - Collapses whitespace to a single line
/// - Redacts absolute/relative path tokens that are not the resolved executable basename
/// - Redacts secret-shaped tokens (key=value, Bearer, sk-*, long hex/base64 blobs)
/// - Caps at [`VERSION_EVIDENCE_BUDGET`] bytes (UTF-8 safe truncation)
pub fn sanitize_version_evidence(
    combined_output: &str,
    resolved_executable: Option<&Path>,
) -> String {
    let basename = resolved_executable
        .and_then(|p| p.file_name())
        .and_then(|n| n.to_str())
        .unwrap_or("");

    let mut cleaned = String::with_capacity(combined_output.len().min(VERSION_EVIDENCE_BUDGET));
    for ch in combined_output.chars() {
        if ch == '\n' || ch == '\r' || ch == '\t' {
            cleaned.push(' ');
        } else if ch.is_control() {
            // drop control characters
        } else {
            cleaned.push(ch);
        }
    }

    let mut tokens: Vec<String> = Vec::new();
    let mut redact_next = false;
    for raw in cleaned.split_whitespace() {
        if redact_next {
            tokens.push(REDACTED.to_string());
            redact_next = false;
            continue;
        }
        // "Bearer <token>" is two whitespace tokens after normalization.
        if raw.eq_ignore_ascii_case("bearer") {
            tokens.push(REDACTED.to_string());
            redact_next = true;
            continue;
        }
        tokens.push(sanitize_token(raw, basename));
    }
    let mut line = tokens.join(" ");
    if line.len() > VERSION_EVIDENCE_BUDGET {
        line = truncate_utf8(&line, VERSION_EVIDENCE_BUDGET);
    }
    line
}

fn sanitize_token(token: &str, allowed_basename: &str) -> String {
    if looks_like_secret_token(token) {
        return REDACTED.to_string();
    }
    // key=value: redact secret-shaped keys; also scrub path-shaped values.
    if let Some((key, value)) = token.split_once('=') {
        if crate::redact::is_secret_shaped_key(key) {
            return format!("{key}={REDACTED}");
        }
        if looks_like_path(value) {
            return format!("{key}={REDACTED}");
        }
    }
    if looks_like_path(token) {
        let path = Path::new(token);
        if let Some(name) = path.file_name().and_then(|n| n.to_str())
            && name == allowed_basename
            && !allowed_basename.is_empty()
        {
            // Keep only the basename for the resolved executable.
            return name.to_string();
        }
        return REDACTED.to_string();
    }
    token.to_string()
}

fn looks_like_path(token: &str) -> bool {
    if token.is_empty() {
        return false;
    }
    if token.starts_with('/') || token.starts_with("./") || token.starts_with("../") {
        return true;
    }
    if token.contains("://") {
        // URLs are not local paths; leave for secret heuristics only.
        return false;
    }
    if token.len() >= 3
        && token.as_bytes()[0].is_ascii_alphabetic()
        && token.as_bytes()[1] == b':'
        && (token.as_bytes()[2] == b'\\' || token.as_bytes()[2] == b'/')
    {
        return true; // Windows drive path
    }
    if token.contains('\\') {
        return true;
    }
    // Multi-component path, including absolute forms with RootDir.
    let path = Path::new(token);
    let components: Vec<_> = path.components().collect();
    if components.len() <= 1 {
        return false;
    }
    components.iter().all(|c| {
        matches!(
            c,
            Component::Normal(_)
                | Component::CurDir
                | Component::ParentDir
                | Component::RootDir
                | Component::Prefix(_)
        )
    })
}

fn looks_like_secret_token(token: &str) -> bool {
    let lower = token.to_ascii_lowercase();
    if lower.starts_with("bearer") && token.len() > 6 {
        // "Bearerxyz" or "bearer:token" collapsed forms.
        return true;
    }
    if lower.starts_with("sk-") && token.len() >= 20 {
        return true;
    }
    if lower.starts_with("ghp_") || lower.starts_with("gho_") || lower.starts_with("github_pat_") {
        return true;
    }
    // long hex
    if token.len() >= 32 && token.chars().all(|c| c.is_ascii_hexdigit()) {
        return true;
    }
    // long base64-ish
    if token.len() >= 40
        && token.chars().all(|c| {
            c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=' || c == '-' || c == '_'
        })
    {
        // Avoid redacting normal version strings like 1.2.3-alpha
        if token.contains('.') && token.chars().filter(|c| c.is_ascii_digit()).count() >= 2 {
            return false;
        }
        return true;
    }
    false
}

fn truncate_utf8(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s.to_string();
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

#[cfg(test)]
mod unit_tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn strips_controls_and_paths_keeps_basename() {
        let out = "version\x01 1.2.3 from /usr/local/bin/rg path=/home/u/secret config=/home/alice/.config";
        let cleaned = sanitize_version_evidence(out, Some(Path::new("/usr/local/bin/rg")));
        assert!(cleaned.contains("1.2.3"));
        assert!(cleaned.contains("rg"));
        assert!(!cleaned.contains("/usr/local/bin"));
        assert!(!cleaned.contains("/home/u/secret"));
        assert!(!cleaned.contains("/home/alice"));
        assert!(cleaned.contains(REDACTED));
    }
}
