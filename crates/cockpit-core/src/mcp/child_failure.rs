//! Typed, sanitized MCP stdio child failure diagnostics.
//!
//! Parent classification depends only on whether a Monty exception escapes
//! the script. Child spawn/timeout/transport/exit/cancel failures are typed
//! here so durable child rows and catchable Monty exceptions carry stage,
//! cause, and optional exit evidence — without args, env, sealed values,
//! cwd, or unbounded stderr.

use std::fmt;

/// Lifecycle stage of a stdio MCP child failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    Spawn,
    Timeout,
    Transport,
    Exit,
    Cancel,
}

impl Stage {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Spawn => "spawn",
            Self::Timeout => "timeout",
            Self::Transport => "transport",
            Self::Exit => "exit",
            Self::Cancel => "cancel",
        }
    }
}

impl fmt::Display for Stage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Optional process-exit evidence. Codes/signals only — never stderr bodies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitEvidence {
    pub code: Option<i32>,
    pub signal: Option<String>,
}

/// Bounded, sanitized child failure diagnostic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChildFailure {
    pub stage: Stage,
    pub server: String,
    pub cause: String,
    pub exit: Option<ExitEvidence>,
}

impl ChildFailure {
    pub fn new(
        stage: Stage,
        server: impl Into<String>,
        cause: impl Into<String>,
        exit: Option<ExitEvidence>,
    ) -> Self {
        Self {
            stage,
            server: server.into(),
            cause: sanitize_cause(cause.into()),
            exit,
        }
    }

    pub fn spawn(server: impl Into<String>, cause: impl Into<String>) -> Self {
        Self::new(Stage::Spawn, server, cause, None)
    }

    pub fn timeout(server: impl Into<String>, cause: impl Into<String>) -> Self {
        Self::new(Stage::Timeout, server, cause, None)
    }

    pub fn transport(server: impl Into<String>, cause: impl Into<String>) -> Self {
        Self::new(Stage::Transport, server, cause, None)
    }

    pub fn cancel(server: impl Into<String>, cause: impl Into<String>) -> Self {
        Self::new(Stage::Cancel, server, cause, None)
    }

    pub fn exit(server: impl Into<String>, cause: impl Into<String>, exit: ExitEvidence) -> Self {
        Self::new(Stage::Exit, server, cause, Some(exit))
    }

    /// Stable single-line diagnostic for child rows and Monty exceptions.
    pub fn render(&self) -> String {
        let mut out = format!(
            "mcp child failure: stage={} server=`{}` cause={}",
            self.stage, self.server, self.cause
        );
        if let Some(exit) = &self.exit {
            if let Some(code) = exit.code {
                out.push_str(&format!(" exit_code={code}"));
            }
            if let Some(signal) = &exit.signal {
                out.push_str(&format!(" signal={signal}"));
            }
        }
        out
    }
}

impl fmt::Display for ChildFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.render())
    }
}

impl std::error::Error for ChildFailure {}

/// Cap free-form cause text so diagnostics stay bounded and secret-safe.
///
/// Strips control characters, redacts obvious `KEY=value` / `key: value`
/// credential-like fragments, and truncates length. Diagnostics must never
/// carry environment or sealed values into child rows or model text.
fn sanitize_cause(raw: String) -> String {
    const CAP: usize = 160;
    let mut cleaned = String::with_capacity(raw.len().min(CAP));
    for ch in raw.chars() {
        if cleaned.len() >= CAP {
            cleaned.push('~');
            break;
        }
        if ch.is_control() {
            cleaned.push(' ');
        } else {
            cleaned.push(ch);
        }
    }
    // Redact KEY=value and key: value fragments (case-insensitive keys that look
    // like credentials / environment assignments).
    let mut redacted = String::with_capacity(cleaned.len());
    for token in cleaned.split_whitespace() {
        let lower = token.to_ascii_lowercase();
        let is_assign = token.contains('=')
            || (token.contains(':') && !token.starts_with("http") && !token.starts_with("stage"));
        let looks_secret = [
            "secret",
            "password",
            "passwd",
            "token",
            "api_key",
            "apikey",
            "auth",
            "credential",
            "private",
            "bearer",
        ]
        .iter()
        .any(|needle| lower.contains(needle));
        if is_assign && looks_secret {
            // Keep key side only when present.
            if let Some((key, _)) = token.split_once('=') {
                redacted.push_str(key);
                redacted.push_str("=[redacted]");
            } else if let Some((key, _)) = token.split_once(':') {
                redacted.push_str(key);
                redacted.push_str(":[redacted]");
            } else {
                redacted.push_str("[redacted]");
            }
        } else if is_assign && token.contains('=') {
            // Generic ENV=value style — redact the value half.
            if let Some((key, _)) = token.split_once('=') {
                redacted.push_str(key);
                redacted.push_str("=[redacted]");
            } else {
                redacted.push_str("[redacted]");
            }
        } else {
            redacted.push_str(token);
        }
        redacted.push(' ');
    }
    let trimmed = redacted.split_whitespace().collect::<Vec<_>>().join(" ");
    if trimmed.is_empty() {
        "unspecified".into()
    } else {
        // Cap by Unicode scalar count so `len()` stays within CAP bytes for ASCII
        // diagnostics (our producers emit ASCII). Use a single ASCII ellipsis.
        let mut out = String::new();
        for ch in trimmed.chars() {
            if out.len() + ch.len_utf8() > CAP {
                if out.len() < CAP {
                    out.push('~');
                }
                break;
            }
            out.push(ch);
        }
        out
    }
}

/// Map a raw OS exit status into sanitized exit evidence.
pub fn exit_evidence_from_status(status: std::process::ExitStatus) -> ExitEvidence {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(signal) = status.signal() {
            return ExitEvidence {
                code: None,
                signal: Some(signal_name(signal).to_string()),
            };
        }
    }
    ExitEvidence {
        code: status.code(),
        signal: None,
    }
}

#[cfg(unix)]
fn signal_name(signal: i32) -> &'static str {
    match signal {
        1 => "SIGHUP",
        2 => "SIGINT",
        3 => "SIGQUIT",
        6 => "SIGABRT",
        9 => "SIGKILL",
        15 => "SIGTERM",
        _ => "SIGNAL",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_includes_stage_cause_and_exit_without_secrets() {
        let failure = ChildFailure::exit(
            "fake",
            "nonzero_status\nSECRET=s3cret\t",
            ExitEvidence {
                code: Some(7),
                signal: None,
            },
        );
        let rendered = failure.render();
        assert!(rendered.contains("stage=exit"), "{rendered}");
        assert!(rendered.contains("server=`fake`"), "{rendered}");
        assert!(rendered.contains("cause=nonzero_status"), "{rendered}");
        assert!(
            !rendered.contains("s3cret"),
            "diagnostics must not leak secret values: {rendered}"
        );
        assert!(
            rendered.contains("SECRET=[redacted]") || rendered.contains("[redacted]"),
            "secret assignment must be redacted: {rendered}"
        );
        assert!(rendered.contains("exit_code=7"), "{rendered}");
        assert!(!rendered.contains('\n'), "{rendered}");
    }

    #[test]
    fn cause_is_bounded() {
        let long = "x".repeat(400);
        let failure = ChildFailure::spawn("srv", long);
        assert!(
            failure.cause.len() <= 160,
            "cause len {} > CAP: {}",
            failure.cause.len(),
            failure.cause
        );
    }
}
