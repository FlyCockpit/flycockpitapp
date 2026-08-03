//! Path-only classification for files that commonly carry credentials.
//!
//! This module intentionally does not inspect the filesystem. Callers decide
//! whether a read is authorized; after an approved read they can pass the path
//! to redaction for parsed-value registration.

use std::path::{Path, PathBuf};

use globset::{GlobBuilder, GlobSet, GlobSetBuilder};

const BUILTIN_PATTERNS: &[&str] = &[
    ".env*",
    "**/.env*",
    "*.pem",
    "**/*.pem",
    "*.key",
    "**/*.key",
    "id_rsa*",
    "**/id_rsa*",
    "id_ed25519*",
    "**/id_ed25519*",
    "credentials",
    "**/credentials",
    "*.tfvars",
    "**/*.tfvars",
    ".npmrc",
    "**/.npmrc",
    ".netrc",
    "**/.netrc",
];
const SECRET_DIRECTORIES: &[&str] = &[".ssh", ".aws", ".gnupg"];

#[derive(Debug, Clone)]
pub struct SecretPathMatcher {
    globs: GlobSet,
}

impl SecretPathMatcher {
    pub fn from_redact_config(cfg: &crate::config::extended::RedactConfig) -> Self {
        Self::new(&cfg.secret_path_patterns)
    }

    /// Built-ins plus additive user patterns. Invalid user patterns are ignored:
    /// configuration must not weaken the built-in floor.
    pub fn new(user_patterns: &[String]) -> Self {
        let mut builder = GlobSetBuilder::new();
        for pattern in BUILTIN_PATTERNS
            .iter()
            .copied()
            .chain(user_patterns.iter().map(String::as_str))
        {
            if let Ok(glob) = GlobBuilder::new(pattern)
                .case_insensitive(cfg!(windows))
                .build()
            {
                builder.add(glob);
            }
        }
        Self {
            globs: builder
                .build()
                .expect("built-in secret path globs are valid"),
        }
    }

    pub fn is_secret_path(&self, path: &Path) -> bool {
        let normalized = normalized(path);
        self.globs.is_match(&normalized)
            || normalized.components().any(|component| {
                component.as_os_str().to_str().is_some_and(|name| {
                    SECRET_DIRECTORIES
                        .iter()
                        .any(|dir| name.eq_ignore_ascii_case(dir))
                })
            })
    }
}
impl Default for SecretPathMatcher {
    fn default() -> Self {
        Self::new(&[])
    }
}
fn normalized(path: &Path) -> PathBuf {
    PathBuf::from(path.to_string_lossy().replace(char::from(92), "/"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn builtin_patterns_cover_known_gaps() {
        let matcher = SecretPathMatcher::default();
        assert!(matcher.is_secret_path(Path::new(".env.production")));
        assert!(matcher.is_secret_path(Path::new("terraform.tfvars")));
    }
    #[test]
    fn directory_patterns_imply_contents() {
        assert!(SecretPathMatcher::default().is_secret_path(Path::new("work/.ssh/id_rsa")));
    }
    #[test]
    fn user_patterns_extend_builtins() {
        let matcher = SecretPathMatcher::new(&["vault/*.token".to_string()]);
        assert!(matcher.is_secret_path(Path::new("vault/app.token")));
        assert!(matcher.is_secret_path(Path::new(".env.local")));
    }
    #[test]
    fn redact_config_patterns_extend_builtins() {
        let cfg = crate::config::extended::RedactConfig {
            secret_path_patterns: vec!["vault/**/*.token".to_string()],
            ..Default::default()
        };
        let matcher = SecretPathMatcher::from_redact_config(&cfg);
        assert!(matcher.is_secret_path(Path::new("vault/app.token")));
        assert!(matcher.is_secret_path(Path::new(".env.local")));
    }
}

#[cfg(test)]
mod no_filesystem_tests {
    use super::*;
    #[test]
    fn construction_and_matching_do_not_require_the_path_to_exist() {
        let matcher = SecretPathMatcher::new(&["unreadable/*.secret".to_string()]);
        assert!(matcher.is_secret_path(Path::new("unreadable/missing.secret")));
    }
}
