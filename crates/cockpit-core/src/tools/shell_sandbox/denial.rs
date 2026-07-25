use std::path::{Component, Path, PathBuf};

use crate::tools::shell_sandbox::SandboxPolicy;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SandboxDenialConfidence {
    High,
    Possible,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DenialEvidence {
    WriteOutsideAllowlist { path: PathBuf },
    ReadOutsideAllowlist { path: PathBuf },
    StderrPermissionMarker,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxDenialVerdict {
    pub confidence: SandboxDenialConfidence,
    pub evidence: Vec<DenialEvidence>,
}

impl SandboxDenialVerdict {
    pub fn unknown() -> Self {
        Self {
            confidence: SandboxDenialConfidence::Unknown,
            evidence: Vec::new(),
        }
    }

    pub fn is_high(&self) -> bool {
        matches!(self.confidence, SandboxDenialConfidence::High)
    }

    pub fn is_possible(&self) -> bool {
        matches!(self.confidence, SandboxDenialConfidence::Possible)
    }

    pub fn wire_report(&self) -> Option<crate::daemon::proto::SandboxDenialReport> {
        let confidence = match self.confidence {
            SandboxDenialConfidence::High => crate::daemon::proto::SandboxDenialConfidence::High,
            SandboxDenialConfidence::Possible => {
                crate::daemon::proto::SandboxDenialConfidence::Possible
            }
            SandboxDenialConfidence::Unknown => return None,
        };
        Some(crate::daemon::proto::SandboxDenialReport {
            confidence,
            evidence: self
                .evidence
                .iter()
                .map(|evidence| match evidence {
                    DenialEvidence::WriteOutsideAllowlist { path } => {
                        crate::daemon::proto::SandboxDenialEvidence::WriteOutsideAllowlist {
                            path: path.display().to_string(),
                        }
                    }
                    DenialEvidence::ReadOutsideAllowlist { path } => {
                        crate::daemon::proto::SandboxDenialEvidence::ReadOutsideAllowlist {
                            path: path.display().to_string(),
                        }
                    }
                    DenialEvidence::StderrPermissionMarker => {
                        crate::daemon::proto::SandboxDenialEvidence::StderrPermissionMarker
                    }
                })
                .collect(),
        })
    }
}

pub struct SandboxDenialInput<'a> {
    pub command: &'a str,
    pub cwd: &'a Path,
    pub policy: &'a SandboxPolicy,
    pub exit: i32,
    pub stderr: &'a str,
}

pub trait SandboxDenialClassifier {
    fn classify(&self, input: &SandboxDenialInput<'_>) -> SandboxDenialVerdict;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct HeuristicSandboxDenialClassifier;

impl SandboxDenialClassifier for HeuristicSandboxDenialClassifier {
    fn classify(&self, input: &SandboxDenialInput<'_>) -> SandboxDenialVerdict {
        if input.exit == 0 {
            return SandboxDenialVerdict::unknown();
        }

        let mut evidence = Vec::new();
        match crate::tools::bash::shell_write_targets(input.command, input.cwd) {
            crate::tools::bash::ShellWriteTargets::Concrete(targets) => {
                for target in targets {
                    if !is_under_any_root(&target, &input.policy.allow_write_roots) {
                        evidence.push(DenialEvidence::WriteOutsideAllowlist {
                            path: lexical_normalize(&target),
                        });
                    }
                }
            }
            crate::tools::bash::ShellWriteTargets::None
            | crate::tools::bash::ShellWriteTargets::Dynamic => {}
        }

        for target in read_targets(input.command, input.cwd) {
            if !is_under_any_root(&target, &input.policy.allow_read_roots) {
                evidence.push(DenialEvidence::ReadOutsideAllowlist {
                    path: lexical_normalize(&target),
                });
            }
        }

        let has_policy_evidence = evidence.iter().any(|evidence| {
            matches!(
                evidence,
                DenialEvidence::WriteOutsideAllowlist { .. }
                    | DenialEvidence::ReadOutsideAllowlist { .. }
            )
        });
        if stderr_has_permission_marker(input.stderr) {
            evidence.push(DenialEvidence::StderrPermissionMarker);
        }

        let confidence = if has_policy_evidence {
            SandboxDenialConfidence::High
        } else if evidence.is_empty() {
            SandboxDenialConfidence::Unknown
        } else {
            SandboxDenialConfidence::Possible
        };
        SandboxDenialVerdict {
            confidence,
            evidence,
        }
    }
}

fn read_targets(command: &str, cwd: &Path) -> Vec<PathBuf> {
    let words = simple_shell_words(command);
    let Some(program) = words.first().map(String::as_str) else {
        return Vec::new();
    };
    let read_args = match program {
        "cat" | "head" | "tail" | "less" | "sed" | "grep" | "rg" | "wc" => &words[1..],
        "cp" | "mv" if words.len() > 2 => &words[1..words.len() - 1],
        _ => return Vec::new(),
    };
    read_args
        .iter()
        .filter(|arg| !arg.starts_with('-') && !is_dynamic_path(arg))
        .map(|arg| crate::tools::common::resolve(arg, cwd))
        .collect()
}

fn simple_shell_words(command: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut quote: Option<char> = None;
    let mut chars = command.chars().peekable();
    while let Some(ch) = chars.next() {
        if let Some(q) = quote {
            if ch == q {
                quote = None;
            } else if ch == '\\' && q == '"' {
                if let Some(next) = chars.next() {
                    word.push(next);
                }
            } else {
                word.push(ch);
            }
            continue;
        }
        match ch {
            '\'' | '"' => quote = Some(ch),
            '\\' => {
                if let Some(next) = chars.next() {
                    word.push(next);
                }
            }
            c if c.is_whitespace() => {
                if !word.is_empty() {
                    words.push(std::mem::take(&mut word));
                }
            }
            ';' | '|' | '&' => break,
            _ => word.push(ch),
        }
    }
    if !word.is_empty() {
        words.push(word);
    }
    words
}

fn is_dynamic_path(value: &str) -> bool {
    value.contains('$')
        || value.contains('*')
        || value.contains('?')
        || value.contains('[')
        || value.contains(']')
        || value.contains('{')
        || value.contains('}')
}

fn stderr_has_permission_marker(stderr: &str) -> bool {
    let stderr = stderr.to_ascii_lowercase();
    stderr.contains("permission denied")
        || stderr.contains("operation not permitted")
        || stderr.contains("read-only file system")
        || stderr.contains(" eacces")
        || stderr.contains(" eperm")
        || stderr == "eacces"
        || stderr == "eperm"
}

fn is_under_any_root(path: &Path, roots: &[PathBuf]) -> bool {
    let path = lexical_normalize(path);
    roots.iter().any(|root| {
        let root = lexical_normalize(root);
        path == root || path.starts_with(root)
    })
}

fn lexical_normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            Component::Prefix(prefix) => out.push(prefix.as_os_str()),
            Component::RootDir => out.push(component.as_os_str()),
            Component::Normal(part) => out.push(part),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    struct AlwaysHigh;

    impl SandboxDenialClassifier for AlwaysHigh {
        fn classify(&self, _input: &SandboxDenialInput<'_>) -> SandboxDenialVerdict {
            SandboxDenialVerdict {
                confidence: SandboxDenialConfidence::High,
                evidence: vec![DenialEvidence::WriteOutsideAllowlist {
                    path: PathBuf::from("/outside"),
                }],
            }
        }
    }

    fn policy(root: &Path) -> SandboxPolicy {
        SandboxPolicy {
            allow_read_roots: vec![root.to_path_buf()],
            allow_write_roots: vec![root.to_path_buf()],
            network_allowed: true,
        }
    }

    #[test]
    fn sandbox_denial_seam_swappable() {
        let tmp = tempfile::tempdir().unwrap();
        let classifier: &dyn SandboxDenialClassifier = &AlwaysHigh;
        let verdict = classifier.classify(&SandboxDenialInput {
            command: "true",
            cwd: tmp.path(),
            policy: &policy(tmp.path()),
            exit: 1,
            stderr: "",
        });
        assert!(verdict.is_high());
    }

    #[test]
    fn sandbox_denial_write_outside_allowlist_high() {
        let tmp = tempfile::tempdir().unwrap();
        let outside = tmp.path().parent().unwrap().join("outside.txt");
        let classifier = HeuristicSandboxDenialClassifier;
        let verdict = classifier.classify(&SandboxDenialInput {
            command: &format!("printf hi > '{}'", outside.display()),
            cwd: tmp.path(),
            policy: &policy(tmp.path()),
            exit: 1,
            stderr: "sh: cannot create: Permission denied",
        });
        assert!(verdict.is_high(), "{verdict:?}");
        assert!(verdict.evidence.iter().any(|evidence| {
            matches!(evidence, DenialEvidence::WriteOutsideAllowlist { path } if path == &outside)
        }));

        let success = classifier.classify(&SandboxDenialInput {
            command: &format!("printf hi > '{}'", outside.display()),
            cwd: tmp.path(),
            policy: &policy(tmp.path()),
            exit: 0,
            stderr: "",
        });
        assert_eq!(success.confidence, SandboxDenialConfidence::Unknown);
    }

    #[test]
    fn sandbox_denial_stderr_alone_never_high() {
        let tmp = tempfile::tempdir().unwrap();
        let verdict = HeuristicSandboxDenialClassifier.classify(&SandboxDenialInput {
            command: "printf 'Permission denied' >&2",
            cwd: tmp.path(),
            policy: &policy(tmp.path()),
            exit: 1,
            stderr: "Permission denied",
        });
        assert!(verdict.is_possible(), "{verdict:?}");
    }

    #[test]
    fn sandbox_denial_classifier_is_pure() {
        let tmp = tempfile::tempdir().unwrap();
        let outside = tmp.path().join("missing").join("..").join("inside.txt");
        let verdict = HeuristicSandboxDenialClassifier.classify(&SandboxDenialInput {
            command: &format!("cat '{}'", outside.display()),
            cwd: tmp.path(),
            policy: &policy(tmp.path()),
            exit: 1,
            stderr: "Permission denied",
        });
        assert!(
            verdict
                .evidence
                .iter()
                .any(|evidence| { matches!(evidence, DenialEvidence::StderrPermissionMarker) })
        );
    }
}
