use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use crate::approval::classify::SimpleCommandInfo;
use crate::engine::tool::{SandboxResourceProfileMeta, SandboxResourceRootMeta};
use crate::tools::shell_sandbox::{ExtraSandboxPath, SandboxPathAccess};

const PROFILE_ID: &str = "rust_toolchain";

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RustToolchainPlan {
    pub detected: bool,
    pub matched_commands: Vec<String>,
    pub allow_paths: Vec<ExtraSandboxPath>,
    pub meta: Option<SandboxResourceProfileMeta>,
    pub invalid_roots: Vec<RustToolchainRootIssue>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RustToolchainRootIssue {
    pub kind: &'static str,
    pub path: PathBuf,
    pub reason: String,
}

impl RustToolchainRootIssue {
    pub fn render(&self) -> String {
        format!(
            "{} at `{}` is not usable: {}",
            self.kind,
            self.path.display(),
            self.reason
        )
    }
}

pub fn plan_for_command(
    simple_commands: &[SimpleCommandInfo],
    cwd: &Path,
    session_env: &HashMap<String, String>,
    configured_wrapper_keys: &[String],
) -> RustToolchainPlan {
    let detection = detect(simple_commands, configured_wrapper_keys);
    if detection.matched_commands.is_empty() {
        return RustToolchainPlan::default();
    }

    let mut plan = RustToolchainPlan {
        detected: true,
        matched_commands: detection.matched_commands,
        ..RustToolchainPlan::default()
    };
    let mut seen_paths = HashSet::new();
    add_env_root(
        &mut plan,
        &mut seen_paths,
        EnvRootSpec {
            kind: "cargo_home",
            env_name: "CARGO_HOME",
            default: dirs::home_dir().map(|home| home.join(".cargo")),
            needed: detection.needs_cargo_home,
        },
        cwd,
        session_env,
    );
    add_env_root(
        &mut plan,
        &mut seen_paths,
        EnvRootSpec {
            kind: "rustup_home",
            env_name: "RUSTUP_HOME",
            default: dirs::home_dir().map(|home| home.join(".rustup")),
            needed: detection.needs_rustup_home,
        },
        cwd,
        session_env,
    );
    add_binary_roots(&mut plan, &mut seen_paths, cwd, &detection.binary_programs);
    add_cargo_configs(&mut plan, &mut seen_paths, cwd);

    plan.meta = Some(SandboxResourceProfileMeta {
        profile: PROFILE_ID.to_string(),
        matched_commands: plan.matched_commands.clone(),
        roots: plan
            .allow_paths
            .iter()
            .map(|path| SandboxResourceRootMeta {
                kind: path.kind.clone(),
                path: path.path.display().to_string(),
                access: path.access.as_str().to_string(),
            })
            .collect(),
        denied_roots: plan
            .invalid_roots
            .iter()
            .map(|issue| SandboxResourceRootMeta {
                kind: issue.kind.to_string(),
                path: issue.path.display().to_string(),
                access: format!("denied: {}", issue.reason),
            })
            .collect(),
    });
    plan
}

#[derive(Debug, Default)]
struct Detection {
    matched_commands: Vec<String>,
    binary_programs: Vec<String>,
    needs_cargo_home: bool,
    needs_rustup_home: bool,
}

fn detect(simple_commands: &[SimpleCommandInfo], configured_wrapper_keys: &[String]) -> Detection {
    let configured: HashSet<&str> = configured_wrapper_keys
        .iter()
        .map(String::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    let mut out = Detection::default();
    for info in simple_commands {
        let program_name = program_basename(&info.normalized_program);
        let key = info.key.as_storage_str();
        let configured_match = configured.contains(key.as_str());
        let builtin = match program_name.as_str() {
            "cargo" => {
                out.needs_cargo_home = true;
                out.needs_rustup_home = true;
                true
            }
            "rustup" => {
                out.needs_cargo_home = true;
                out.needs_rustup_home = true;
                true
            }
            "rustc" | "rustfmt" | "clippy-driver" => {
                out.needs_cargo_home = true;
                out.needs_rustup_home = true;
                true
            }
            _ => false,
        };
        if builtin || configured_match {
            out.matched_commands.push(key);
            if builtin {
                out.binary_programs.push(info.normalized_program.clone());
            }
            if configured_match {
                out.needs_cargo_home = true;
                out.needs_rustup_home = true;
            }
        }
    }
    out.matched_commands.sort();
    out.matched_commands.dedup();
    out.binary_programs.sort();
    out.binary_programs.dedup();
    out
}

fn program_basename(program: &str) -> String {
    let name = Path::new(program)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(program);
    name.strip_suffix(".exe").unwrap_or(name).to_string()
}

struct EnvRootSpec {
    kind: &'static str,
    env_name: &'static str,
    default: Option<PathBuf>,
    needed: bool,
}

fn add_env_root(
    plan: &mut RustToolchainPlan,
    seen: &mut HashSet<PathBuf>,
    spec: EnvRootSpec,
    cwd: &Path,
    session_env: &HashMap<String, String>,
) {
    if !spec.needed {
        return;
    }
    let (path, explicit) = match env_path(spec.env_name, cwd, session_env) {
        Some(path) => (path, true),
        None => match spec.default {
            Some(path) => (path, false),
            None => return,
        },
    };
    if path.is_dir() {
        add_path(plan, seen, spec.kind, path, SandboxPathAccess::ReadWrite);
    } else if explicit {
        let reason = if path.exists() {
            "path is not a directory".to_string()
        } else {
            "path does not exist".to_string()
        };
        plan.invalid_roots.push(RustToolchainRootIssue {
            kind: spec.kind,
            path,
            reason,
        });
    }
}

fn env_path(env_name: &str, cwd: &Path, session_env: &HashMap<String, String>) -> Option<PathBuf> {
    let raw = session_env
        .get(env_name)
        .filter(|s| !s.trim().is_empty())
        .cloned()
        .or_else(|| {
            std::env::var(env_name)
                .ok()
                .filter(|s| !s.trim().is_empty())
        })?;
    let path = PathBuf::from(shellexpand::tilde(&raw).into_owned());
    Some(if path.is_absolute() {
        path
    } else {
        cwd.join(path)
    })
}

fn add_binary_roots(
    plan: &mut RustToolchainPlan,
    seen: &mut HashSet<PathBuf>,
    cwd: &Path,
    programs: &[String],
) {
    for program in programs {
        let candidate = if program.contains('/') || program.contains('\\') {
            let path = PathBuf::from(program);
            Some(if path.is_absolute() {
                path
            } else {
                cwd.join(path)
            })
        } else {
            which::which(program).ok()
        };
        let Some(path) = candidate else {
            continue;
        };
        let Some(parent) = path.parent() else {
            continue;
        };
        add_path(
            plan,
            seen,
            "binary_dir",
            parent.to_path_buf(),
            SandboxPathAccess::Read,
        );
    }
}

fn add_cargo_configs(plan: &mut RustToolchainPlan, seen: &mut HashSet<PathBuf>, cwd: &Path) {
    for dir in cwd.ancestors() {
        for name in [".cargo/config.toml", ".cargo/config"] {
            let path = dir.join(name);
            if path.is_file() {
                add_path(plan, seen, "cargo_config", path, SandboxPathAccess::Read);
            }
        }
    }
}

fn add_path(
    plan: &mut RustToolchainPlan,
    seen: &mut HashSet<PathBuf>,
    kind: &'static str,
    path: PathBuf,
    access: SandboxPathAccess,
) {
    let canonical = path.canonicalize().unwrap_or(path);
    if !seen.insert(canonical.clone()) {
        return;
    }
    plan.allow_paths.push(ExtraSandboxPath {
        kind: kind.to_string(),
        path: canonical,
        access,
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::approval::classify;

    #[test]
    fn detects_cargo_and_rustup_inside_compound_commands() {
        let classified = classify::classify("echo ok && cargo test --all && rustup show");
        let detection = detect(classified.simple_commands(), &[]);

        assert!(detection.needs_cargo_home);
        assert!(detection.needs_rustup_home);
        assert!(
            detection
                .matched_commands
                .contains(&"cargo test".to_string())
        );
        assert!(
            detection
                .matched_commands
                .contains(&"rustup show".to_string())
        );
    }

    #[test]
    fn configured_wrapper_key_opts_into_rust_toolchain_profile() {
        let classified = classify::classify("just test");
        let detection = detect(classified.simple_commands(), &["just test".to_string()]);

        assert_eq!(detection.matched_commands, vec!["just test"]);
        assert!(detection.needs_cargo_home);
        assert!(detection.needs_rustup_home);
    }

    #[test]
    fn plain_cargo_needs_rustup_home_for_toolchain_resolution() {
        let classified = classify::classify("cargo check");
        let detection = detect(classified.simple_commands(), &[]);

        assert_eq!(detection.matched_commands, vec!["cargo check"]);
        assert!(detection.needs_cargo_home);
        assert!(detection.needs_rustup_home);
    }

    #[test]
    fn no_detection_for_unconfigured_wrappers() {
        let classified = classify::classify("just test");
        let detection = detect(classified.simple_commands(), &[]);

        assert!(detection.matched_commands.is_empty());
    }

    #[test]
    fn explicit_missing_home_is_reported_without_creating_temp_home() {
        let tmp = tempfile::tempdir().unwrap();
        let missing = tmp.path().join("missing-cargo-home");
        let mut env = HashMap::new();
        env.insert("CARGO_HOME".to_string(), missing.display().to_string());
        let classified = classify::classify("cargo check");

        let plan = plan_for_command(classified.simple_commands(), tmp.path(), &env, &[]);

        assert!(plan.detected);
        assert!(
            plan.invalid_roots
                .iter()
                .any(|issue| issue.kind == "cargo_home" && issue.path == missing)
        );
        assert!(!plan.allow_paths.iter().any(|path| path.path == missing));
    }

    #[test]
    fn existing_homes_and_project_cargo_config_are_exposed() {
        let tmp = tempfile::tempdir().unwrap();
        let cargo_home = tmp.path().join("cargo-home");
        let rustup_home = tmp.path().join("rustup-home");
        let cargo_dir = tmp.path().join(".cargo");
        std::fs::create_dir_all(&cargo_home).unwrap();
        std::fs::create_dir_all(&rustup_home).unwrap();
        std::fs::create_dir_all(&cargo_dir).unwrap();
        std::fs::write(cargo_dir.join("config.toml"), "[build]\n").unwrap();
        let mut env = HashMap::new();
        env.insert("CARGO_HOME".to_string(), cargo_home.display().to_string());
        env.insert("RUSTUP_HOME".to_string(), rustup_home.display().to_string());
        let classified = classify::classify("rustup show");

        let plan = plan_for_command(classified.simple_commands(), tmp.path(), &env, &[]);

        assert!(plan.allow_paths.iter().any(|path| {
            path.kind == "cargo_home" && path.access == SandboxPathAccess::ReadWrite
        }));
        assert!(plan.allow_paths.iter().any(|path| {
            path.kind == "rustup_home" && path.access == SandboxPathAccess::ReadWrite
        }));
        assert!(
            plan.allow_paths.iter().any(|path| {
                path.kind == "cargo_config" && path.access == SandboxPathAccess::Read
            })
        );
    }
}
