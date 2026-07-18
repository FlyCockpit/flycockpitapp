use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use crate::approval::classify::SimpleCommandInfo;
use crate::config::extended::{
    CommandResourceProfileDefinition, CommandResourceProfileRoot, CommandResourceProfileRootAccess,
    CommandResourceProfilesConfig,
};
use crate::engine::tool::{
    SandboxResourceIntrospectionMeta, SandboxResourceProfileMeta, SandboxResourceRootMeta,
};
use crate::tools::shell_sandbox::{ExtraSandboxPath, SandboxPathAccess};

pub const RUST_TOOLCHAIN: &str = "rust_toolchain";
pub const NODE_PACKAGE_MANAGER: &str = "node_package_manager";
pub const PYTHON_TOOLCHAIN: &str = "python_toolchain";
pub const GO_TOOLCHAIN: &str = "go_toolchain";
pub const JAVA_TOOLCHAIN: &str = "java_toolchain";

const BUILTIN_PROFILE_IDS: &[&str] = &[
    RUST_TOOLCHAIN,
    NODE_PACKAGE_MANAGER,
    PYTHON_TOOLCHAIN,
    GO_TOOLCHAIN,
    JAVA_TOOLCHAIN,
];

const UNSUPPORTED_DEVTOOLS: &[&str] = &["terraform", "tofu", "terragrunt"];

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CommandResourcePlan {
    pub matched: bool,
    pub allow_paths: Vec<ExtraSandboxPath>,
    pub invalid_roots: Vec<ProfileRootIssue>,
    pub metas: Vec<SandboxResourceProfileMeta>,
    pub unsupported_tools: Vec<String>,
}

impl CommandResourcePlan {
    pub fn unsupported_hint(&self) -> Option<String> {
        if self.unsupported_tools.is_empty() {
            return None;
        }
        Some(format!(
            "\nResource profile hint: `{}` is a known developer tool without a matching command resource profile. Ask the user to configure commandResourceProfiles.profiles/wrappers for it or approve a broad command run; do not retry blindly.",
            self.unsupported_tools.join("`, `")
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileRootIssue {
    pub profile: String,
    pub kind: String,
    pub path: PathBuf,
    pub access: SandboxPathAccess,
    pub reason: String,
}

impl ProfileRootIssue {
    pub fn render(&self) -> String {
        format!(
            "{}:{} at `{}` is not usable: {}",
            self.profile,
            self.kind,
            self.path.display(),
            self.reason
        )
    }

    fn meta(&self) -> SandboxResourceRootMeta {
        SandboxResourceRootMeta {
            kind: self.kind.clone(),
            path: self.path.display().to_string(),
            access: self.access.as_str().to_string(),
            source: Some("denied".to_string()),
            reason: Some(self.reason.clone()),
            contributing_profiles: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntrospectionStatus {
    Used,
    Skipped,
    Failed,
    Timeout,
}

impl IntrospectionStatus {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Used => "used",
            Self::Skipped => "skipped",
            Self::Failed => "failed",
            Self::Timeout => "timeout",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntrospectionResult {
    pub tool: String,
    pub command: Vec<String>,
    pub status: IntrospectionStatus,
    pub stdout: String,
    pub detail: Option<String>,
}

impl IntrospectionResult {
    fn meta(&self) -> SandboxResourceIntrospectionMeta {
        SandboxResourceIntrospectionMeta {
            tool: self.tool.clone(),
            command: self.command.join(" "),
            status: self.status.as_str().to_string(),
            detail: self.detail.clone(),
        }
    }
}

pub trait ProfileIntrospector: Send + Sync {
    fn run_fixed(
        &self,
        tool: &str,
        args: &[&str],
        cwd: &Path,
        env: &HashMap<String, String>,
    ) -> IntrospectionResult;
}

#[derive(Debug, Clone)]
pub struct ProductionProfileIntrospector {
    timeout: Duration,
    trusted_workspace: bool,
    session_tmp: Option<PathBuf>,
}

impl ProductionProfileIntrospector {
    pub fn new(trusted_workspace: bool, session_tmp: Option<PathBuf>) -> Self {
        Self {
            timeout: Duration::from_secs(2),
            trusted_workspace,
            session_tmp,
        }
    }
}

impl ProfileIntrospector for ProductionProfileIntrospector {
    fn run_fixed(
        &self,
        tool: &str,
        args: &[&str],
        cwd: &Path,
        env: &HashMap<String, String>,
    ) -> IntrospectionResult {
        let command = std::iter::once(tool.to_string())
            .chain(args.iter().map(|s| (*s).to_string()))
            .collect::<Vec<_>>();
        if !self.trusted_workspace {
            return IntrospectionResult {
                tool: tool.to_string(),
                command,
                status: IntrospectionStatus::Skipped,
                stdout: String::new(),
                detail: Some(
                    "workspace is not trusted for developer-tool introspection".to_string(),
                ),
            };
        }
        let resolved = match which::which(tool) {
            Ok(path) => path,
            Err(error) => {
                return IntrospectionResult {
                    tool: tool.to_string(),
                    command,
                    status: IntrospectionStatus::Failed,
                    stdout: String::new(),
                    detail: Some(format!("resolve failed: {error}")),
                };
            }
        };
        if resolved.is_relative()
            || path_is_within(&resolved, cwd)
            || self
                .session_tmp
                .as_ref()
                .is_some_and(|tmp| path_is_within(&resolved, tmp))
        {
            return IntrospectionResult {
                tool: tool.to_string(),
                command,
                status: IntrospectionStatus::Skipped,
                stdout: String::new(),
                detail: Some(format!(
                    "resolved executable `{}` is project-controlled",
                    resolved.display()
                )),
            };
        }
        let mut cmd = Command::new(&resolved);
        cmd.args(args).current_dir(cwd);
        for (key, value) in env {
            cmd.env(key, value);
        }
        let start = std::time::Instant::now();
        match cmd.output() {
            Ok(_output) if start.elapsed() > self.timeout => IntrospectionResult {
                tool: tool.to_string(),
                command,
                status: IntrospectionStatus::Timeout,
                stdout: String::new(),
                detail: Some(format!("exceeded {} ms", self.timeout.as_millis())),
            },
            Ok(output) if output.status.success() => IntrospectionResult {
                tool: tool.to_string(),
                command,
                status: IntrospectionStatus::Used,
                stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
                detail: Some(format!("resolved `{}`", resolved.display())),
            },
            Ok(output) => IntrospectionResult {
                tool: tool.to_string(),
                command,
                status: IntrospectionStatus::Failed,
                stdout: String::new(),
                detail: Some(format!(
                    "exit {}; stderr: {}",
                    output.status,
                    String::from_utf8_lossy(&output.stderr).trim()
                )),
            },
            Err(error) => IntrospectionResult {
                tool: tool.to_string(),
                command,
                status: IntrospectionStatus::Failed,
                stdout: String::new(),
                detail: Some(error.to_string()),
            },
        }
    }
}

pub fn plan_for_command(
    simple_commands: &[SimpleCommandInfo],
    cwd: &Path,
    session_env: &HashMap<String, String>,
    config: &CommandResourceProfilesConfig,
    introspector: &dyn ProfileIntrospector,
) -> CommandResourcePlan {
    let mut builder = PlanBuilder::default();
    let matches = collect_matches(simple_commands, config);
    let matched_profile_ids = matches.keys().cloned().collect::<BTreeSet<_>>();

    for id in BUILTIN_PROFILE_IDS {
        if !config.profile_enabled(id) {
            continue;
        }
        let Some(profile_match) = matches.get(*id) else {
            continue;
        };
        add_builtin_profile(
            &mut builder,
            id,
            profile_match,
            cwd,
            session_env,
            introspector,
        );
    }

    for (id, def) in &config.profiles {
        if BUILTIN_PROFILE_IDS.contains(&id.as_str())
            || !valid_profile_id(id)
            || !config.profile_enabled(id)
        {
            continue;
        }
        let Some(profile_match) = matches.get(id.as_str()) else {
            continue;
        };
        add_custom_profile(&mut builder, id, def, profile_match, cwd, session_env);
    }

    let unsupported_tools = detect_unsupported_tools(simple_commands, &matched_profile_ids);
    builder.finish(unsupported_tools)
}

#[derive(Debug, Default)]
struct ProfileMatch {
    matched_commands: BTreeSet<String>,
    configured_wrappers: BTreeSet<String>,
    builtin_programs: BTreeSet<String>,
}

fn collect_matches(
    simple_commands: &[SimpleCommandInfo],
    config: &CommandResourceProfilesConfig,
) -> BTreeMap<String, ProfileMatch> {
    let mut out: BTreeMap<String, ProfileMatch> = BTreeMap::new();
    for info in simple_commands {
        let key = info.key.as_storage_str();
        let program_name = program_basename(&info.normalized_program);
        for id in builtin_profiles_for_program(&program_name) {
            let entry = out.entry(id.to_string()).or_default();
            entry.matched_commands.insert(key.clone());
            entry
                .builtin_programs
                .insert(info.normalized_program.clone());
        }
        for (wrapper, ids) in &config.wrappers {
            if wrapper.trim() == key {
                for id in ids {
                    let entry = out.entry(id.clone()).or_default();
                    entry.matched_commands.insert(key.clone());
                    entry.configured_wrappers.insert(wrapper.clone());
                }
            }
        }
        for (id, def) in &config.profiles {
            if custom_profile_matches(def, info) {
                let entry = out.entry(id.clone()).or_default();
                entry.matched_commands.insert(key.clone());
                entry
                    .builtin_programs
                    .insert(info.normalized_program.clone());
            }
        }
    }
    out
}

fn builtin_profiles_for_program(program: &str) -> &'static [&'static str] {
    match program {
        "cargo" | "rustup" | "rustc" | "rustfmt" | "clippy-driver" => &[RUST_TOOLCHAIN],
        "npm" | "npx" | "pnpm" | "pnpx" | "yarn" | "corepack" | "bun" => &[NODE_PACKAGE_MANAGER],
        "python" | "python3" | "py" | "pip" | "pip3" | "uv" | "uvx" | "poetry" | "pipenv"
        | "ruff" | "pytest" | "mypy" => &[PYTHON_TOOLCHAIN],
        "go" | "gofmt" | "golangci-lint" => &[GO_TOOLCHAIN],
        "mvn" | "mvnw" | "gradle" | "gradlew" | "java" | "javac" => &[JAVA_TOOLCHAIN],
        _ => &[],
    }
}

fn custom_profile_matches(
    def: &CommandResourceProfileDefinition,
    info: &SimpleCommandInfo,
) -> bool {
    let normalized = info.normalized_program.as_str();
    let basename = program_basename(normalized);
    def.commands.iter().any(|matcher| {
        let trimmed = matcher.trim();
        if trimmed.contains('/') || trimmed.contains('\\') {
            normalize_command_path(trimmed) == normalize_command_path(normalized)
        } else {
            program_basename(trimmed) == basename
        }
    })
}

fn normalize_command_path(value: &str) -> String {
    value.replace('\\', "/")
}

#[derive(Debug, Default)]
struct PlanBuilder {
    profiles: BTreeMap<String, ProfileBuild>,
    roots: BTreeMap<PathBuf, RootBuild>,
}

#[derive(Debug, Default)]
struct ProfileBuild {
    definition_source: String,
    matched_commands: BTreeSet<String>,
    configured_wrappers: BTreeSet<String>,
    introspection: Vec<IntrospectionResult>,
    denied_roots: Vec<ProfileRootIssue>,
}

#[derive(Debug, Clone)]
struct RootBuild {
    kind: String,
    path: PathBuf,
    access: SandboxPathAccess,
    source: String,
    contributing_profiles: BTreeSet<String>,
}

impl PlanBuilder {
    fn profile(&mut self, id: &str, source: &str, m: &ProfileMatch) -> &mut ProfileBuild {
        let profile = self
            .profiles
            .entry(id.to_string())
            .or_insert_with(|| ProfileBuild {
                definition_source: source.to_string(),
                ..ProfileBuild::default()
            });
        profile.definition_source = source.to_string();
        profile
            .matched_commands
            .extend(m.matched_commands.iter().cloned());
        profile
            .configured_wrappers
            .extend(m.configured_wrappers.iter().cloned());
        profile
    }

    fn add_root(
        &mut self,
        profile: &str,
        kind: &str,
        path: PathBuf,
        access: SandboxPathAccess,
        source: &str,
    ) {
        let canonical = path.canonicalize().unwrap_or(path);
        let entry = self
            .roots
            .entry(canonical.clone())
            .or_insert_with(|| RootBuild {
                kind: kind.to_string(),
                path: canonical.clone(),
                access,
                source: source.to_string(),
                contributing_profiles: BTreeSet::new(),
            });
        if matches!(access, SandboxPathAccess::ReadWrite) {
            entry.access = SandboxPathAccess::ReadWrite;
        }
        entry.contributing_profiles.insert(profile.to_string());
    }

    fn add_issue(&mut self, profile: &str, issue: ProfileRootIssue) {
        self.profiles
            .entry(profile.to_string())
            .or_insert_with(|| ProfileBuild {
                definition_source: "builtin".to_string(),
                ..ProfileBuild::default()
            })
            .denied_roots
            .push(issue);
    }

    fn add_introspection(&mut self, profile: &str, result: IntrospectionResult) {
        self.profiles
            .entry(profile.to_string())
            .or_insert_with(|| ProfileBuild {
                definition_source: "builtin".to_string(),
                ..ProfileBuild::default()
            })
            .introspection
            .push(result);
    }

    fn finish(mut self, unsupported_tools: Vec<String>) -> CommandResourcePlan {
        let allow_paths = self
            .roots
            .values()
            .map(|root| ExtraSandboxPath {
                kind: root.kind.clone(),
                path: root.path.clone(),
                access: root.access,
            })
            .collect::<Vec<_>>();
        let invalid_roots = self
            .profiles
            .values()
            .flat_map(|profile| profile.denied_roots.clone())
            .collect::<Vec<_>>();
        let root_meta = self
            .roots
            .values()
            .map(|root| {
                (
                    root.path.clone(),
                    SandboxResourceRootMeta {
                        kind: root.kind.clone(),
                        path: root.path.display().to_string(),
                        access: root.access.as_str().to_string(),
                        source: Some(root.source.clone()),
                        reason: None,
                        contributing_profiles: root.contributing_profiles.iter().cloned().collect(),
                    },
                )
            })
            .collect::<BTreeMap<_, _>>();
        let mut metas = Vec::new();
        for (id, profile) in self.profiles.iter_mut() {
            let roots = root_meta
                .values()
                .filter_map(|meta| {
                    if meta.contributing_profiles.iter().any(|p| p == id) {
                        Some(meta.clone())
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>();
            metas.push(SandboxResourceProfileMeta {
                profile: id.clone(),
                definition_source: Some(profile.definition_source.clone()),
                matched_commands: profile.matched_commands.iter().cloned().collect(),
                configured_wrappers: profile.configured_wrappers.iter().cloned().collect(),
                introspection: profile
                    .introspection
                    .iter()
                    .map(IntrospectionResult::meta)
                    .collect(),
                roots,
                denied_roots: profile
                    .denied_roots
                    .iter()
                    .map(ProfileRootIssue::meta)
                    .collect(),
            });
        }
        CommandResourcePlan {
            matched: !metas.is_empty(),
            allow_paths,
            invalid_roots,
            metas,
            unsupported_tools,
        }
    }
}

fn add_builtin_profile(
    builder: &mut PlanBuilder,
    id: &str,
    m: &ProfileMatch,
    cwd: &Path,
    session_env: &HashMap<String, String>,
    introspector: &dyn ProfileIntrospector,
) {
    builder.profile(id, "builtin", m);
    match id {
        RUST_TOOLCHAIN => add_rust_roots(builder, id, m, cwd, session_env),
        NODE_PACKAGE_MANAGER => add_node_roots(builder, id, cwd, session_env),
        PYTHON_TOOLCHAIN => add_python_roots(builder, id, cwd, session_env),
        GO_TOOLCHAIN => add_go_roots(builder, id, cwd, session_env, introspector),
        JAVA_TOOLCHAIN => add_java_roots(builder, id, cwd, session_env),
        _ => {}
    }
}

fn add_rust_roots(
    builder: &mut PlanBuilder,
    id: &str,
    m: &ProfileMatch,
    cwd: &Path,
    session_env: &HashMap<String, String>,
) {
    let needs = !m.matched_commands.is_empty();
    add_env_or_default_dir(
        builder,
        id,
        "cargo_home",
        "CARGO_HOME",
        dirs::home_dir().map(|h| h.join(".cargo")),
        cwd,
        session_env,
        SandboxPathAccess::ReadWrite,
        needs,
    );
    add_env_or_default_dir(
        builder,
        id,
        "rustup_home",
        "RUSTUP_HOME",
        dirs::home_dir().map(|h| h.join(".rustup")),
        cwd,
        session_env,
        SandboxPathAccess::ReadWrite,
        needs,
    );
    for program in &m.builtin_programs {
        if let Some(parent) = resolve_program_parent(program, cwd) {
            builder.add_root(
                id,
                "binary_dir",
                parent,
                SandboxPathAccess::Read,
                "introspection",
            );
        }
    }
    for dir in cwd.ancestors() {
        for name in [".cargo/config.toml", ".cargo/config"] {
            let path = dir.join(name);
            if path.is_file() {
                builder.add_root(id, "cargo_config", path, SandboxPathAccess::Read, "default");
            }
        }
    }
}

fn add_node_roots(
    builder: &mut PlanBuilder,
    id: &str,
    cwd: &Path,
    session_env: &HashMap<String, String>,
) {
    add_first_env_dir(
        builder,
        id,
        "npm_cache",
        &["NPM_CONFIG_CACHE", "npm_config_cache"],
        cwd,
        session_env,
        SandboxPathAccess::ReadWrite,
    );
    add_env_or_default_dir(
        builder,
        id,
        "pnpm_home",
        "PNPM_HOME",
        dirs::home_dir().map(|h| h.join(".local/share/pnpm")),
        cwd,
        session_env,
        SandboxPathAccess::ReadWrite,
        true,
    );
    add_env_or_default_dir(
        builder,
        id,
        "yarn_cache",
        "YARN_CACHE_FOLDER",
        dirs::home_dir().map(|h| h.join(".cache/yarn")),
        cwd,
        session_env,
        SandboxPathAccess::ReadWrite,
        true,
    );
    add_env_or_default_dir(
        builder,
        id,
        "bun_cache",
        "BUN_INSTALL_CACHE_DIR",
        dirs::home_dir().map(|h| h.join(".bun/install/cache")),
        cwd,
        session_env,
        SandboxPathAccess::ReadWrite,
        true,
    );
    add_env_or_default_dir(
        builder,
        id,
        "corepack_home",
        "COREPACK_HOME",
        dirs::home_dir().map(|h| h.join(".cache/node/corepack")),
        cwd,
        session_env,
        SandboxPathAccess::ReadWrite,
        true,
    );
    if env_path_any(&["NPM_CONFIG_CACHE", "npm_config_cache"], cwd, session_env).is_none()
        && let Some(home) = dirs::home_dir()
    {
        let path = home.join(".npm");
        if path.is_dir() {
            builder.add_root(
                id,
                "npm_cache",
                path,
                SandboxPathAccess::ReadWrite,
                "default",
            );
        }
    }
}

fn add_python_roots(
    builder: &mut PlanBuilder,
    id: &str,
    cwd: &Path,
    session_env: &HashMap<String, String>,
) {
    add_env_or_default_dir(
        builder,
        id,
        "pip_cache",
        "PIP_CACHE_DIR",
        dirs::home_dir().map(|h| h.join(".cache/pip")),
        cwd,
        session_env,
        SandboxPathAccess::ReadWrite,
        true,
    );
    add_env_or_default_dir(
        builder,
        id,
        "uv_cache",
        "UV_CACHE_DIR",
        dirs::home_dir().map(|h| h.join(".cache/uv")),
        cwd,
        session_env,
        SandboxPathAccess::ReadWrite,
        true,
    );
    add_env_or_default_dir(
        builder,
        id,
        "poetry_cache",
        "POETRY_CACHE_DIR",
        dirs::home_dir().map(|h| h.join(".cache/pypoetry")),
        cwd,
        session_env,
        SandboxPathAccess::ReadWrite,
        true,
    );
    add_env_or_default_dir(
        builder,
        id,
        "mypy_cache",
        "MYPY_CACHE_DIR",
        Some(cwd.join(".mypy_cache")),
        cwd,
        session_env,
        SandboxPathAccess::ReadWrite,
        true,
    );
    if let Some(venv) = env_path("VIRTUAL_ENV", cwd, session_env)
        && !path_is_within(&venv, cwd)
        && venv.is_dir()
    {
        builder.add_root(
            id,
            "virtualenv",
            venv,
            SandboxPathAccess::ReadWrite,
            "session_env",
        );
    }
}

fn add_go_roots(
    builder: &mut PlanBuilder,
    id: &str,
    cwd: &Path,
    session_env: &HashMap<String, String>,
    introspector: &dyn ProfileIntrospector,
) {
    let mut have_mod = add_env_or_default_dir(
        builder,
        id,
        "go_mod_cache",
        "GOMODCACHE",
        None,
        cwd,
        session_env,
        SandboxPathAccess::ReadWrite,
        true,
    );
    let mut have_build = add_env_or_default_dir(
        builder,
        id,
        "go_build_cache",
        "GOCACHE",
        None,
        cwd,
        session_env,
        SandboxPathAccess::ReadWrite,
        true,
    );
    add_env_or_default_dir(
        builder,
        id,
        "gopath",
        "GOPATH",
        dirs::home_dir().map(|h| h.join("go")),
        cwd,
        session_env,
        SandboxPathAccess::ReadWrite,
        true,
    );
    if !have_mod || !have_build {
        let result =
            introspector.run_fixed("go", &["env", "GOMODCACHE", "GOCACHE"], cwd, session_env);
        if matches!(result.status, IntrospectionStatus::Used) {
            for (idx, line) in result
                .stdout
                .lines()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .enumerate()
            {
                let kind = if idx == 0 {
                    "go_mod_cache"
                } else {
                    "go_build_cache"
                };
                let path = expand_path(line, cwd);
                if path.is_dir() {
                    builder.add_root(
                        id,
                        kind,
                        path,
                        SandboxPathAccess::ReadWrite,
                        "introspection",
                    );
                    if idx == 0 {
                        have_mod = true;
                    } else {
                        have_build = true;
                    }
                }
            }
        }
        builder.add_introspection(id, result);
    }
    if !have_mod && let Some(home) = dirs::home_dir() {
        let p = home.join("go/pkg/mod");
        if p.is_dir() {
            builder.add_root(
                id,
                "go_mod_cache",
                p,
                SandboxPathAccess::ReadWrite,
                "default",
            );
        }
    }
    if !have_build && let Some(home) = dirs::home_dir() {
        let p = home.join(".cache/go-build");
        if p.is_dir() {
            builder.add_root(
                id,
                "go_build_cache",
                p,
                SandboxPathAccess::ReadWrite,
                "default",
            );
        }
    }
}

fn add_java_roots(
    builder: &mut PlanBuilder,
    id: &str,
    cwd: &Path,
    session_env: &HashMap<String, String>,
) {
    add_env_or_default_dir(
        builder,
        id,
        "maven_local_repository",
        "MAVEN_REPO_LOCAL",
        dirs::home_dir().map(|h| h.join(".m2/repository")),
        cwd,
        session_env,
        SandboxPathAccess::ReadWrite,
        true,
    );
    add_env_or_default_dir(
        builder,
        id,
        "gradle_user_home",
        "GRADLE_USER_HOME",
        dirs::home_dir().map(|h| h.join(".gradle")),
        cwd,
        session_env,
        SandboxPathAccess::ReadWrite,
        true,
    );
}

fn add_custom_profile(
    builder: &mut PlanBuilder,
    id: &str,
    def: &CommandResourceProfileDefinition,
    m: &ProfileMatch,
    cwd: &Path,
    session_env: &HashMap<String, String>,
) {
    builder.profile(id, "config", m);
    for root in &def.roots {
        add_custom_root(builder, id, root, cwd, session_env);
    }
}

fn add_custom_root(
    builder: &mut PlanBuilder,
    profile: &str,
    root: &CommandResourceProfileRoot,
    cwd: &Path,
    session_env: &HashMap<String, String>,
) {
    let access = match root.access {
        CommandResourceProfileRootAccess::Read => SandboxPathAccess::Read,
        CommandResourceProfileRootAccess::ReadWrite => SandboxPathAccess::ReadWrite,
    };
    let (path, source, explicit) = if let Some(env_name) = root.env.as_deref() {
        if let Some((path, source)) = env_path_with_source(env_name, cwd, session_env) {
            (Some(path), source, true)
        } else if let Some(literal) = root.path.as_deref() {
            (Some(expand_path(literal, cwd)), "default".to_string(), true)
        } else {
            (None, "denied".to_string(), true)
        }
    } else if let Some(literal) = root.path.as_deref() {
        (Some(expand_path(literal, cwd)), "default".to_string(), true)
    } else {
        (None, "denied".to_string(), true)
    };
    let Some(path) = path else {
        if !root.optional {
            builder.add_issue(
                profile,
                ProfileRootIssue {
                    profile: profile.to_string(),
                    kind: root.kind.clone(),
                    path: PathBuf::from(root.env.as_deref().unwrap_or("<unresolved>")),
                    access,
                    reason: "required root could not be resolved".to_string(),
                },
            );
        }
        return;
    };
    if root.within_cwd && !path_is_within(&path, cwd) {
        builder.add_issue(
            profile,
            ProfileRootIssue {
                profile: profile.to_string(),
                kind: root.kind.clone(),
                path,
                access,
                reason: "path escapes cwd but withinCwd is true".to_string(),
            },
        );
        return;
    }
    if path.exists() {
        let usable = if matches!(access, SandboxPathAccess::ReadWrite) {
            path.is_dir()
        } else {
            path.is_dir() || path.is_file()
        };
        if usable {
            builder.add_root(profile, &root.kind, path, access, &source);
        } else if !root.optional || explicit {
            builder.add_issue(
                profile,
                ProfileRootIssue {
                    profile: profile.to_string(),
                    kind: root.kind.clone(),
                    path,
                    access,
                    reason: "path is not a usable file or directory".to_string(),
                },
            );
        }
    } else if !root.optional && explicit {
        builder.add_issue(
            profile,
            ProfileRootIssue {
                profile: profile.to_string(),
                kind: root.kind.clone(),
                path,
                access,
                reason: "path does not exist".to_string(),
            },
        );
    }
}

fn add_first_env_dir(
    builder: &mut PlanBuilder,
    profile: &str,
    kind: &str,
    env_names: &[&str],
    cwd: &Path,
    session_env: &HashMap<String, String>,
    access: SandboxPathAccess,
) -> bool {
    let Some((path, source)) = env_path_any_with_source(env_names, cwd, session_env) else {
        return false;
    };
    if path.is_dir() {
        builder.add_root(profile, kind, path, access, &source);
        true
    } else {
        builder.add_issue(
            profile,
            ProfileRootIssue {
                profile: profile.to_string(),
                kind: kind.to_string(),
                path,
                access,
                reason: "path does not exist or is not a directory".to_string(),
            },
        );
        false
    }
}

#[allow(clippy::too_many_arguments)]
fn add_env_or_default_dir(
    builder: &mut PlanBuilder,
    profile: &str,
    kind: &str,
    env_name: &str,
    default: Option<PathBuf>,
    cwd: &Path,
    session_env: &HashMap<String, String>,
    access: SandboxPathAccess,
    needed: bool,
) -> bool {
    if !needed {
        return false;
    }
    if let Some((path, source)) = env_path_with_source(env_name, cwd, session_env) {
        if path.is_dir() {
            builder.add_root(profile, kind, path, access, &source);
            return true;
        }
        builder.add_issue(
            profile,
            ProfileRootIssue {
                profile: profile.to_string(),
                kind: kind.to_string(),
                path,
                access,
                reason: "path does not exist or is not a directory".to_string(),
            },
        );
        return false;
    }
    if let Some(path) = default.filter(|p| p.is_dir()) {
        builder.add_root(profile, kind, path, access, "default");
        return true;
    }
    false
}

fn env_path_any(
    env_names: &[&str],
    cwd: &Path,
    session_env: &HashMap<String, String>,
) -> Option<PathBuf> {
    env_path_any_with_source(env_names, cwd, session_env).map(|(path, _)| path)
}

fn env_path_any_with_source(
    env_names: &[&str],
    cwd: &Path,
    session_env: &HashMap<String, String>,
) -> Option<(PathBuf, String)> {
    for name in env_names {
        if let Some(value) = env_path_with_source(name, cwd, session_env) {
            return Some(value);
        }
    }
    None
}

fn env_path(env_name: &str, cwd: &Path, session_env: &HashMap<String, String>) -> Option<PathBuf> {
    env_path_with_source(env_name, cwd, session_env).map(|(path, _)| path)
}

fn env_path_with_source(
    env_name: &str,
    cwd: &Path,
    session_env: &HashMap<String, String>,
) -> Option<(PathBuf, String)> {
    if let Some(raw) = session_env.get(env_name).filter(|s| !s.trim().is_empty()) {
        return Some((expand_path(raw, cwd), "session_env".to_string()));
    }
    if let Ok(raw) = std::env::var(env_name)
        && !raw.trim().is_empty()
    {
        return Some((expand_path(&raw, cwd), "process_env".to_string()));
    }
    None
}

fn expand_path(raw: &str, cwd: &Path) -> PathBuf {
    let expanded = PathBuf::from(shellexpand::tilde(raw).into_owned());
    if expanded.is_absolute() {
        expanded
    } else {
        cwd.join(expanded)
    }
}

fn resolve_program_parent(program: &str, cwd: &Path) -> Option<PathBuf> {
    let candidate = if program.contains('/') || program.contains('\\') {
        let path = PathBuf::from(program);
        Some(if path.is_absolute() {
            path
        } else {
            cwd.join(path)
        })
    } else {
        which::which(program).ok()
    }?;
    candidate.parent().map(Path::to_path_buf)
}

fn detect_unsupported_tools(
    simple_commands: &[SimpleCommandInfo],
    matched_profiles: &BTreeSet<String>,
) -> Vec<String> {
    let mut tools = BTreeSet::new();
    for info in simple_commands {
        let program = program_basename(&info.normalized_program);
        if UNSUPPORTED_DEVTOOLS.contains(&program.as_str())
            && !matched_profiles
                .iter()
                .any(|id| !BUILTIN_PROFILE_IDS.contains(&id.as_str()))
        {
            tools.insert(program);
        }
    }
    tools.into_iter().collect()
}

fn valid_profile_id(id: &str) -> bool {
    let mut chars = id.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    first.is_ascii_lowercase()
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

fn program_basename(program: &str) -> String {
    let name = Path::new(program)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(program);
    name.strip_suffix(".exe").unwrap_or(name).to_string()
}

fn path_is_within(path: &Path, root: &Path) -> bool {
    let canon_path = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    let canon_root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
    canon_path.starts_with(canon_root)
}

pub fn resource_profile_context(plan: &CommandResourcePlan) -> String {
    if !plan.matched {
        return String::new();
    }
    let mut parts = Vec::new();
    for meta in &plan.metas {
        let roots = meta
            .roots
            .iter()
            .map(|root| format!("{}:{}:{}", root.kind, root.access, root.path))
            .collect::<Vec<_>>()
            .join(", ");
        let denied = meta
            .denied_roots
            .iter()
            .map(|root| {
                format!(
                    "{}:{}",
                    root.kind,
                    root.reason.clone().unwrap_or_else(|| "denied".to_string())
                )
            })
            .collect::<Vec<_>>()
            .join(", ");
        let mut p = format!(
            "{} matched [{}]",
            meta.profile,
            meta.matched_commands.join(", ")
        );
        if !roots.is_empty() {
            p.push_str(&format!(" roots [{roots}]"));
        }
        if !denied.is_empty() {
            p.push_str(&format!(" denied [{denied}]"));
        }
        parts.push(p);
    }
    format!("\ncommand resource profiles: {}", parts.join("; "))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::approval::classify;

    #[derive(Default)]
    struct ScriptedIntrospector {
        result: Option<IntrospectionResult>,
    }

    impl ProfileIntrospector for ScriptedIntrospector {
        fn run_fixed(
            &self,
            tool: &str,
            args: &[&str],
            _cwd: &Path,
            _env: &HashMap<String, String>,
        ) -> IntrospectionResult {
            self.result.clone().unwrap_or_else(|| IntrospectionResult {
                tool: tool.to_string(),
                command: std::iter::once(tool.to_string())
                    .chain(args.iter().map(|s| (*s).to_string()))
                    .collect(),
                status: IntrospectionStatus::Skipped,
                stdout: String::new(),
                detail: Some("scripted skip".to_string()),
            })
        }
    }

    #[test]
    fn rust_builtin_and_wrapper_activate_profile() {
        let tmp = tempfile::tempdir().unwrap();
        let cargo_home = tmp.path().join("cargo-home");
        let rustup_home = tmp.path().join("rustup-home");
        std::fs::create_dir_all(&cargo_home).unwrap();
        std::fs::create_dir_all(&rustup_home).unwrap();
        let mut env = HashMap::new();
        env.insert("CARGO_HOME".to_string(), cargo_home.display().to_string());
        env.insert("RUSTUP_HOME".to_string(), rustup_home.display().to_string());
        let mut cfg = CommandResourceProfilesConfig::default();
        cfg.wrappers
            .insert("just test".to_string(), vec![RUST_TOOLCHAIN.to_string()]);
        let classified = classify::classify("just test && cargo check");

        let plan = plan_for_command(
            classified.simple_commands(),
            tmp.path(),
            &env,
            &cfg,
            &ScriptedIntrospector::default(),
        );

        assert!(plan.metas.iter().any(|m| m.profile == RUST_TOOLCHAIN));
        assert!(plan.allow_paths.iter().any(|p| p.kind == "cargo_home"));
        assert!(
            plan.metas[0]
                .configured_wrappers
                .contains(&"just test".to_string())
        );
    }

    #[test]
    fn node_profile_uses_cache_roots_not_path_runtime_roots() {
        let tmp = tempfile::tempdir().unwrap();
        let npm_cache = tmp.path().join("npm-cache");
        let pnpm_home = tmp.path().join("pnpm-home");
        std::fs::create_dir_all(&npm_cache).unwrap();
        std::fs::create_dir_all(&pnpm_home).unwrap();
        let mut env = HashMap::new();
        env.insert(
            "NPM_CONFIG_CACHE".to_string(),
            npm_cache.display().to_string(),
        );
        env.insert("PNPM_HOME".to_string(), pnpm_home.display().to_string());
        let classified = classify::classify("pnpm test");

        let plan = plan_for_command(
            classified.simple_commands(),
            tmp.path(),
            &env,
            &CommandResourceProfilesConfig::default(),
            &ScriptedIntrospector::default(),
        );

        assert!(
            plan.allow_paths
                .iter()
                .any(|p| p.kind == "npm_cache" || p.kind == "pnpm_home")
        );
        assert!(!plan.allow_paths.iter().any(|p| p.kind == "nvm_dir"));
    }

    #[test]
    fn go_profile_uses_scripted_introspection() {
        let tmp = tempfile::tempdir().unwrap();
        let mod_cache = tmp.path().join("gomod");
        let build_cache = tmp.path().join("gocache");
        std::fs::create_dir_all(&mod_cache).unwrap();
        std::fs::create_dir_all(&build_cache).unwrap();
        let introspector = ScriptedIntrospector {
            result: Some(IntrospectionResult {
                tool: "go".to_string(),
                command: vec![
                    "go".to_string(),
                    "env".to_string(),
                    "GOMODCACHE".to_string(),
                    "GOCACHE".to_string(),
                ],
                status: IntrospectionStatus::Used,
                stdout: format!("{}\n{}\n", mod_cache.display(), build_cache.display()),
                detail: None,
            }),
        };
        let classified = classify::classify("go test ./...");

        let plan = plan_for_command(
            classified.simple_commands(),
            tmp.path(),
            &HashMap::new(),
            &CommandResourceProfilesConfig::default(),
            &introspector,
        );

        assert!(plan.allow_paths.iter().any(|p| p.kind == "go_mod_cache"));
        assert!(
            plan.metas
                .iter()
                .any(|m| m.introspection.iter().any(|i| i.status == "used"))
        );
    }

    #[test]
    fn custom_terraform_profile_resolves_env_optional_home_and_within_cwd() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = tmp.path().join("plugin-cache");
        let project = tmp.path().join(".terraform");
        std::fs::create_dir_all(&cache).unwrap();
        std::fs::create_dir_all(&project).unwrap();
        let mut cfg = CommandResourceProfilesConfig::default();
        cfg.profiles.insert(
            "terraform_toolchain".to_string(),
            CommandResourceProfileDefinition {
                commands: vec![
                    "terraform".to_string(),
                    "tofu".to_string(),
                    "terragrunt".to_string(),
                ],
                roots: vec![
                    CommandResourceProfileRoot {
                        kind: "terraform_plugin_cache".to_string(),
                        env: Some("TF_PLUGIN_CACHE_DIR".to_string()),
                        path: None,
                        access: CommandResourceProfileRootAccess::ReadWrite,
                        optional: false,
                        within_cwd: false,
                        extra: Default::default(),
                    },
                    CommandResourceProfileRoot {
                        kind: "project_terraform_dir".to_string(),
                        env: None,
                        path: Some(".terraform".to_string()),
                        access: CommandResourceProfileRootAccess::ReadWrite,
                        optional: true,
                        within_cwd: true,
                        extra: Default::default(),
                    },
                ],
                extra: Default::default(),
            },
        );
        let mut env = HashMap::new();
        env.insert(
            "TF_PLUGIN_CACHE_DIR".to_string(),
            cache.display().to_string(),
        );
        let classified = classify::classify("terraform plan");

        let plan = plan_for_command(
            classified.simple_commands(),
            tmp.path(),
            &env,
            &cfg,
            &ScriptedIntrospector::default(),
        );

        assert!(
            plan.allow_paths
                .iter()
                .any(|p| p.kind == "terraform_plugin_cache")
        );
        assert!(
            plan.allow_paths
                .iter()
                .any(|p| p.kind == "project_terraform_dir")
        );
        assert!(plan.unsupported_tools.is_empty());
    }

    #[test]
    fn duplicate_roots_merge_read_write_and_contributors() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("shared");
        std::fs::create_dir_all(&root).unwrap();
        let mut cfg = CommandResourceProfilesConfig::default();
        for id in ["one_profile", "two_profile"] {
            cfg.profiles.insert(
                id.to_string(),
                CommandResourceProfileDefinition {
                    commands: vec![id.trim_end_matches("_profile").to_string()],
                    roots: vec![CommandResourceProfileRoot {
                        kind: "shared".to_string(),
                        env: None,
                        path: Some(root.display().to_string()),
                        access: if id == "one_profile" {
                            CommandResourceProfileRootAccess::Read
                        } else {
                            CommandResourceProfileRootAccess::ReadWrite
                        },
                        optional: false,
                        within_cwd: false,
                        extra: Default::default(),
                    }],
                    extra: Default::default(),
                },
            );
        }
        let classified = classify::classify("one && two");

        let plan = plan_for_command(
            classified.simple_commands(),
            tmp.path(),
            &HashMap::new(),
            &cfg,
            &ScriptedIntrospector::default(),
        );

        assert_eq!(plan.allow_paths.len(), 1);
        assert_eq!(plan.allow_paths[0].access, SandboxPathAccess::ReadWrite);
        let shared_path = root.display().to_string();
        let contributors = plan
            .metas
            .iter()
            .flat_map(|m| &m.roots)
            .find(|root_meta| root_meta.path == shared_path)
            .map(|root_meta| &root_meta.contributing_profiles)
            .unwrap();
        assert!(contributors.contains(&"one_profile".to_string()));
        assert!(contributors.contains(&"two_profile".to_string()));
    }

    #[test]
    fn disabled_profile_is_skipped() {
        let tmp = tempfile::tempdir().unwrap();
        let mut cfg = CommandResourceProfilesConfig::default();
        cfg.enabled.insert(RUST_TOOLCHAIN.to_string(), false);
        let classified = classify::classify("cargo check");

        let plan = plan_for_command(
            classified.simple_commands(),
            tmp.path(),
            &HashMap::new(),
            &cfg,
            &ScriptedIntrospector::default(),
        );

        assert!(!plan.metas.iter().any(|m| m.profile == RUST_TOOLCHAIN));
    }

    #[test]
    fn custom_within_cwd_escape_is_denied() {
        let tmp = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let mut cfg = CommandResourceProfilesConfig::default();
        cfg.profiles.insert(
            "terraform_toolchain".to_string(),
            CommandResourceProfileDefinition {
                commands: vec!["terraform".to_string()],
                roots: vec![CommandResourceProfileRoot {
                    kind: "project_terraform_dir".to_string(),
                    env: None,
                    path: Some(outside.path().display().to_string()),
                    access: CommandResourceProfileRootAccess::ReadWrite,
                    optional: false,
                    within_cwd: true,
                    extra: Default::default(),
                }],
                extra: Default::default(),
            },
        );
        let classified = classify::classify("terraform plan");

        let plan = plan_for_command(
            classified.simple_commands(),
            tmp.path(),
            &HashMap::new(),
            &cfg,
            &ScriptedIntrospector::default(),
        );

        assert!(
            plan.invalid_roots
                .iter()
                .any(|i| i.reason.contains("withinCwd"))
        );
    }
}
