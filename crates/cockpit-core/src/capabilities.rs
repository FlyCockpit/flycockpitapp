use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ExecutionTarget {
    Host,
    Container,
}

impl ExecutionTarget {
    pub fn from_sandbox_mode(mode: crate::tools::sandbox_mode::SandboxMode) -> Self {
        if mode.is_container() {
            Self::Container
        } else {
            Self::Host
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum BinaryRequirementKind {
    Required,
    Optional,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemedyPlatform {
    Unix,
    Windows,
}

impl RemedyPlatform {
    pub fn current() -> Self {
        if cfg!(windows) {
            Self::Windows
        } else {
            Self::Unix
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityRemedy {
    pub prose: String,
    pub unix_install_command: Option<String>,
    pub windows_install_command: Option<String>,
}

impl CapabilityRemedy {
    pub fn prose(prose: impl Into<String>) -> Self {
        Self {
            prose: prose.into(),
            unix_install_command: None,
            windows_install_command: None,
        }
    }

    pub fn with_unix_command(prose: impl Into<String>, command: impl Into<String>) -> Self {
        Self {
            prose: prose.into(),
            unix_install_command: Some(command.into()),
            windows_install_command: None,
        }
    }

    pub fn command_for_current_platform(&self) -> Option<&str> {
        self.command_for_platform(RemedyPlatform::current())
    }

    pub fn command_for_platform(&self, platform: RemedyPlatform) -> Option<&str> {
        match platform {
            RemedyPlatform::Unix => self.unix_install_command.as_deref(),
            RemedyPlatform::Windows => self.windows_install_command.as_deref(),
        }
    }

    pub fn render_for_platform(&self, platform: RemedyPlatform) -> String {
        if let Some(command) = self.command_for_platform(platform) {
            format!("{} Fix: {command}", self.prose)
        } else {
            self.prose.clone()
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BinaryRequirement {
    pub name: String,
    pub kind: BinaryRequirementKind,
    pub remedy: CapabilityRemedy,
}

impl BinaryRequirement {
    pub fn required(name: impl Into<String>, remedy: CapabilityRemedy) -> Self {
        Self {
            name: name.into(),
            kind: BinaryRequirementKind::Required,
            remedy,
        }
    }

    pub fn optional(name: impl Into<String>, remedy: CapabilityRemedy) -> Self {
        Self {
            name: name.into(),
            kind: BinaryRequirementKind::Optional,
            remedy,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BinaryProbeStatus {
    Present(PathBuf),
    Missing,
    ProvidedByContainer,
    Unknown(String),
}

impl BinaryProbeStatus {
    pub fn is_available(&self) -> bool {
        matches!(self, Self::Present(_) | Self::ProvidedByContainer)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BinaryProbeResult {
    pub name: String,
    pub target: ExecutionTarget,
    pub status: BinaryProbeStatus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolCapabilityIssue {
    pub tool: String,
    pub requirement: BinaryRequirement,
    pub status: BinaryProbeStatus,
    pub availability: crate::mcp::builtin::Availability,
}

impl ToolCapabilityIssue {
    pub fn render_remedy(&self, platform: RemedyPlatform) -> String {
        self.requirement.remedy.render_for_platform(platform)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ToolCapabilityEvaluation {
    pub unavailable: Vec<ToolCapabilityIssue>,
    pub optional_missing: Vec<ToolCapabilityIssue>,
}

impl ToolCapabilityEvaluation {
    pub fn is_callable(&self) -> bool {
        self.unavailable.is_empty()
    }
}

pub trait BinaryProbe: Send + Sync {
    fn resolve(
        &self,
        name: &str,
        path: Option<&str>,
        cwd: &Path,
        budget: Duration,
    ) -> BinaryProbeStatus;
}

#[derive(Debug, Default)]
pub struct SystemBinaryProbe;

impl BinaryProbe for SystemBinaryProbe {
    fn resolve(
        &self,
        name: &str,
        path: Option<&str>,
        cwd: &Path,
        budget: Duration,
    ) -> BinaryProbeStatus {
        if budget.is_zero() {
            return BinaryProbeStatus::Unknown("probe budget exhausted".to_string());
        }
        resolve_on_path_bounded(name, path, cwd, budget)
    }
}

#[derive(Clone)]
pub struct CapabilityProbeCache {
    probe: Arc<dyn BinaryProbe>,
    budget: Duration,
    cache: Arc<Mutex<HashMap<ProbeCacheKey, BTreeMap<String, BinaryProbeStatus>>>>,
}

impl Default for CapabilityProbeCache {
    fn default() -> Self {
        Self::new(Arc::new(SystemBinaryProbe), Duration::from_millis(250))
    }
}

impl CapabilityProbeCache {
    pub fn new(probe: Arc<dyn BinaryProbe>, budget: Duration) -> Self {
        Self {
            probe,
            budget,
            cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn probe_many(
        &self,
        names: impl IntoIterator<Item = String>,
        env: &HashMap<String, String>,
        cwd: &Path,
        target: ExecutionTarget,
    ) -> BTreeMap<String, BinaryProbeStatus> {
        let mut names = names.into_iter().collect::<BTreeSet<_>>();
        if names.is_empty() {
            return BTreeMap::new();
        }
        let path = effective_path(env);
        let key = ProbeCacheKey {
            target,
            path_hash: path_hash(path.as_deref()),
            names: names.iter().cloned().collect(),
        };
        if let Some(cached) = self.cache.lock().unwrap().get(&key).cloned() {
            return cached;
        }
        let mut out = BTreeMap::new();
        for name in std::mem::take(&mut names) {
            let status = if target == ExecutionTarget::Container && container_provides(&name) {
                BinaryProbeStatus::ProvidedByContainer
            } else {
                self.probe.resolve(&name, path.as_deref(), cwd, self.budget)
            };
            out.insert(name, status);
        }
        self.cache.lock().unwrap().insert(key, out.clone());
        out
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ProbeCacheKey {
    target: ExecutionTarget,
    path_hash: String,
    names: Vec<String>,
}

pub fn default_probe_cache() -> CapabilityProbeCache {
    static CACHE: std::sync::OnceLock<CapabilityProbeCache> = std::sync::OnceLock::new();
    CACHE.get_or_init(CapabilityProbeCache::default).clone()
}

pub fn evaluate_tool_requirements(
    tool_name: &str,
    requirements: &[BinaryRequirement],
    env: &HashMap<String, String>,
    cwd: &Path,
    target: ExecutionTarget,
    cache: &CapabilityProbeCache,
) -> ToolCapabilityEvaluation {
    let results = cache.probe_many(
        requirements
            .iter()
            .map(|requirement| requirement.name.clone()),
        env,
        cwd,
        target,
    );
    let mut evaluation = ToolCapabilityEvaluation::default();
    for requirement in requirements {
        let status = results
            .get(&requirement.name)
            .cloned()
            .unwrap_or(BinaryProbeStatus::Unknown(
                "probe result missing".to_string(),
            ));
        if status.is_available() {
            continue;
        }
        let issue = ToolCapabilityIssue {
            tool: tool_name.to_string(),
            requirement: requirement.clone(),
            status,
            availability: crate::mcp::builtin::Availability::unavailable(format!(
                "`{}` is not available on the {:?} execution target",
                requirement.name, target
            )),
        };
        match requirement.kind {
            BinaryRequirementKind::Required => evaluation.unavailable.push(issue),
            BinaryRequirementKind::Optional => evaluation.optional_missing.push(issue),
        }
    }
    evaluation
}

pub fn missing_required_notice(
    issues: impl IntoIterator<Item = ToolCapabilityIssue>,
    platform: RemedyPlatform,
) -> Option<String> {
    let mut by_binary = BTreeMap::<String, ToolCapabilityIssue>::new();
    for issue in issues {
        by_binary
            .entry(issue.requirement.name.clone())
            .or_insert(issue);
    }
    if by_binary.is_empty() {
        return None;
    }
    let mut parts = Vec::new();
    for (binary, issue) in by_binary {
        parts.push(format!(
            "`{binary}` missing for `{}`. {}",
            issue.tool,
            issue.render_remedy(platform)
        ));
    }
    Some(format!(
        "Required command capability unavailable: {}",
        parts.join(" ")
    ))
}

pub fn first_copyable_install_command(
    issues: impl IntoIterator<Item = ToolCapabilityIssue>,
    platform: RemedyPlatform,
) -> Option<String> {
    let mut by_binary = BTreeMap::<String, ToolCapabilityIssue>::new();
    for issue in issues {
        by_binary
            .entry(issue.requirement.name.clone())
            .or_insert(issue);
    }
    by_binary.into_values().find_map(|issue| {
        issue
            .requirement
            .remedy
            .command_for_platform(platform)
            .map(str::to_string)
    })
}

pub fn declared_missing_binary_remedy(
    binary: &str,
    requirements: impl IntoIterator<Item = BinaryRequirement>,
    platform: RemedyPlatform,
) -> Option<String> {
    requirements
        .into_iter()
        .find(|requirement| requirement.name == binary)
        .map(|requirement| requirement.remedy.render_for_platform(platform))
}

pub fn resolve_binary(name: &str) -> Option<PathBuf> {
    let cwd = std::env::current_dir().ok()?;
    let env = std::env::var("PATH")
        .ok()
        .map(|path| HashMap::from([("PATH".to_string(), path)]))
        .unwrap_or_default();
    resolve_binary_with_env(name, &env, &cwd)
}

pub fn resolve_binary_with_env(
    name: &str,
    env: &HashMap<String, String>,
    cwd: &Path,
) -> Option<PathBuf> {
    let result =
        default_probe_cache().probe_many(vec![name.to_string()], env, cwd, ExecutionTarget::Host);
    match result.get(name) {
        Some(BinaryProbeStatus::Present(path)) => Some(path.clone()),
        _ => None,
    }
}

pub fn resolve_on_path(name: &str, path: Option<&str>, cwd: &Path) -> Option<PathBuf> {
    which::which_in(name, path, cwd).ok()
}

fn resolve_on_path_bounded(
    name: &str,
    path: Option<&str>,
    cwd: &Path,
    budget: Duration,
) -> BinaryProbeStatus {
    let name = name.to_string();
    let path = path.map(str::to_string);
    let cwd = cwd.to_path_buf();
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let resolved = resolve_on_path(&name, path.as_deref(), &cwd);
        let _ = tx.send(resolved);
    });
    match rx.recv_timeout(budget) {
        Ok(Some(path)) => BinaryProbeStatus::Present(path),
        Ok(None) => BinaryProbeStatus::Missing,
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            BinaryProbeStatus::Unknown("probe budget exhausted".to_string())
        }
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            BinaryProbeStatus::Unknown("probe worker failed".to_string())
        }
    }
}

pub fn path_hash(path: Option<&str>) -> String {
    let mut hasher = Sha256::new();
    hasher.update(path.unwrap_or("").as_bytes());
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub fn effective_path(env: &HashMap<String, String>) -> Option<String> {
    env.get("PATH")
        .cloned()
        .or_else(|| std::env::var("PATH").ok())
}

pub fn container_provides(binary: &str) -> bool {
    matches!(
        binary,
        "ca-certificates"
            | "curl"
            | "git"
            | "jq"
            | "rg"
            | "ripgrep"
            | "python"
            | "python3"
            | "pip"
            | "pip3"
            | "node"
            | "nodejs"
            | "npm"
    )
}

pub fn common_remedy(binary: &str) -> CapabilityRemedy {
    match binary {
        "rg" | "ripgrep" => CapabilityRemedy::with_unix_command(
            "Install ripgrep or use `search`/`grep` tools instead.",
            "sudo apt-get install ripgrep",
        ),
        "fd" => CapabilityRemedy::with_unix_command(
            "Install fd-find or use `tree`/`glob` tools instead.",
            "sudo apt-get install fd-find",
        ),
        "gsed" => CapabilityRemedy::with_unix_command(
            "Install GNU sed if macOS-compatible sed behavior is required.",
            "brew install gnu-sed",
        ),
        "jq" => CapabilityRemedy::with_unix_command(
            "Install jq, or use Cockpit's bundled `cockpit jq` applet in host sessions.",
            "sudo apt-get install jq",
        ),
        "curl" => CapabilityRemedy::with_unix_command(
            "Install curl or use another configured fetch provider.",
            "sudo apt-get install curl",
        ),
        "python" | "python3" => CapabilityRemedy::with_unix_command(
            "Install Python 3 and ensure it is on PATH.",
            "sudo apt-get install python3",
        ),
        "node" | "nodejs" | "npm" => CapabilityRemedy::with_unix_command(
            "Install Node.js/npm and ensure it is on PATH.",
            "sudo apt-get install nodejs npm",
        ),
        "docker" => CapabilityRemedy::with_unix_command(
            "Install Docker or Podman to use container sandbox mode.",
            "sudo apt-get install docker.io",
        ),
        "podman" => CapabilityRemedy::with_unix_command(
            "Install Podman or Docker to use container sandbox mode.",
            "sudo apt-get install podman",
        ),
        other => CapabilityRemedy::prose(format!("Install `{other}` and ensure it is on PATH.")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Default)]
    struct CountingProbe {
        calls: AtomicUsize,
        present: BTreeSet<String>,
    }

    impl CountingProbe {
        fn with_present(names: &[&str]) -> Self {
            Self {
                calls: AtomicUsize::new(0),
                present: names.iter().map(|name| (*name).to_string()).collect(),
            }
        }
    }

    impl BinaryProbe for CountingProbe {
        fn resolve(
            &self,
            name: &str,
            _path: Option<&str>,
            _cwd: &Path,
            _budget: Duration,
        ) -> BinaryProbeStatus {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.present.contains(name) {
                BinaryProbeStatus::Present(PathBuf::from(format!("/usr/bin/{name}")))
            } else {
                BinaryProbeStatus::Missing
            }
        }
    }

    #[test]
    fn capability_probe_cache_reuses_identical_path_and_reprobes_changed_path() {
        let probe = Arc::new(CountingProbe::with_present(&["rg"]));
        let cache = CapabilityProbeCache::new(probe.clone(), Duration::from_millis(1));
        let cwd = Path::new("/");
        let env_a = HashMap::from([("PATH".to_string(), "/a".to_string())]);
        let env_b = HashMap::from([("PATH".to_string(), "/b".to_string())]);

        let names = vec!["rg".to_string(), "fd".to_string()];
        cache.probe_many(names.clone(), &env_a, cwd, ExecutionTarget::Host);
        cache.probe_many(names.clone(), &env_a, cwd, ExecutionTarget::Host);
        assert_eq!(probe.calls.load(Ordering::SeqCst), 2);

        cache.probe_many(names, &env_b, cwd, ExecutionTarget::Host);
        assert_eq!(probe.calls.load(Ordering::SeqCst), 4);
    }

    #[test]
    fn capability_container_target_treats_image_binaries_as_present() {
        let probe = Arc::new(CountingProbe::default());
        let cache = CapabilityProbeCache::new(probe.clone(), Duration::from_millis(1));
        let env = HashMap::new();
        let result = cache.probe_many(
            vec!["jq".to_string()],
            &env,
            Path::new("/"),
            ExecutionTarget::Container,
        );

        assert_eq!(result["jq"], BinaryProbeStatus::ProvidedByContainer);
        assert_eq!(probe.calls.load(Ordering::SeqCst), 0);

        let host_result = cache.probe_many(
            vec!["jq".to_string()],
            &env,
            Path::new("/"),
            ExecutionTarget::Host,
        );
        assert_eq!(host_result["jq"], BinaryProbeStatus::Missing);
        assert_eq!(probe.calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn capability_required_and_optional_requirements_are_classified() {
        let probe = Arc::new(CountingProbe::with_present(&["present"]));
        let cache = CapabilityProbeCache::new(probe, Duration::from_millis(1));
        let requirements = vec![
            BinaryRequirement::required("missing", common_remedy("missing")),
            BinaryRequirement::optional("other", common_remedy("other")),
            BinaryRequirement::required("present", common_remedy("present")),
        ];

        let result = evaluate_tool_requirements(
            "demo",
            &requirements,
            &HashMap::new(),
            Path::new("/"),
            ExecutionTarget::Host,
            &cache,
        );

        assert_eq!(result.unavailable.len(), 1);
        assert_eq!(result.unavailable[0].requirement.name, "missing");
        assert!(!result.unavailable[0].availability.is_available());
        assert!(
            result.unavailable[0]
                .availability
                .reason()
                .is_some_and(|reason| reason.contains("missing"))
        );
        assert_eq!(result.optional_missing.len(), 1);
        assert_eq!(result.optional_missing[0].requirement.name, "other");
        assert!(
            missing_required_notice(result.unavailable, RemedyPlatform::Unix)
                .unwrap()
                .contains("`missing` missing for `demo`")
        );
    }

    #[test]
    fn capability_remedy_renders_command_or_prose_by_platform() {
        let remedy = CapabilityRemedy::with_unix_command("Install demo.", "apt install demo");
        assert_eq!(
            remedy.render_for_platform(RemedyPlatform::Unix),
            "Install demo. Fix: apt install demo"
        );
        assert_eq!(
            remedy.render_for_platform(RemedyPlatform::Windows),
            "Install demo."
        );
    }

    struct BudgetAwareProbe;

    impl BinaryProbe for BudgetAwareProbe {
        fn resolve(
            &self,
            _name: &str,
            _path: Option<&str>,
            _cwd: &Path,
            budget: Duration,
        ) -> BinaryProbeStatus {
            if budget < Duration::from_secs(1) {
                BinaryProbeStatus::Unknown("probe exceeded budget".to_string())
            } else {
                BinaryProbeStatus::Missing
            }
        }
    }

    #[test]
    fn capability_probe_budget_can_degrade_to_unknown_without_sleeping() {
        let cache = CapabilityProbeCache::new(Arc::new(BudgetAwareProbe), Duration::from_millis(1));
        let result = cache.probe_many(
            vec!["slow-tool".to_string()],
            &HashMap::new(),
            Path::new("/"),
            ExecutionTarget::Host,
        );

        assert_eq!(
            result["slow-tool"],
            BinaryProbeStatus::Unknown("probe exceeded budget".to_string())
        );
    }

    #[test]
    fn capability_system_probe_returns_unknown_when_budget_is_exhausted() {
        assert_eq!(
            SystemBinaryProbe.resolve("anything", Some("/bin"), Path::new("/"), Duration::ZERO),
            BinaryProbeStatus::Unknown("probe budget exhausted".to_string())
        );
    }
}
