use std::collections::{BTreeMap, HashMap, HashSet};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use tokio::sync::{Mutex, OnceCell};
use uuid::Uuid;

use crate::tools::command_resource_profiles::CommandResourcePlan;
use crate::tools::sandbox_mode::SandboxMode;
use crate::tools::shell_sandbox::SandboxPathAccess;

pub use crate::daemon::proto::{
    ContainerAvailability, ContainerRuntimeKind, ContainerUnavailableReason,
};

pub const DEFAULT_DOCKERFILE: &str = r#"# Cockpit default sandbox image. Edit freely — Cockpit rebuilds when this changes.
# Cockpit runs commands as your host user (uid/gid mapping) so files created in
# the mounted working directory stay owned by you. Do not add a fixed USER.
FROM ubuntu:24.04

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl git jq ripgrep python3 python3-pip python3-venv \
    && rm -rf /var/lib/apt/lists/*

# Node.js 22 LTS
RUN curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*
"#;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ContainerRuntime {
    pub kind: ContainerRuntimeKind,
    pub binary: PathBuf,
}

#[cfg(test)]
pub fn detect_runtime_with<F>(mut which: F, harness_in_container: bool) -> ContainerAvailability
where
    F: FnMut(&str) -> Option<PathBuf>,
{
    let runtime = which("docker")
        .map(|binary| ContainerRuntime {
            kind: ContainerRuntimeKind::Docker,
            binary,
        })
        .or_else(|| {
            which("podman").map(|binary| ContainerRuntime {
                kind: ContainerRuntimeKind::Podman,
                binary,
            })
        });
    if harness_in_container {
        return ContainerAvailability {
            runtime: runtime.as_ref().map(|r| r.kind),
            harness_in_container: true,
            available: false,
            reason: Some(ContainerUnavailableReason::HarnessInContainer),
        };
    }
    match runtime {
        Some(runtime) => ContainerAvailability {
            runtime: Some(runtime.kind),
            harness_in_container: false,
            available: true,
            reason: None,
        },
        None => ContainerAvailability {
            runtime: None,
            harness_in_container: false,
            available: false,
            reason: Some(ContainerUnavailableReason::NoRuntime),
        },
    }
}

#[cfg(any(test, feature = "test-support"))]
thread_local! {
    static DETECT_RUNTIME_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(any(test, feature = "test-support"))]
pub fn reset_detect_runtime_call_count() {
    DETECT_RUNTIME_CALLS.with(|calls| calls.set(0));
}

#[cfg(any(test, feature = "test-support"))]
pub fn detect_runtime_call_count() -> usize {
    DETECT_RUNTIME_CALLS.with(std::cell::Cell::get)
}

pub fn detect_runtime() -> (Option<ContainerRuntime>, ContainerAvailability) {
    #[cfg(any(test, feature = "test-support"))]
    DETECT_RUNTIME_CALLS.with(|calls| calls.set(calls.get() + 1));
    let harness = harness_in_container();
    let docker = crate::capabilities::resolve_binary("docker");
    let podman = crate::capabilities::resolve_binary("podman");
    let runtime = docker
        .map(|binary| ContainerRuntime {
            kind: ContainerRuntimeKind::Docker,
            binary,
        })
        .or_else(|| {
            podman.map(|binary| ContainerRuntime {
                kind: ContainerRuntimeKind::Podman,
                binary,
            })
        });
    let availability = if harness {
        ContainerAvailability {
            runtime: runtime.as_ref().map(|r| r.kind),
            harness_in_container: true,
            available: false,
            reason: Some(ContainerUnavailableReason::HarnessInContainer),
        }
    } else if let Some(runtime) = &runtime {
        ContainerAvailability {
            runtime: Some(runtime.kind),
            harness_in_container: false,
            available: true,
            reason: None,
        }
    } else {
        ContainerAvailability {
            runtime: None,
            harness_in_container: false,
            available: false,
            reason: Some(ContainerUnavailableReason::NoRuntime),
        }
    };
    (runtime, availability)
}

pub fn harness_in_container() -> bool {
    if Path::new("/.dockerenv").exists() || Path::new("/run/.containerenv").exists() {
        return true;
    }
    for path in ["/proc/1/cgroup", "/proc/self/mountinfo"] {
        if let Ok(body) = std::fs::read_to_string(path)
            && harness_markers(&body)
        {
            return true;
        }
    }
    false
}

pub fn harness_markers(body: &str) -> bool {
    let body = body.to_ascii_lowercase();
    ["docker", "containerd", "kubepods", "lxc", "podman"]
        .iter()
        .any(|needle| body.contains(needle))
}

#[derive(Debug, Clone)]
pub struct ContainerManager {
    runtime: Option<ContainerRuntime>,
    availability: ContainerAvailability,
    build_locks: Arc<Mutex<HashMap<String, Arc<Mutex<()>>>>>,
    create_locks: Arc<Mutex<HashMap<String, Arc<Mutex<()>>>>>,
}

impl ContainerManager {
    pub fn detect() -> Self {
        let (runtime, availability) = detect_runtime();
        Self {
            runtime,
            availability,
            build_locks: Arc::new(Mutex::new(HashMap::new())),
            create_locks: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn availability(&self) -> &ContainerAvailability {
        &self.availability
    }

    pub fn ensure_available(&self) -> Result<&ContainerRuntime, String> {
        if !self.availability.available {
            return Err(self
                .availability
                .unavailable_reason_text()
                .unwrap_or_else(|| "container sandbox is unavailable".to_string()));
        }
        self.runtime
            .as_ref()
            .ok_or_else(|| "container runtime missing".to_string())
    }

    async fn build_lock(&self, tag: &str) -> Arc<Mutex<()>> {
        let mut locks = self.build_locks.lock().await;
        locks
            .entry(tag.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }

    pub async fn image_exists(&self, tag: &str) -> Result<bool> {
        let runtime = self
            .runtime
            .as_ref()
            .context("container runtime unavailable")?;
        let status = tokio::process::Command::new(&runtime.binary)
            .arg("image")
            .arg("inspect")
            .arg(tag)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .await
            .with_context(|| format!("running {} image inspect", runtime.kind.as_str()))?;
        Ok(status.success())
    }

    pub async fn ensure_image(&self, dockerfile: &Path, bytes: &[u8]) -> Result<String> {
        let tag = image_tag(bytes, &[]);
        let lock = self.build_lock(&tag).await;
        let _guard = lock.lock().await;
        if self.image_exists(&tag).await? {
            return Ok(tag);
        }
        let runtime = self
            .runtime
            .as_ref()
            .context("container runtime unavailable")?;
        let context = dockerfile.parent().unwrap_or_else(|| Path::new("."));
        let output = tokio::process::Command::new(&runtime.binary)
            .arg("build")
            .arg("-t")
            .arg(&tag)
            .arg("-f")
            .arg(dockerfile)
            .arg(context)
            .output()
            .await
            .with_context(|| format!("running {} build", runtime.kind.as_str()))?;
        if output.status.success() {
            Ok(tag)
        } else {
            let mut log = String::from_utf8_lossy(&output.stdout).into_owned();
            log.push_str(&String::from_utf8_lossy(&output.stderr));
            anyhow::bail!("container image build failed: {}", tail_text(&log, 4096));
        }
    }

    async fn create_lock(&self, name: &str) -> Arc<Mutex<()>> {
        let mut locks = self.create_locks.lock().await;
        locks
            .entry(name.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }

    pub async fn container_exists(&self, name: &str) -> Result<bool> {
        let runtime = self
            .runtime
            .as_ref()
            .context("container runtime unavailable")?;
        let status = tokio::process::Command::new(&runtime.binary)
            .arg("container")
            .arg("inspect")
            .arg(name)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .await
            .with_context(|| format!("running {} container inspect", runtime.kind.as_str()))?;
        Ok(status.success())
    }

    pub async fn ensure_container(
        &self,
        session_id: Uuid,
        image: &str,
        mode: SandboxMode,
        map: &MountMap,
        profile_mounts: &[ContainerMount],
        network_enabled: bool,
    ) -> Result<String> {
        let runtime = self
            .runtime
            .as_ref()
            .context("container runtime unavailable")?;
        let name = container_name(session_id);
        let lock = self.create_lock(&name).await;
        let _guard = lock.lock().await;
        if self.container_exists(&name).await? {
            return Ok(name);
        }
        let args = build_create_args(
            runtime.kind,
            session_id,
            image,
            mode,
            map,
            profile_mounts,
            network_enabled,
            HostPlatform::current(),
        );
        let output = tokio::process::Command::new(&runtime.binary)
            .args(args)
            .output()
            .await
            .with_context(|| format!("running {} container create", runtime.kind.as_str()))?;
        if output.status.success() {
            Ok(name)
        } else {
            let mut log = String::from_utf8_lossy(&output.stdout).into_owned();
            log.push_str(&String::from_utf8_lossy(&output.stderr));
            anyhow::bail!("container create failed: {}", tail_text(&log, 4096));
        }
    }

    pub async fn remove_container(&self, session_id: Uuid) -> Result<()> {
        let Some(runtime) = self.runtime.as_ref() else {
            return Ok(());
        };
        let _ = tokio::process::Command::new(&runtime.binary)
            .arg("rm")
            .arg("-f")
            .arg(container_name(session_id))
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .await;
        Ok(())
    }

    pub fn exec_command(
        &self,
        container: &str,
        cwd: &Path,
        env: &BTreeMap<String, String>,
        command: &str,
    ) -> Result<tokio::process::Command> {
        let runtime = self.ensure_available().map_err(anyhow::Error::msg)?;
        let mut cmd = tokio::process::Command::new(&runtime.binary);
        cmd.args(build_exec_args(container, cwd, env, command));
        Ok(cmd)
    }
}

pub fn container_manager() -> &'static OnceCell<ContainerManager> {
    static CELL: OnceCell<ContainerManager> = OnceCell::const_new();
    &CELL
}

pub fn initial_availability_unknown() -> ContainerAvailability {
    ContainerAvailability {
        runtime: None,
        harness_in_container: false,
        available: false,
        reason: Some(ContainerUnavailableReason::NoRuntime),
    }
}

pub fn availability_snapshot() -> ContainerAvailability {
    container_manager()
        .get()
        .map(|manager| manager.availability().clone())
        .unwrap_or_else(|| detect_runtime().1)
}

pub fn default_config_dir() -> Result<PathBuf> {
    if let Ok(s) = std::env::var("XDG_CONFIG_HOME")
        && !s.trim().is_empty()
    {
        return Ok(PathBuf::from(s).join("cockpit"));
    }
    if let Some(dir) = dirs::config_dir() {
        return Ok(dir.join("cockpit"));
    }
    let home = dirs::home_dir().context("could not locate home dir")?;
    Ok(home.join(".config").join("cockpit"))
}

pub fn resolve_dockerfile_for_session(
    project_root: &Path,
    sandbox_config: &crate::config::extended::SandboxConfig,
) -> Result<ResolvedDockerfile> {
    let trusted_project =
        crate::config::trust::project_config_allowed(&project_root.join(".cockpit"));
    let configured = sandbox_config.dockerfile.as_ref().map(|path| {
        if path.is_absolute() {
            path.clone()
        } else {
            project_root.join(path)
        }
    });
    resolve_dockerfile(
        project_root,
        trusted_project,
        configured,
        None,
        &default_config_dir()?,
    )
}

pub fn image_tag(dockerfile_bytes: &[u8], build_args: &[(&str, &str)]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(dockerfile_bytes);
    for (key, value) in build_args {
        hasher.update([0]);
        hasher.update(key.as_bytes());
        hasher.update([b'=']);
        hasher.update(value.as_bytes());
    }
    let hex = crate::intel::hex_lower(&hasher.finalize());
    format!("cockpit-sandbox:{}", &hex[..16])
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DockerfileSource {
    ConfigProject,
    ConfigGlobal,
    ProjectConvention,
    GlobalDefault,
    BuiltinDefault,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedDockerfile {
    pub path: PathBuf,
    pub source: DockerfileSource,
    pub ignored_project_reason: Option<String>,
}

pub fn materialize_default_dockerfile(global_config_dir: &Path) -> Result<PathBuf> {
    let path = global_config_dir.join("sandbox").join("Dockerfile");
    if !path.exists() {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        std::fs::write(&path, DEFAULT_DOCKERFILE)
            .with_context(|| format!("writing {}", path.display()))?;
    }
    Ok(path)
}

pub fn resolve_dockerfile(
    project_root: &Path,
    trusted_project: bool,
    project_config_dockerfile: Option<PathBuf>,
    global_config_dockerfile: Option<PathBuf>,
    global_config_dir: &Path,
) -> Result<ResolvedDockerfile> {
    let mut ignored_project_reason = None;
    if trusted_project {
        if let Some(path) = project_config_dockerfile {
            return Ok(ResolvedDockerfile {
                path,
                source: DockerfileSource::ConfigProject,
                ignored_project_reason: None,
            });
        }
        let convention = project_root.join(".cockpit/sandbox/Dockerfile");
        if convention.exists() {
            return Ok(ResolvedDockerfile {
                path: convention,
                source: DockerfileSource::ProjectConvention,
                ignored_project_reason: None,
            });
        }
    } else if project_config_dockerfile.is_some()
        || project_root.join(".cockpit/sandbox/Dockerfile").exists()
    {
        ignored_project_reason =
            Some("project Dockerfile ignored because workspace is not trusted".to_string());
    }
    if let Some(path) = global_config_dockerfile {
        return Ok(ResolvedDockerfile {
            path,
            source: DockerfileSource::ConfigGlobal,
            ignored_project_reason,
        });
    }
    let global = global_config_dir.join("sandbox").join("Dockerfile");
    if global.exists() {
        return Ok(ResolvedDockerfile {
            path: global,
            source: DockerfileSource::GlobalDefault,
            ignored_project_reason,
        });
    }
    let path = materialize_default_dockerfile(global_config_dir)?;
    Ok(ResolvedDockerfile {
        path,
        source: DockerfileSource::BuiltinDefault,
        ignored_project_reason,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountMap {
    pub host_root: PathBuf,
    pub container_root: PathBuf,
}

impl MountMap {
    pub fn unix(host_root: PathBuf) -> Self {
        Self {
            container_root: host_root.clone(),
            host_root,
        }
    }

    pub fn windows(host_root: PathBuf) -> Self {
        Self {
            host_root,
            container_root: PathBuf::from("/workspace"),
        }
    }

    pub fn for_current_platform(host_root: PathBuf) -> Self {
        if cfg!(windows) {
            Self::windows(host_root)
        } else {
            Self::unix(host_root)
        }
    }

    pub fn to_container(&self, host_path: &Path) -> Option<PathBuf> {
        let rel = path_relative_to(host_path, &self.host_root)?;
        if rel.as_os_str().is_empty() {
            return Some(self.container_root.clone());
        }
        Some(self.container_root.join(rel))
    }
}

fn path_relative_to<'a>(path: &'a Path, root: &'a Path) -> Option<PathBuf> {
    let path = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    let root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
    path.strip_prefix(root).ok().map(Path::to_path_buf)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerMount {
    pub host: PathBuf,
    pub container: PathBuf,
    pub read_only: bool,
}

impl ContainerMount {
    pub fn volume_arg(&self) -> OsString {
        let mut value = OsString::new();
        value.push(self.host.as_os_str());
        value.push(":");
        value.push(self.container.as_os_str());
        if self.read_only {
            value.push(":ro");
        }
        value
    }
}

pub fn project_mount(mode: SandboxMode, map: &MountMap) -> ContainerMount {
    ContainerMount {
        host: map.host_root.clone(),
        container: map.container_root.clone(),
        read_only: mode.project_read_only(),
    }
}

pub fn resource_profile_mounts(
    plan: &CommandResourcePlan,
    map: &MountMap,
    native_windows: bool,
) -> Vec<ContainerMount> {
    let mut seen = HashSet::new();
    let mut mounts = Vec::new();
    for root in &plan.allow_paths {
        if path_relative_to(&root.path, &map.host_root).is_some() {
            continue;
        }
        if native_windows {
            continue;
        }
        let key = root
            .path
            .canonicalize()
            .unwrap_or_else(|_| root.path.clone());
        if !seen.insert(key.clone()) {
            continue;
        }
        mounts.push(ContainerMount {
            host: key.clone(),
            container: key,
            read_only: matches!(root.access, SandboxPathAccess::Read),
        });
    }
    mounts
}

pub fn container_env(
    session_env: &HashMap<String, String>,
    scrub: &[(String, String)],
) -> BTreeMap<String, String> {
    let scrubbed = scrub
        .iter()
        .map(|(k, _)| k.as_str())
        .collect::<HashSet<_>>();
    let mut out = BTreeMap::new();
    for (key, value) in session_env {
        if scrubbed.contains(key.as_str()) || container_owned_env(key) || secret_like_env(key) {
            continue;
        }
        out.insert(key.clone(), value.clone());
    }
    out.insert("HOME".to_string(), "/tmp".to_string());
    out.insert("TMPDIR".to_string(), "/tmp".to_string());
    out
}

fn container_owned_env(key: &str) -> bool {
    matches!(key, "PATH" | "HOME" | "TMPDIR" | "TMP" | "TEMP" | "SHELL") || key.starts_with("LD_")
}

fn secret_like_env(key: &str) -> bool {
    let key = key.to_ascii_uppercase();
    ["TOKEN", "SECRET", "PASSWORD", "PASS", "KEY", "CREDENTIAL"]
        .iter()
        .any(|needle| key.contains(needle))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostPlatform {
    Linux,
    Macos,
    Windows,
}

impl HostPlatform {
    pub fn current() -> Self {
        if cfg!(target_os = "windows") {
            Self::Windows
        } else if cfg!(target_os = "macos") {
            Self::Macos
        } else {
            Self::Linux
        }
    }
}

#[cfg(unix)]
fn host_uid_gid() -> Option<(u32, u32)> {
    Some((unsafe { libc::geteuid() }, unsafe { libc::getegid() }))
}

#[cfg(not(unix))]
fn host_uid_gid() -> Option<(u32, u32)> {
    None
}

pub fn uid_flags(kind: ContainerRuntimeKind, platform: HostPlatform) -> Vec<OsString> {
    if platform != HostPlatform::Linux {
        return Vec::new();
    }
    match kind {
        ContainerRuntimeKind::Docker => host_uid_gid()
            .map(|(uid, gid)| {
                vec![
                    OsString::from("--user"),
                    OsString::from(format!("{uid}:{gid}")),
                ]
            })
            .unwrap_or_default(),
        ContainerRuntimeKind::Podman => vec![OsString::from("--userns=keep-id")],
    }
}

pub fn container_name(session_id: Uuid) -> String {
    format!("cockpit-sess-{}", session_id.simple())
}

#[allow(clippy::too_many_arguments)]
pub fn build_create_args(
    runtime: ContainerRuntimeKind,
    session_id: Uuid,
    image: &str,
    mode: SandboxMode,
    map: &MountMap,
    profile_mounts: &[ContainerMount],
    network_enabled: bool,
    platform: HostPlatform,
) -> Vec<OsString> {
    let mut args = vec![
        OsString::from("run"),
        OsString::from("-d"),
        OsString::from("--name"),
        OsString::from(container_name(session_id)),
        OsString::from("--label"),
        OsString::from(format!("cockpit.session={session_id}")),
    ];
    args.extend(uid_flags(runtime, platform));
    if !network_enabled {
        args.push(OsString::from("--network"));
        args.push(OsString::from("none"));
    }
    args.push(OsString::from("--tmpfs"));
    args.push(OsString::from("/tmp"));
    args.push(OsString::from("-e"));
    args.push(OsString::from("HOME=/tmp"));
    args.push(OsString::from("-v"));
    args.push(project_mount(mode, map).volume_arg());
    for mount in profile_mounts {
        args.push(OsString::from("-v"));
        args.push(mount.volume_arg());
    }
    args.push(OsString::from(image));
    args.push(OsString::from("sleep"));
    args.push(OsString::from("infinity"));
    args
}

pub fn build_exec_args(
    container: &str,
    cwd: &Path,
    env: &BTreeMap<String, String>,
    command: &str,
) -> Vec<OsString> {
    let mut args = vec![
        OsString::from("exec"),
        OsString::from("-i"),
        OsString::from("-w"),
        cwd.as_os_str().to_os_string(),
    ];
    for (key, value) in env {
        args.push(OsString::from("--env"));
        args.push(OsString::from(format!("{key}={value}")));
    }
    args.push(OsString::from(container));
    args.push(OsString::from("sh"));
    args.push(OsString::from("-c"));
    args.push(OsString::from(command));
    args
}

pub fn tail_text(text: &str, max_bytes: usize) -> String {
    if text.len() <= max_bytes {
        return text.to_string();
    }
    let start = text.len().saturating_sub(max_bytes);
    let start = text
        .char_indices()
        .find_map(|(idx, _)| (idx >= start).then_some(idx))
        .unwrap_or(start);
    format!("…{}", &text[start..])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::shell_sandbox::{ExtraSandboxPath, SandboxPathAccess};

    #[test]
    fn runtime_detection_prefers_docker_and_blocks_nested_container() {
        let avail = detect_runtime_with(
            |name| Some(PathBuf::from(format!("/usr/bin/{name}"))),
            false,
        );
        assert_eq!(avail.runtime, Some(ContainerRuntimeKind::Docker));
        assert!(avail.available);

        let avail = detect_runtime_with(
            |name| (name == "podman").then(|| PathBuf::from("/usr/bin/podman")),
            false,
        );
        assert_eq!(avail.runtime, Some(ContainerRuntimeKind::Podman));
        assert!(avail.available);

        let avail = detect_runtime_with(|_| None, false);
        assert_eq!(avail.reason, Some(ContainerUnavailableReason::NoRuntime));

        let avail =
            detect_runtime_with(|name| Some(PathBuf::from(format!("/usr/bin/{name}"))), true);
        assert_eq!(
            avail.reason,
            Some(ContainerUnavailableReason::HarnessInContainer)
        );
        assert!(!avail.available);
    }

    #[test]
    fn harness_marker_detection_matches_common_container_strings() {
        assert!(harness_markers("1:name=systemd:/docker/abc"));
        assert!(harness_markers("kubepods-burstable-pod"));
        assert!(!harness_markers("0::/user.slice/session-1.scope"));
    }

    #[test]
    fn image_tag_changes_with_dockerfile_content() {
        let a = image_tag(b"FROM ubuntu:24.04\n", &[]);
        let b = image_tag(b"FROM ubuntu:24.04\n", &[]);
        let c = image_tag(b"FROM debian:stable\n", &[]);
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert!(a.starts_with("cockpit-sandbox:"));
    }

    #[test]
    fn materialize_default_dockerfile_never_overwrites_existing_file() {
        let tmp = tempfile::tempdir().unwrap();
        let path = materialize_default_dockerfile(tmp.path()).unwrap();
        assert!(
            std::fs::read_to_string(&path)
                .unwrap()
                .contains("FROM ubuntu:24.04")
        );
        std::fs::write(&path, "FROM scratch\n").unwrap();
        let again = materialize_default_dockerfile(tmp.path()).unwrap();
        assert_eq!(again, path);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "FROM scratch\n");
    }

    #[test]
    fn dockerfile_resolution_honors_trust_and_precedence() {
        let tmp = tempfile::tempdir().unwrap();
        let project = tmp.path().join("project");
        let global = tmp.path().join("global");
        std::fs::create_dir_all(project.join(".cockpit/sandbox")).unwrap();
        std::fs::create_dir_all(&global).unwrap();
        let project_convention = project.join(".cockpit/sandbox/Dockerfile");
        std::fs::write(&project_convention, "FROM project\n").unwrap();
        let cfg_project = project.join("custom.Dockerfile");
        let cfg_global = global.join("custom.Dockerfile");

        let resolved = resolve_dockerfile(
            &project,
            true,
            Some(cfg_project.clone()),
            Some(cfg_global.clone()),
            &global,
        )
        .unwrap();
        assert_eq!(resolved.path, cfg_project);
        assert_eq!(resolved.source, DockerfileSource::ConfigProject);

        let resolved =
            resolve_dockerfile(&project, true, None, Some(cfg_global.clone()), &global).unwrap();
        assert_eq!(resolved.path, project_convention);
        assert_eq!(resolved.source, DockerfileSource::ProjectConvention);

        let resolved = resolve_dockerfile(
            &project,
            false,
            Some(project.join("blocked")),
            Some(cfg_global.clone()),
            &global,
        )
        .unwrap();
        assert_eq!(resolved.path, cfg_global);
        assert!(resolved.ignored_project_reason.is_some());
    }

    #[test]
    fn mount_map_translates_windows_root_and_rejects_outside() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("repo");
        let sub = root.join("src");
        std::fs::create_dir_all(&sub).unwrap();
        let map = MountMap::windows(root.clone());
        assert_eq!(
            map.to_container(&root).unwrap(),
            PathBuf::from("/workspace")
        );
        assert_eq!(
            map.to_container(&sub).unwrap(),
            PathBuf::from("/workspace/src")
        );
        assert!(map.to_container(tmp.path()).is_none());
    }

    #[test]
    fn resource_profile_roots_map_to_mounts_and_skip_project_roots() {
        let tmp = tempfile::tempdir().unwrap();
        let project = tmp.path().join("repo");
        let inside = project.join(".cache");
        let cargo = tmp.path().join("cargo");
        let readonly = tmp.path().join("readonly");
        for dir in [&inside, &cargo, &readonly] {
            std::fs::create_dir_all(dir).unwrap();
        }
        let plan = CommandResourcePlan {
            matched: true,
            allow_paths: vec![
                ExtraSandboxPath {
                    kind: "inside".into(),
                    path: inside,
                    access: SandboxPathAccess::ReadWrite,
                },
                ExtraSandboxPath {
                    kind: "cargo".into(),
                    path: cargo.clone(),
                    access: SandboxPathAccess::ReadWrite,
                },
                ExtraSandboxPath {
                    kind: "ro".into(),
                    path: readonly.clone(),
                    access: SandboxPathAccess::Read,
                },
            ],
            invalid_roots: Vec::new(),
            metas: Vec::new(),
            unsupported_tools: Vec::new(),
        };
        let map = MountMap::unix(project);
        let mounts = resource_profile_mounts(&plan, &map, false);
        assert_eq!(mounts.len(), 2);
        assert!(mounts.iter().any(|m| m.host == cargo && !m.read_only));
        assert!(mounts.iter().any(|m| m.host == readonly && m.read_only));
        assert!(resource_profile_mounts(&plan, &map, true).is_empty());
    }

    #[test]
    fn env_builder_omits_container_owned_scrubbed_and_secret_like_vars() {
        let env = HashMap::from([
            ("PATH".to_string(), "bad".to_string()),
            ("LD_PRELOAD".to_string(), "bad".to_string()),
            ("API_TOKEN".to_string(), "secret".to_string()),
            ("KEEP_ME".to_string(), "ok".to_string()),
            ("SCRUB".to_string(), "gone".to_string()),
        ]);
        let out = container_env(&env, &[("SCRUB".to_string(), "gone".to_string())]);
        assert_eq!(out.get("KEEP_ME").map(String::as_str), Some("ok"));
        assert_eq!(out.get("HOME").map(String::as_str), Some("/tmp"));
        assert!(!out.contains_key("PATH"));
        assert!(!out.contains_key("API_TOKEN"));
        assert!(!out.contains_key("SCRUB"));
    }

    #[test]
    fn default_container_image_keeps_jq_installed() {
        assert!(
            DEFAULT_DOCKERFILE
                .split_whitespace()
                .any(|token| token == "jq"),
            "jq is required in the default sandbox image"
        );
    }

    #[test]
    fn create_and_exec_args_encode_network_mount_uid_and_env() {
        let id = Uuid::nil();
        let tmp = tempfile::tempdir().unwrap();
        let map = MountMap::unix(tmp.path().to_path_buf());
        let args = build_create_args(
            ContainerRuntimeKind::Podman,
            id,
            "cockpit-sandbox:abc",
            SandboxMode::ContainerReadonly,
            &map,
            &[],
            false,
            HostPlatform::Linux,
        );
        let rendered = args.iter().map(|s| s.to_string_lossy()).collect::<Vec<_>>();
        assert!(rendered.contains(&"--network".into()));
        assert!(rendered.contains(&"none".into()));
        assert!(rendered.contains(&"--userns=keep-id".into()));
        assert!(rendered.iter().any(|s| s.ends_with(":ro")));

        let env = BTreeMap::from([("KEEP".to_string(), "ok".to_string())]);
        let exec = build_exec_args("cockpit-sess", Path::new("/workspace"), &env, "echo hi");
        let rendered = exec.iter().map(|s| s.to_string_lossy()).collect::<Vec<_>>();
        assert_eq!(rendered[0], "exec");
        assert!(rendered.contains(&"-w".into()));
        assert!(rendered.contains(&"/workspace".into()));
        assert!(rendered.contains(&"KEEP=ok".into()));
    }
}
