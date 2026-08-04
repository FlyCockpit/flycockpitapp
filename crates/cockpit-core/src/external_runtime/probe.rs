//! Bounded probes for trusted-catalog entries; resolution-only for configured commands.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::health::{HealthCause, HealthEntry, HealthState, SpawnFailureKind};
use super::platform::configured_command_remedy;
use super::sanitize::sanitize_version_evidence;
use super::schema::{
    Applicability, CompatibilityRule, ExternalRuntimeDescriptor, FUNCTIONAL_PROBE_DEADLINE,
    HostPlatform, PROBE_CAPTURE_BUDGET, ProbePolicy, VERSION_PROBE_DEADLINE, VersionParser,
};
use crate::capabilities::{ExecutionTarget, container_provides};
use crate::process::terminate_group_sync;

/// Cancellation flag for in-flight probes.
#[derive(Debug, Default)]
pub struct CancelToken {
    cancelled: AtomicBool,
}

impl CancelToken {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }
}

/// Raw result of a trusted-catalog command probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeCommandResult {
    pub exit_code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub timed_out: bool,
    pub cancelled: bool,
    /// Typed spawn failure only — never raw OS error text with paths.
    pub spawn_error: Option<SpawnFailureKind>,
}

impl ProbeCommandResult {
    pub fn combined_capped(&self) -> String {
        let mut combined =
            Vec::with_capacity((self.stdout.len() + self.stderr.len()).min(PROBE_CAPTURE_BUDGET));
        let stdout_take = self.stdout.len().min(PROBE_CAPTURE_BUDGET);
        combined.extend_from_slice(&self.stdout[..stdout_take]);
        let remaining = PROBE_CAPTURE_BUDGET.saturating_sub(combined.len());
        let stderr_take = self.stderr.len().min(remaining);
        combined.extend_from_slice(&self.stderr[..stderr_take]);
        String::from_utf8_lossy(&combined).into_owned()
    }
}

/// Seam for PATH resolution and command execution (injectable in tests).
pub trait ProbeExecutor: Send + Sync {
    fn resolve(
        &self,
        name: &str,
        exact_path: Option<&Path>,
        path_env: Option<&str>,
        cwd: &Path,
    ) -> Option<PathBuf>;

    fn is_spawnable(&self, path: &Path) -> bool;

    /// Run program with args. Must honor deadline and cancel; kill/reap on timeout.
    fn run(
        &self,
        program: &Path,
        args: &[String],
        deadline: Duration,
        cancel: &CancelToken,
    ) -> ProbeCommandResult;
}

/// Production executor: real PATH resolution and process probes.
#[derive(Debug, Default)]
pub struct SystemProbeExecutor;

impl ProbeExecutor for SystemProbeExecutor {
    fn resolve(
        &self,
        name: &str,
        exact_path: Option<&Path>,
        path_env: Option<&str>,
        cwd: &Path,
    ) -> Option<PathBuf> {
        if let Some(path) = exact_path {
            return self.is_spawnable(path).then(|| path.to_path_buf());
        }
        let p = Path::new(name);
        if p.components().count() > 1 || p.is_absolute() {
            return self.is_spawnable(p).then(|| p.to_path_buf());
        }
        which::which_in(name, path_env, cwd)
            .ok()
            .filter(|path| self.is_spawnable(path))
    }

    fn is_spawnable(&self, path: &Path) -> bool {
        is_spawnable_file(path)
    }

    fn run(
        &self,
        program: &Path,
        args: &[String],
        deadline: Duration,
        cancel: &CancelToken,
    ) -> ProbeCommandResult {
        run_bounded_command(program, args, deadline, cancel)
    }
}

#[cfg(unix)]
fn is_spawnable_file(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    match std::fs::metadata(path) {
        Ok(meta) => meta.is_file() && meta.permissions().mode() & 0o111 != 0,
        Err(_) => false,
    }
}

#[cfg(windows)]
fn is_spawnable_file(path: &Path) -> bool {
    if !path.is_file() {
        return false;
    }
    // Only treat known executable extensions as spawnable on Windows so a
    // configured `server.txt` cannot report Available.
    // Only CreateProcess-native extensions. `.ps1` requires an interpreter and
    // is not directly spawnable via `Command::new(path)`.
    const EXTS: &[&str] = &["exe", "cmd", "bat", "com"];
    path.extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| EXTS.iter().any(|allowed| ext.eq_ignore_ascii_case(allowed)))
}

#[cfg(not(any(unix, windows)))]
fn is_spawnable_file(path: &Path) -> bool {
    path.is_file()
}

fn run_bounded_command(
    program: &Path,
    args: &[String],
    deadline: Duration,
    cancel: &CancelToken,
) -> ProbeCommandResult {
    if cancel.is_cancelled() {
        return ProbeCommandResult {
            exit_code: None,
            stdout: Vec::new(),
            stderr: Vec::new(),
            timed_out: false,
            cancelled: true,
            spawn_error: None,
        };
    }
    if deadline.is_zero() {
        return ProbeCommandResult {
            exit_code: None,
            stdout: Vec::new(),
            stderr: Vec::new(),
            timed_out: true,
            cancelled: false,
            spawn_error: None,
        };
    }

    let mut cmd = std::process::Command::new(program);
    cmd.args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // Own process group so terminate_group_sync can reap descendants.
        unsafe {
            cmd.pre_exec(|| {
                libc::setpgid(0, 0);
                Ok(())
            });
        }
    }

    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(error) => {
            return ProbeCommandResult {
                exit_code: None,
                stdout: Vec::new(),
                stderr: Vec::new(),
                timed_out: false,
                cancelled: false,
                spawn_error: Some(classify_spawn_error(&error)),
            };
        }
    };

    // Concurrent bounded readers so a noisy child cannot block the wait loop
    // or post-timeout cleanup on pipe EOF. Combined stdout+stderr ≤ 8 KiB.
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let stdout_buf = Arc::new(Mutex::new(Vec::new()));
    let stderr_buf = Arc::new(Mutex::new(Vec::new()));
    let remaining = Arc::new(AtomicUsize::new(PROBE_CAPTURE_BUDGET));
    let stdout_thread =
        spawn_bounded_reader(stdout, Arc::clone(&stdout_buf), Arc::clone(&remaining));
    let stderr_thread =
        spawn_bounded_reader(stderr, Arc::clone(&stderr_buf), Arc::clone(&remaining));

    let started = std::time::Instant::now();
    let poll = Duration::from_millis(10);
    let outcome = loop {
        if cancel.is_cancelled() {
            terminate_group_sync(&mut child, Duration::from_millis(50));
            break ProbeCommandResult {
                exit_code: None,
                stdout: Vec::new(),
                stderr: Vec::new(),
                timed_out: false,
                cancelled: true,
                spawn_error: None,
            };
        }
        match child.try_wait() {
            Ok(Some(status)) => {
                break ProbeCommandResult {
                    exit_code: status.code(),
                    stdout: Vec::new(),
                    stderr: Vec::new(),
                    timed_out: false,
                    cancelled: false,
                    spawn_error: None,
                };
            }
            Ok(None) => {
                if started.elapsed() >= deadline {
                    // Kill/reap first; never block on pipe drain before termination.
                    terminate_group_sync(&mut child, Duration::from_millis(50));
                    break ProbeCommandResult {
                        exit_code: None,
                        stdout: Vec::new(),
                        stderr: Vec::new(),
                        timed_out: true,
                        cancelled: false,
                        spawn_error: None,
                    };
                }
                // Timed park between try_wait polls (not a deadline-simulating sleep).
                std::thread::park_timeout(poll.min(deadline.saturating_sub(started.elapsed())));
            }
            Err(error) => {
                terminate_group_sync(&mut child, Duration::from_millis(50));
                break ProbeCommandResult {
                    exit_code: None,
                    stdout: Vec::new(),
                    stderr: Vec::new(),
                    timed_out: false,
                    cancelled: false,
                    spawn_error: Some(classify_spawn_error(&error)),
                };
            }
        }
    };

    // Wait briefly for readers after kill/reap, but never block forever if a
    // stubborn descendant still holds a pipe open.
    join_readers_bounded(stdout_thread, stderr_thread, Duration::from_millis(200));
    let stdout = std::mem::take(&mut *stdout_buf.lock().unwrap_or_else(|p| p.into_inner()));
    let stderr = std::mem::take(&mut *stderr_buf.lock().unwrap_or_else(|p| p.into_inner()));
    ProbeCommandResult {
        exit_code: outcome.exit_code,
        stdout,
        stderr,
        timed_out: outcome.timed_out,
        cancelled: outcome.cancelled,
        spawn_error: outcome.spawn_error,
    }
}

fn join_readers_bounded(
    stdout_thread: std::thread::JoinHandle<()>,
    stderr_thread: std::thread::JoinHandle<()>,
    budget: Duration,
) {
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let _ = stdout_thread.join();
        let _ = stderr_thread.join();
        let _ = tx.send(());
    });
    let _ = rx.recv_timeout(budget);
}

fn classify_spawn_error(error: &std::io::Error) -> SpawnFailureKind {
    match error.kind() {
        std::io::ErrorKind::NotFound => SpawnFailureKind::NotFound,
        std::io::ErrorKind::PermissionDenied => SpawnFailureKind::PermissionDenied,
        _ => SpawnFailureKind::Other,
    }
}

/// Shared remaining capture budget so stdout+stderr together never exceed
/// [`PROBE_CAPTURE_BUDGET`].
fn spawn_bounded_reader(
    pipe: Option<impl Read + Send + 'static>,
    sink: Arc<Mutex<Vec<u8>>>,
    remaining: Arc<AtomicUsize>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let Some(mut pipe) = pipe else {
            return;
        };
        let mut chunk = [0u8; 1024];
        loop {
            match pipe.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    let allow = remaining
                        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |left| {
                            Some(left.saturating_sub(n.min(left)))
                        })
                        .unwrap_or(0);
                    let take = n.min(allow);
                    if take > 0 {
                        let mut buf = sink.lock().unwrap_or_else(|p| p.into_inner());
                        buf.extend_from_slice(&chunk[..take]);
                    }
                    // Always continue reading to unblock the child once budget
                    // is exhausted; just do not retain more bytes.
                }
                Err(_) => break,
            }
        }
    })
}

/// Deadlines used by a refresh (injectable; production uses 2s/5s constants).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbeDeadlines {
    pub version: Duration,
    pub functional: Duration,
}

impl Default for ProbeDeadlines {
    fn default() -> Self {
        Self {
            version: VERSION_PROBE_DEADLINE,
            functional: FUNCTIONAL_PROBE_DEADLINE,
        }
    }
}

/// Evaluation context for applicability (platform + selected features).
#[derive(Debug, Clone)]
pub struct EvaluationContext {
    pub platform: HostPlatform,
    /// Feature keys currently selected/enabled by configuration.
    pub selected_features: BTreeSet<String>,
}

impl EvaluationContext {
    pub fn new(platform: HostPlatform) -> Self {
        Self {
            platform,
            selected_features: BTreeSet::new(),
        }
    }

    pub fn with_features(mut self, features: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.selected_features = features.into_iter().map(Into::into).collect();
        self
    }
}

/// Evaluate a single descriptor into a health entry without mutating global state.
pub fn evaluate_descriptor(
    descriptor: &ExternalRuntimeDescriptor,
    executor: &dyn ProbeExecutor,
    path_env: Option<&str>,
    cwd: &Path,
    ctx: &EvaluationContext,
    deadlines: ProbeDeadlines,
    cancel: &CancelToken,
) -> HealthEntry {
    let platform = ctx.platform;
    if !is_applicable(
        &descriptor.applicability,
        &descriptor.owner.feature,
        platform,
        &ctx.selected_features,
    ) {
        return HealthEntry {
            id: descriptor.id.clone(),
            state: HealthState::NotApplicable,
            importance: descriptor.importance,
            target: descriptor.target,
            remedy: None,
            platform,
        };
    }

    if cancel.is_cancelled() {
        return HealthEntry {
            id: descriptor.id.clone(),
            state: HealthState::Unknown {
                cause: HealthCause::Cancellation,
            },
            importance: descriptor.importance,
            target: descriptor.target,
            remedy: Some(descriptor.remedy.clone()),
            platform,
        };
    }

    // Container-target health must not use host PATH/spawn results. Host
    // resolution only applies to Host-target descriptors. Container image
    // guarantees use `container_provides`; deeper container probes are owned
    // by later adapter prompts.
    if descriptor.target == ExecutionTarget::Container {
        return evaluate_container_target(descriptor, platform);
    }

    match &descriptor.probe_policy {
        ProbePolicy::ConfiguredCommand {
            command,
            exact_path,
        } => evaluate_configured_command(
            descriptor,
            command,
            exact_path.as_deref(),
            executor,
            path_env,
            cwd,
            platform,
        ),
        ProbePolicy::TrustedCatalog(policy) if !policy.is_executable() => {
            // Deserialized/forged trusted policies never reach the spawn seam.
            HealthEntry {
                id: descriptor.id.clone(),
                state: HealthState::Failed {
                    cause: HealthCause::Internal {
                        message: "trusted catalog policy is not catalog-minted".into(),
                    },
                },
                importance: descriptor.importance,
                target: descriptor.target,
                remedy: Some(descriptor.remedy.clone()),
                platform,
            }
        }
        ProbePolicy::TrustedCatalog(policy) => evaluate_trusted_catalog(
            descriptor, policy, executor, path_env, cwd, platform, deadlines, cancel,
        ),
    }
}

fn evaluate_container_target(
    descriptor: &ExternalRuntimeDescriptor,
    platform: HostPlatform,
) -> HealthEntry {
    // Configured commands targeting a container still cannot be assumed present
    // from host resolution; without a container-side executor they are Missing
    // with forced config/PATH guidance (never a package recipe by name).
    if let ProbePolicy::ConfiguredCommand {
        command,
        exact_path,
    } = &descriptor.probe_policy
    {
        return HealthEntry {
            id: descriptor.id.clone(),
            state: HealthState::Missing,
            importance: descriptor.importance,
            target: descriptor.target,
            remedy: Some(configured_command_remedy(
                command,
                exact_path.as_ref().and_then(|p| p.to_str()),
            )),
            platform,
        };
    }

    let provided = descriptor
        .executable_candidates
        .iter()
        .any(|name| container_provides(name));
    if provided {
        HealthEntry {
            id: descriptor.id.clone(),
            state: HealthState::Available {
                resolved_path: None,
                version_evidence: None,
            },
            importance: descriptor.importance,
            target: descriptor.target,
            remedy: None,
            platform,
        }
    } else {
        HealthEntry {
            id: descriptor.id.clone(),
            state: HealthState::Missing,
            importance: descriptor.importance,
            target: descriptor.target,
            remedy: Some(descriptor.remedy.clone()),
            platform,
        }
    }
}

fn evaluate_configured_command(
    descriptor: &ExternalRuntimeDescriptor,
    command: &str,
    exact_path: Option<&Path>,
    executor: &dyn ProbeExecutor,
    path_env: Option<&str>,
    cwd: &Path,
    platform: HostPlatform,
) -> HealthEntry {
    // Resolution + spawnability only — executor.run is never called.
    let resolved = executor.resolve(command, exact_path, path_env, cwd);
    let remedy = Some(configured_command_remedy(
        command,
        exact_path.and_then(|p| p.to_str()),
    ));
    match resolved {
        Some(path) if executor.is_spawnable(&path) => HealthEntry {
            id: descriptor.id.clone(),
            state: HealthState::Available {
                resolved_path: Some(path),
                version_evidence: None,
            },
            importance: descriptor.importance,
            target: descriptor.target,
            remedy: None,
            platform,
        },
        Some(_) => HealthEntry {
            id: descriptor.id.clone(),
            state: HealthState::Failed {
                cause: HealthCause::NotSpawnable,
            },
            importance: descriptor.importance,
            target: descriptor.target,
            remedy,
            platform,
        },
        None => HealthEntry {
            id: descriptor.id.clone(),
            state: HealthState::Missing,
            importance: descriptor.importance,
            target: descriptor.target,
            remedy,
            platform,
        },
    }
}

#[allow(clippy::too_many_arguments)]
fn evaluate_trusted_catalog(
    descriptor: &ExternalRuntimeDescriptor,
    policy: &super::schema::TrustedCatalogPolicy,
    executor: &dyn ProbeExecutor,
    path_env: Option<&str>,
    cwd: &Path,
    platform: HostPlatform,
    deadlines: ProbeDeadlines,
    cancel: &CancelToken,
) -> HealthEntry {
    let version_argv = policy.version_argv();
    let version_parser = policy.version_parser();
    let functional_argv = policy.functional_argv();
    let mut resolved = None;
    for candidate in &descriptor.executable_candidates {
        if let Some(path) = executor.resolve(candidate, None, path_env, cwd) {
            resolved = Some(path);
            break;
        }
    }
    let Some(program) = resolved else {
        return HealthEntry {
            id: descriptor.id.clone(),
            state: HealthState::Missing,
            importance: descriptor.importance,
            target: descriptor.target,
            remedy: Some(descriptor.remedy.clone()),
            platform,
        };
    };

    if !executor.is_spawnable(&program) {
        return HealthEntry {
            id: descriptor.id.clone(),
            state: HealthState::Failed {
                cause: HealthCause::NotSpawnable,
            },
            importance: descriptor.importance,
            target: descriptor.target,
            remedy: Some(descriptor.remedy.clone()),
            platform,
        };
    }

    let version_result = executor.run(&program, version_argv, deadlines.version, cancel);
    if version_result.cancelled {
        return HealthEntry {
            id: descriptor.id.clone(),
            state: HealthState::Unknown {
                cause: HealthCause::Cancellation,
            },
            importance: descriptor.importance,
            target: descriptor.target,
            remedy: Some(descriptor.remedy.clone()),
            platform,
        };
    }
    if version_result.timed_out {
        return HealthEntry {
            id: descriptor.id.clone(),
            state: HealthState::TimedOut,
            importance: descriptor.importance,
            target: descriptor.target,
            remedy: Some(descriptor.remedy.clone()),
            platform,
        };
    }
    if let Some(failure) = version_result.spawn_error {
        return HealthEntry {
            id: descriptor.id.clone(),
            state: HealthState::Failed {
                cause: HealthCause::SpawnFailed { failure },
            },
            importance: descriptor.importance,
            target: descriptor.target,
            remedy: Some(descriptor.remedy.clone()),
            platform,
        };
    }
    if version_result.exit_code != Some(0) {
        return HealthEntry {
            id: descriptor.id.clone(),
            state: HealthState::Failed {
                cause: HealthCause::NonZeroExit {
                    code: version_result.exit_code,
                },
            },
            importance: descriptor.importance,
            target: descriptor.target,
            remedy: Some(descriptor.remedy.clone()),
            platform,
        };
    }

    let combined = version_result.combined_capped();
    let evidence = sanitize_version_evidence(&combined, Some(&program));
    // Parse from sanitized evidence only — never put raw probe output into health.
    let parsed_version = parse_version(version_parser, &evidence);

    if let Some(rule) = &descriptor.compatibility
        && let Some(detail) = compatibility_failure(rule, parsed_version.as_deref())
    {
        // Detail is built only from rule constants + sanitized parsed version.
        let detail = sanitize_version_evidence(&detail, Some(&program));
        return HealthEntry {
            id: descriptor.id.clone(),
            state: HealthState::Incompatible { detail },
            importance: descriptor.importance,
            target: descriptor.target,
            remedy: Some(descriptor.remedy.clone()),
            platform,
        };
    }

    if let Some(func_argv) = functional_argv {
        let func = executor.run(&program, func_argv, deadlines.functional, cancel);
        if func.cancelled {
            return HealthEntry {
                id: descriptor.id.clone(),
                state: HealthState::Unknown {
                    cause: HealthCause::Cancellation,
                },
                importance: descriptor.importance,
                target: descriptor.target,
                remedy: Some(descriptor.remedy.clone()),
                platform,
            };
        }
        if func.timed_out {
            return HealthEntry {
                id: descriptor.id.clone(),
                state: HealthState::TimedOut,
                importance: descriptor.importance,
                target: descriptor.target,
                remedy: Some(descriptor.remedy.clone()),
                platform,
            };
        }
        if let Some(failure) = func.spawn_error {
            return HealthEntry {
                id: descriptor.id.clone(),
                state: HealthState::Failed {
                    cause: HealthCause::SpawnFailed { failure },
                },
                importance: descriptor.importance,
                target: descriptor.target,
                remedy: Some(descriptor.remedy.clone()),
                platform,
            };
        }
        if func.exit_code != Some(0) {
            return HealthEntry {
                id: descriptor.id.clone(),
                state: HealthState::Failed {
                    cause: HealthCause::NonZeroExit {
                        code: func.exit_code,
                    },
                },
                importance: descriptor.importance,
                target: descriptor.target,
                remedy: Some(descriptor.remedy.clone()),
                platform,
            };
        }
    }

    HealthEntry {
        id: descriptor.id.clone(),
        state: HealthState::Available {
            resolved_path: Some(program),
            version_evidence: if evidence.is_empty() {
                None
            } else {
                Some(evidence)
            },
        },
        importance: descriptor.importance,
        target: descriptor.target,
        remedy: None,
        platform,
    }
}

fn is_applicable(
    applicability: &Applicability,
    feature: &str,
    platform: HostPlatform,
    selected_features: &BTreeSet<String>,
) -> bool {
    let feature_selected = selected_features.contains(feature);
    match applicability {
        Applicability::Always => true,
        Applicability::WhenFeatureSelected => feature_selected,
        Applicability::Platforms(list) => list.contains(&platform),
        Applicability::WhenFeatureSelectedOnPlatforms { platforms } => {
            feature_selected && (platforms.is_empty() || platforms.contains(&platform))
        }
    }
}

fn parse_version(parser: &VersionParser, combined: &str) -> Option<String> {
    match parser {
        VersionParser::FirstLine => combined
            .lines()
            .map(str::trim)
            .find(|l| !l.is_empty())
            .map(str::to_string),
        VersionParser::FirstSemverToken => {
            for token in combined.split_whitespace() {
                let cleaned = token
                    .trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '.' && c != '-');
                if cleaned
                    .split('.')
                    .filter(|p| p.chars().all(|c| c.is_ascii_digit()))
                    .count()
                    >= 2
                {
                    return Some(cleaned.to_string());
                }
            }
            None
        }
        VersionParser::RegexCapture { pattern, group } => {
            let Ok(re) = regex::Regex::new(pattern) else {
                return None;
            };
            re.captures(combined)
                .and_then(|caps| caps.get(*group).map(|m| m.as_str().to_string()))
        }
    }
}

fn compatibility_failure(rule: &CompatibilityRule, version: Option<&str>) -> Option<String> {
    match rule {
        CompatibilityRule::CatalogRule { .. } => None,
        CompatibilityRule::ExactVersion { version: expected } => {
            let Some(actual) = version else {
                return Some("version evidence missing".into());
            };
            if versions_equal(actual, expected) {
                None
            } else {
                Some(format!("expected version {expected}, found {actual}"))
            }
        }
        CompatibilityRule::MinVersion { version: min } => {
            let Some(actual) = version else {
                return Some("version evidence missing".into());
            };
            if version_at_least(actual, min) {
                None
            } else {
                Some(format!("requires at least {min}, found {actual}"))
            }
        }
    }
}

fn extract_numeric_version(s: &str) -> Vec<u64> {
    let core = s
        .trim()
        .trim_start_matches(|c: char| !c.is_ascii_digit())
        .split(['-', '+', ' '])
        .next()
        .unwrap_or("");
    core.split('.')
        .filter_map(|part| {
            let digits: String = part.chars().take_while(|c| c.is_ascii_digit()).collect();
            digits.parse().ok()
        })
        .collect()
}

fn versions_equal(a: &str, b: &str) -> bool {
    extract_numeric_version(a) == extract_numeric_version(b)
        && !extract_numeric_version(a).is_empty()
}

fn version_at_least(actual: &str, min: &str) -> bool {
    let a = extract_numeric_version(actual);
    let m = extract_numeric_version(min);
    if a.is_empty() || m.is_empty() {
        return false;
    }
    for i in 0..a.len().max(m.len()) {
        let av = a.get(i).copied().unwrap_or(0);
        let mv = m.get(i).copied().unwrap_or(0);
        if av > mv {
            return true;
        }
        if av < mv {
            return false;
        }
    }
    true
}

/// Refresh all descriptors into a complete snapshot for `generation`.
#[allow(clippy::too_many_arguments)]
pub fn refresh_snapshot(
    generation: u64,
    descriptors: &[ExternalRuntimeDescriptor],
    executor: &dyn ProbeExecutor,
    path_env: Option<&str>,
    cwd: &Path,
    ctx: &EvaluationContext,
    deadlines: ProbeDeadlines,
    cancel: &CancelToken,
) -> super::health::ExternalRuntimeSnapshot {
    let platform = ctx.platform;
    let mut snapshot = super::health::ExternalRuntimeSnapshot::empty(generation, platform);
    for descriptor in descriptors {
        if cancel.is_cancelled() {
            // Remaining rows become Unknown(Cancellation) without starting probes.
            snapshot.entries.insert(
                descriptor.id.as_str().to_string(),
                HealthEntry {
                    id: descriptor.id.clone(),
                    state: HealthState::Unknown {
                        cause: HealthCause::Cancellation,
                    },
                    importance: descriptor.importance,
                    target: descriptor.target,
                    remedy: Some(descriptor.remedy.clone()),
                    platform,
                },
            );
            continue;
        }
        let entry =
            evaluate_descriptor(descriptor, executor, path_env, cwd, ctx, deadlines, cancel);
        snapshot
            .entries
            .insert(descriptor.id.as_str().to_string(), entry);
    }
    for descriptor in descriptors {
        if let Some(group) = &descriptor.group {
            let key = descriptor.id.as_str().to_string();
            snapshot.groups.insert(key, snapshot.evaluate_group(group));
        }
    }
    snapshot
}

/// Handler for [`RecordingProbeExecutor`] run invocations in tests.
type RecordingRunHandler = Box<dyn Fn(&Path, &[String]) -> ProbeCommandResult + Send>;

/// Recording executor for tests: never sleeps; records run invocations.
pub struct RecordingProbeExecutor {
    pub resolves: Mutex<HashMap<String, PathBuf>>,
    pub spawnable: Mutex<HashSet<PathBuf>>,
    pub run_log: Mutex<Vec<RunRecord>>,
    pub run_handler: Mutex<Option<RecordingRunHandler>>,
    pub run_count: AtomicUsize,
}

impl Default for RecordingProbeExecutor {
    fn default() -> Self {
        Self {
            resolves: Mutex::new(HashMap::new()),
            spawnable: Mutex::new(HashSet::new()),
            run_log: Mutex::new(Vec::new()),
            run_handler: Mutex::new(None),
            run_count: AtomicUsize::new(0),
        }
    }
}

impl std::fmt::Debug for RecordingProbeExecutor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecordingProbeExecutor")
            .field("run_count", &self.run_count.load(Ordering::SeqCst))
            .field(
                "run_log",
                &self.run_log.lock().unwrap_or_else(|p| p.into_inner()),
            )
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunRecord {
    pub program: PathBuf,
    pub args: Vec<String>,
    pub deadline: Duration,
}

impl RecordingProbeExecutor {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_resolve(self, name: impl Into<String>, path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        self.spawnable.lock().unwrap().insert(path.clone());
        self.resolves.lock().unwrap().insert(name.into(), path);
        self
    }

    pub fn set_handler(
        &self,
        handler: impl Fn(&Path, &[String]) -> ProbeCommandResult + Send + 'static,
    ) {
        *self.run_handler.lock().unwrap() = Some(Box::new(handler));
    }
}

impl ProbeExecutor for RecordingProbeExecutor {
    fn resolve(
        &self,
        name: &str,
        exact_path: Option<&Path>,
        _path_env: Option<&str>,
        _cwd: &Path,
    ) -> Option<PathBuf> {
        if let Some(path) = exact_path {
            let spawnable = self.spawnable.lock().unwrap();
            let resolves = self.resolves.lock().unwrap();
            if spawnable.contains(path) || resolves.values().any(|v| v == path) {
                return Some(path.to_path_buf());
            }
            return None;
        }
        self.resolves.lock().unwrap().get(name).cloned()
    }

    fn is_spawnable(&self, path: &Path) -> bool {
        let spawnable = self.spawnable.lock().unwrap();
        if spawnable.is_empty() {
            // Default: anything we resolved is spawnable.
            return self.resolves.lock().unwrap().values().any(|p| p == path);
        }
        spawnable.contains(path)
    }

    fn run(
        &self,
        program: &Path,
        args: &[String],
        deadline: Duration,
        cancel: &CancelToken,
    ) -> ProbeCommandResult {
        self.run_count.fetch_add(1, Ordering::SeqCst);
        self.run_log.lock().unwrap().push(RunRecord {
            program: program.to_path_buf(),
            args: args.to_vec(),
            deadline,
        });
        if cancel.is_cancelled() {
            return ProbeCommandResult {
                exit_code: None,
                stdout: Vec::new(),
                stderr: Vec::new(),
                timed_out: false,
                cancelled: true,
                spawn_error: None,
            };
        }
        if deadline.is_zero() {
            return ProbeCommandResult {
                exit_code: None,
                stdout: Vec::new(),
                stderr: Vec::new(),
                timed_out: true,
                cancelled: false,
                spawn_error: None,
            };
        }
        if let Some(handler) = self.run_handler.lock().unwrap().as_ref() {
            return handler(program, args);
        }
        // Default success with a version line.
        ProbeCommandResult {
            exit_code: Some(0),
            stdout: b"1.0.0\n".to_vec(),
            stderr: Vec::new(),
            timed_out: false,
            cancelled: false,
            spawn_error: None,
        }
    }
}
