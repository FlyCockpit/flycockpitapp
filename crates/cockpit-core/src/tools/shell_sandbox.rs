//! zerobox shell confinement for the `bash` tool (sandboxing part 2).
//!
//! Wraps a `sh -c <command>` invocation in a zerobox `Sandbox` confined
//! to: the agent cwd (read+write), the ephemeral per-session tmp dir
//! (read+write), and the durable workspace scratch dir (read+write),
//! and `PATH` execution (zerobox's default profile auto-adds a minimal
//! system-path read entry, so any binary on `PATH` still runs). Reads
//! outside that allowlist are denied — silently, inside the child only
//! (zerobox is hard-deny with no callback), which is why the
//! run-fail-escalate prompt in `bash.rs` can't name the blocked path.
//! `TMPDIR`/`TMP`/`TEMP` are pointed at that per-session tmp dir so
//! `mktemp`/`tempfile` land in the writable scratch area rather than bare
//! `/tmp` (denied) or an inherited `TMPDIR` outside the box.
//!
//! We build the child via `Sandbox::...prepare().into_command()` rather
//! than `.run()`/`.spawn()` so the caller keeps full control of the
//! `tokio::process::Command` — cockpit re-applies `process_group(0)` +
//! `kill_on_drop` and runs its own cancel/timeout/pgid-kill loop, exactly
//! as the unsandboxed path does. `.run()`/`.spawn()` would use
//! `output()`/piped internally and lose pgid control.
//!
//! Platform support is Linux/macOS/WSL only (zerobox has no native
//! Windows backend); on Windows the shell runs unconfined and this module
//! is never invoked (see `bash.rs`). The shell is confined on the
//! *filesystem* only and shares the host network: we call
//! [`Sandbox::allow_net_all`], which (empty allow-list, no deny, no secret
//! store) makes zerobox select `BwrapNetworkMode::FullAccess` — so bwrap is
//! invoked *without* `--unshare-net` and never tries to bring up an
//! isolated loopback. That loopback bring-up (`RTM_NEWADDR`) fails with
//! `EPERM` on hosts that forbid unprivileged network namespaces, which
//! would otherwise abort *every* confined command before it could exec;
//! sharing the host network avoids that failure entirely. Network
//! confinement is out of scope.
//!
//! Even with `FullAccess`, bwrap still enters fresh user + pid namespaces
//! (`--unshare-user`/`--unshare-pid`). Where those are blocked entirely
//! (some containers, WSL1, AppArmor/sysctl userns restrictions, bwrap
//! absent), sandbox setup still fails — so a cached, refreshable environment
//! probe ([`sandbox_available`]) detects that case and lets `bash.rs` refuse
//! confined commands with an actionable, diagnosed error (exact host fix plus
//! its reboot-persistent form) instead of failing each one into the
//! run-fail-escalate prompt. It never falls back to running unconfined.
//!
//! Linux re-entry: zerobox re-execs the current binary as
//! `zerobox-linux-sandbox`. [`init`] must run once near process start
//! (before the tokio runtime / extra threads) — it dispatches the helper
//! and installs the PATH-prepend alias guard. The resolved helper exe is
//! threaded into every sandbox via `.linux_sandbox_exe(...)`.

#[cfg(target_os = "linux")]
use std::path::PathBuf;
#[cfg(target_os = "linux")]
use std::sync::OnceLock;

use anyhow::Result;
use serde::{Deserialize, Serialize};

pub mod denial;
pub use denial::{
    DenialEvidence, HeuristicSandboxDenialClassifier, SandboxDenialClassifier,
    SandboxDenialConfidence, SandboxDenialInput, SandboxDenialVerdict,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SandboxPathAccess {
    Read,
    ReadWrite,
}

impl SandboxPathAccess {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::ReadWrite => "read_write",
        }
    }

    pub fn storage_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::ReadWrite => "read-write",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtraSandboxPath {
    pub kind: String,
    pub path: std::path::PathBuf,
    pub access: SandboxPathAccess,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxPolicy {
    pub allow_read_roots: Vec<std::path::PathBuf>,
    pub allow_write_roots: Vec<std::path::PathBuf>,
    /// Hard denials applied after the allow lists. Zerobox deny takes
    /// precedence, so these roots stay unreachable even when they sit under
    /// an allowed parent (cwd, PATH, extra_paths).
    pub deny_paths: Vec<std::path::PathBuf>,
    pub network_allowed: bool,
}

pub fn sandbox_policy(
    cwd: &std::path::Path,
    tmp_dir: Option<&std::path::Path>,
    session_env: &std::collections::HashMap<String, String>,
    extra_paths: &[ExtraSandboxPath],
    write_scope: Option<&std::path::Path>,
) -> SandboxPolicy {
    sandbox_policy_with_workspace_scratch(cwd, tmp_dir, None, session_env, extra_paths, write_scope)
}

pub fn sandbox_policy_with_workspace_scratch(
    cwd: &std::path::Path,
    tmp_dir: Option<&std::path::Path>,
    workspace_scratch_dir: Option<&std::path::Path>,
    session_env: &std::collections::HashMap<String, String>,
    extra_paths: &[ExtraSandboxPath],
    write_scope: Option<&std::path::Path>,
) -> SandboxPolicy {
    sandbox_policy_with_visibility_restriction(
        cwd,
        tmp_dir,
        workspace_scratch_dir,
        session_env,
        extra_paths,
        write_scope,
        false,
        true,
    )
}

/// Policy view for a typed workspace lease. Unlike the normal session policy,
/// user-configured PATH/profile and tool allowlists cannot add filesystem
/// access outside the lease visibility root.
pub fn sandbox_policy_for_workspace_lease(
    cwd: &std::path::Path,
    tmp_dir: Option<&std::path::Path>,
    session_env: &std::collections::HashMap<String, String>,
    extra_paths: &[ExtraSandboxPath],
    write_scope: Option<&std::path::Path>,
) -> SandboxPolicy {
    sandbox_policy_with_visibility_restriction(
        cwd,
        tmp_dir,
        None,
        session_env,
        extra_paths,
        write_scope,
        true,
        true,
    )
}

fn sandbox_policy_with_visibility_restriction(
    cwd: &std::path::Path,
    tmp_dir: Option<&std::path::Path>,
    workspace_scratch_dir: Option<&std::path::Path>,
    session_env: &std::collections::HashMap<String, String>,
    extra_paths: &[ExtraSandboxPath],
    write_scope: Option<&std::path::Path>,
    restrict_to_visibility: bool,
    workspace_write_allowed: bool,
) -> SandboxPolicy {
    let mut allow_read_roots = Vec::new();
    let mut allow_write_roots = Vec::new();
    push_unique_path(&mut allow_read_roots, cwd.to_path_buf());
    if workspace_write_allowed {
        if let Some(scope) = write_scope {
            if cockpit_host::path_containment::contained_under(cwd, scope) {
                push_unique_path(&mut allow_write_roots, scope.to_path_buf());
            }
        } else if !system_writable_root_conflict(cwd) {
            // Host path approval may still authorize read-write access to a
            // system directory such as `/etc`, but making that path a writable
            // sandbox root makes zerobox prepare protected `.codex` metadata
            // beneath it. Keep those roots read-only inside the box.
            push_unique_path(&mut allow_write_roots, cwd.to_path_buf());
        }
    }

    for path in crate::env_snapshot::user_runtime_read_paths_from_path(
        session_env.get("PATH").map(String::as_str),
    ) {
        if !restrict_to_visibility || is_narrow_runtime_read_exception(&path) {
            push_unique_path(&mut allow_read_roots, path);
        }
    }

    for extra in extra_paths {
        let inside_visibility = cockpit_host::path_containment::contained_under(cwd, &extra.path);
        let safe_read_exception = matches!(extra.access, SandboxPathAccess::Read)
            && is_narrow_runtime_read_exception(&extra.path);
        if !restrict_to_visibility || inside_visibility || safe_read_exception {
            push_unique_path(&mut allow_read_roots, extra.path.clone());
        }
        if workspace_write_allowed
            && matches!(extra.access, SandboxPathAccess::ReadWrite)
            && (!restrict_to_visibility || inside_visibility)
            && !system_writable_root_conflict(&extra.path)
        {
            push_unique_path(&mut allow_write_roots, extra.path.clone());
        }
    }

    if workspace_write_allowed
        && let Some(tmp) = tmp_dir
        && (!restrict_to_visibility || cockpit_host::path_containment::contained_under(cwd, tmp))
    {
        // A leased shell may only use lease-local scratch. The normal
        // per-session tmp directory is deliberately not an implicit escape
        // hatch into another workspace's shared state.
        push_unique_path(&mut allow_read_roots, tmp.to_path_buf());
        push_unique_path(&mut allow_write_roots, tmp.to_path_buf());
    }
    if let Some(scratch) = workspace_scratch_dir {
        push_unique_path(&mut allow_read_roots, scratch.to_path_buf());
        push_unique_path(&mut allow_write_roots, scratch.to_path_buf());
    }

    SandboxPolicy {
        allow_read_roots,
        allow_write_roots,
        deny_paths: crate::daemon::control_plane_deny_paths(),
        network_allowed: true,
    }
}

/// A leased shell gets no user/profile/toolchain directory escape hatch. The
/// only outside reads are fixed system runtime roots needed to exec the shell
/// itself; `/usr/local`, home directories and PATH/profile-provided roots are
/// deliberately not exceptions.
fn is_narrow_runtime_read_exception(path: &std::path::Path) -> bool {
    matches!(
        path,
        path if path == std::path::Path::new("/bin")
            || path == std::path::Path::new("/usr/bin")
            || path == std::path::Path::new("/lib")
            || path == std::path::Path::new("/lib64")
            || path == std::path::Path::new("/usr/lib")
            || path == std::path::Path::new("/usr/lib64")
    )
}

fn push_unique_path(paths: &mut Vec<std::path::PathBuf>, path: std::path::PathBuf) {
    if !paths.iter().any(|existing| existing == &path) {
        paths.push(path);
    }
}

/// Zerobox's `system-read-linux` profile read-only-mounts `/etc/resolv.conf` and
/// siblings. When `/etc` (or another parent) is also writable, bwrap rejects
/// the conflicting carveout. Omit that profile and rely on the explicit
/// runtime read roots we already add for confined shells.
fn writable_roots_conflict_with_system_read_carveouts(
    allow_write_roots: &[std::path::PathBuf],
) -> bool {
    allow_write_roots
        .iter()
        .any(|root| system_writable_root_conflict(root))
}

fn system_writable_root_conflict(root: &std::path::Path) -> bool {
    root == std::path::Path::new("/etc") || root.starts_with("/etc/")
}

#[cfg(target_os = "linux")]
const SANDBOX_PROFILES_WITHOUT_SYSTEM_READ_LINUX: &[&str] = &[
    "deny-credentials",
    "deny-shell-history",
    "deny-shell-configs",
    "deny-keychains-linux",
    "deny-browser-data-linux",
];

fn apply_sandbox_profiles(sandbox: zerobox::Sandbox, policy: &SandboxPolicy) -> zerobox::Sandbox {
    #[cfg(target_os = "linux")]
    if writable_roots_conflict_with_system_read_carveouts(&policy.allow_write_roots) {
        return sandbox.profiles(SANDBOX_PROFILES_WITHOUT_SYSTEM_READ_LINUX);
    }
    sandbox
}

/// Linux helper alias path, captured by [`init`] and read by
/// [`build_sandboxed_command`]. `None` on non-Linux or when init wasn't
/// run / failed. The guard that keeps the alias dir alive is leaked for
/// the process lifetime (intentional — sandboxed children may re-enter at
/// any time until exit).
#[cfg(target_os = "linux")]
static LINUX_SANDBOX_EXE: OnceLock<Option<PathBuf>> = OnceLock::new();

/// Dispatch the Linux sandbox helper and install the PATH-prepend alias.
///
/// MUST be called near the very start of `main` — before the tokio
/// runtime is built and before any extra threads spawn — because the
/// dispatch can re-exec the process as the helper and the PATH mutation
/// is only sound single-threaded (zerobox documents both constraints).
/// A no-op on non-Linux. The alias guard is leaked deliberately so the
/// helper alias outlives every sandboxed child for the process lifetime.
/// Idempotent: the `LINUX_SANDBOX_EXE` `OnceLock` ignores a second set,
/// so a defensive call from a test is harmless.
pub fn init() {
    #[cfg(target_os = "linux")]
    {
        zerobox::arg0::dispatch_linux_sandbox_helper();
        let exe = match zerobox::arg0::prepend_path_entry_for_zerobox_aliases() {
            Ok(guard) => {
                let exe = guard.zerobox_linux_sandbox_exe().to_path_buf();
                // Keep the alias dir + PATH entry alive for the whole
                // process: leak the guard. Sandboxed children may
                // re-enter the helper at any point until exit.
                std::mem::forget(guard);
                Some(exe)
            }
            Err(e) => {
                tracing::warn!(error = %e, "zerobox Linux helper init failed; shell sandbox disabled");
                None
            }
        };
        let _ = LINUX_SANDBOX_EXE.set(exe);
    }
}

/// Whether shell sandboxing can run on this platform. False on Windows
/// (no zerobox backend) — `bash.rs` takes the unconfined path + a
/// one-time notice there.
pub const fn shell_sandbox_supported() -> bool {
    cfg!(not(windows))
}

/// Build a confined `sh -c <command>` as a `tokio::process::Command`,
/// ready for the caller to apply `process_group(0)` / `kill_on_drop` and
/// run its cancel/timeout loop.
///
/// `command` is the full (prelude-prefixed) shell line. `cwd` is the
/// agent working directory — read+write inside the sandbox. `tmp_dir`, when
/// present, is the ephemeral per-session scratch; `workspace_scratch_dir` is
/// the durable per-workspace, per-session scratch. Both are read+write and
/// count as inside the native-tool boundary. `extra_env` is applied on top of
/// the inherited environment (cockpit uses it for the env-scrub overrides).
/// Reads outside cwd and these scratch roots are denied.
///
/// Returns an error only if zerobox's policy validation fails (e.g. an
/// unusable cwd); a failure there is surfaced to the model as a spawn
/// error, never silently downgraded to unconfined.
pub async fn build_sandboxed_command(
    command: &str,
    cwd: &std::path::Path,
    tmp_dir: Option<&std::path::Path>,
    extra_env: &[(String, String)],
    session_env: &std::collections::HashMap<String, String>,
    extra_paths: &[ExtraSandboxPath],
    write_scope: Option<&std::path::Path>,
) -> Result<tokio::process::Command> {
    build_sandboxed_command_with_sandbox_roots(
        command,
        cwd,
        tmp_dir,
        None,
        extra_env,
        session_env,
        extra_paths,
        write_scope,
        &[],
        &[],
    )
    .await
}

/// Build a confined command while carving protected roots out of read and/or
/// write authority. Read denies take precedence over the workspace root;
/// write-only denies preserve approved KB reads while keeping generic shell
/// writes out of every configured KB. The durable workspace scratch is an
/// explicit read/write capability.
#[allow(clippy::too_many_arguments)]
pub async fn build_sandboxed_command_with_sandbox_roots(
    command: &str,
    cwd: &std::path::Path,
    tmp_dir: Option<&std::path::Path>,
    workspace_scratch_dir: Option<&std::path::Path>,
    extra_env: &[(String, String)],
    session_env: &std::collections::HashMap<String, String>,
    extra_paths: &[ExtraSandboxPath],
    write_scope: Option<&std::path::Path>,
    denied_paths: &[std::path::PathBuf],
    write_denied_paths: &[std::path::PathBuf],
) -> Result<tokio::process::Command> {
    build_sandboxed_command_with_visibility_root(
        command,
        cwd,
        cwd,
        tmp_dir,
        workspace_scratch_dir,
        extra_env,
        session_env,
        extra_paths,
        write_scope,
        false,
        true,
        denied_paths,
        write_denied_paths,
    )
    .await
}

/// Build a confined command whose process cwd may be below a stricter
/// workspace visibility root. This keeps normal relative-path semantics while
/// ensuring a leased child cannot make its requested cwd the sandbox's wider
/// read boundary.
#[allow(clippy::too_many_arguments)]
pub async fn build_sandboxed_command_with_visibility_root(
    command: &str,
    cwd: &std::path::Path,
    visibility_root: &std::path::Path,
    tmp_dir: Option<&std::path::Path>,
    workspace_scratch_dir: Option<&std::path::Path>,
    extra_env: &[(String, String)],
    session_env: &std::collections::HashMap<String, String>,
    extra_paths: &[ExtraSandboxPath],
    write_scope: Option<&std::path::Path>,
    restrict_to_visibility: bool,
    workspace_write_allowed: bool,
    denied_paths: &[std::path::PathBuf],
    write_denied_paths: &[std::path::PathBuf],
) -> Result<tokio::process::Command> {
    // The ephemeral tmp remains lease-local, while the session's durable
    // scratch is an explicit capability and remains available outside a child
    // lease's workspace visibility root.
    let lease_scratch = if restrict_to_visibility && workspace_write_allowed {
        let scratch_root = write_scope
            .filter(|scope| cockpit_host::path_containment::contained_under(visibility_root, scope))
            .unwrap_or(visibility_root);
        let path = scratch_root.join(".cockpit-tmp");
        std::fs::create_dir_all(&path)
            .map_err(|error| anyhow::anyhow!("creating lease-local shell scratch: {error}"))?;
        Some(path)
    } else {
        None
    };
    let tmp_dir = if restrict_to_visibility {
        lease_scratch.as_deref()
    } else {
        tmp_dir
    };
    let policy = sandbox_policy_with_visibility_restriction(
        visibility_root,
        tmp_dir,
        workspace_scratch_dir,
        session_env,
        extra_paths,
        if restrict_to_visibility && !workspace_write_allowed {
            // A read/execute-only lease must not regain cwd writes merely
            // because a shell command has no explicit write scope.
            Some(std::path::Path::new("/__cockpit-deny-writes__"))
        } else {
            write_scope
        },
        restrict_to_visibility,
        workspace_write_allowed,
    );
    let mut sandbox = zerobox::Sandbox::command("sh")
        .arg("-c")
        .arg(command)
        .cwd(cwd.to_path_buf())
        // allow-list with no deny-list and no secret store makes zerobox
        // select `BwrapNetworkMode::FullAccess`, so bwrap runs without
        // `--unshare-net` and never attempts the unprivileged loopback
        // bring-up that EPERMs on restricted hosts. Network confinement is
        // out of scope; this only changes networking, not filesystem
        // confinement (cwd + tmp read/write, deny outside still hold).
        .allow_net_all()
        // cwd is always readable; write roots come from `sandbox_policy` so a
        // scoped child can drop cwd write access.
        .allow_read(visibility_root.to_path_buf());

    for (key, value) in session_env {
        // Sealed child-environment injection is retired: never forward SEALED_*.
        if key.starts_with("SEALED_") {
            continue;
        }
        sandbox = sandbox.env(key.clone(), value.clone());
    }

    for path in &policy.allow_read_roots {
        sandbox = sandbox.allow_read(path.clone());
    }

    for path in &policy.allow_write_roots {
        sandbox = sandbox.allow_write(path.clone());
    }

    // Issue #296: confined children must not reach the daemon control plane
    // (socket, leak-reveal socket, owner-capability file). Deny takes
    // precedence over cwd/PATH/extra allow lists. Follow-up #337 replaces
    // blanket Owner with authenticated per-peer identity.
    let mut control_denies = policy.deny_paths.clone();
    for path in denied_paths {
        if !control_denies.iter().any(|existing| existing == path) {
            control_denies.push(path.clone());
        }
    }
    for path in &control_denies {
        sandbox = sandbox.deny_read(path.clone()).deny_write(path.clone());
    }
    for path in write_denied_paths {
        sandbox = sandbox.deny_write(path.clone());
    }

    if workspace_write_allowed
        && let Some(tmp) = tmp_dir
        && (!restrict_to_visibility
            || cockpit_host::path_containment::contained_under(visibility_root, tmp))
    {
        sandbox = sandbox
            // Point the temp-dir env vars at the one writable scratch area.
            // Without this, `mktemp` / `tempfile` / `std::env::temp_dir()`
            // resolve to bare `/tmp` (denied — only the `cockpit-session-*`
            // subdir is allow-listed) or to an *inherited* `TMPDIR` that may
            // point outside the sandbox; either way the write EPERMs. We
            // override after `inherit_env` so the inherited value can't win.
            // (`TMP`/`TEMP` for tools that honor those instead of `TMPDIR`.)
            .env("TMPDIR", tmp.to_string_lossy().into_owned())
            .env("TMP", tmp.to_string_lossy().into_owned())
            .env("TEMP", tmp.to_string_lossy().into_owned());
    }

    #[cfg(target_os = "linux")]
    if writable_roots_conflict_with_system_read_carveouts(&policy.allow_write_roots)
        && let Some(tmp) = tmp_dir
    {
        let sandbox_home = tmp.join("sandbox-home");
        std::fs::create_dir_all(&sandbox_home)
            .map_err(|error| anyhow::anyhow!("creating confined shell home: {error}"))?;
        let sandbox_config = sandbox_home.join(".config");
        std::fs::create_dir_all(&sandbox_config)
            .map_err(|error| anyhow::anyhow!("creating confined shell config home: {error}"))?;
        sandbox = sandbox
            .env("HOME", sandbox_home.to_string_lossy().into_owned())
            .env(
                "XDG_CONFIG_HOME",
                sandbox_config.to_string_lossy().into_owned(),
            );
    }

    // Layer cockpit's env-scrub overrides (e.g. blanking injection-vector
    // vars) on top of the inherited env. Applied after the TMPDIR override
    // above; the scrub set never includes the temp-dir vars, so they stand.
    for (k, v) in extra_env {
        if k.starts_with("SEALED_") {
            continue;
        }
        sandbox = sandbox.env(k.clone(), v.clone());
    }

    // Linux: hand zerobox the helper alias captured at init so it can
    // re-enter the current binary as the sandbox helper. When init didn't
    // run / failed, fall through to zerobox's internal default resolution.
    #[cfg(target_os = "linux")]
    if let Some(Some(exe)) = LINUX_SANDBOX_EXE.get() {
        sandbox = sandbox.linux_sandbox_exe(exe.clone());
    }

    sandbox = apply_sandbox_profiles(sandbox, &policy);

    let prepared = sandbox.prepare().await?;
    Ok(prepared.into_command())
}

/// Whether the zerobox sandbox can actually initialize in this environment,
/// determined once by [`sandbox_available`] and cached for the process
/// lifetime. `Unavailable` carries a short human-readable reason (the
/// probe's captured stderr, or a generic fallback) for the refuse message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SandboxAvailability {
    /// A sandboxed no-op spawned and exited cleanly — confinement works.
    Available,
    /// Sandbox setup fails in this environment (user namespaces blocked,
    /// WSL1, bwrap absent, …). `reason` is a terse explanation for the
    /// `/sandbox off` error. `fix_command`, when present, is the exact
    /// user-copyable host command that may resolve the condition.
    Unavailable {
        reason: String,
        fix_command: Option<String>,
    },
    // The platform has no shell-sandbox backend. Commands remain usable but
    // must take the normal unconfined grant-or-ask authorization path.
    UnsupportedPlatform {
        reason: String,
    },
}

/// The gating decision for a single `bash` run, derived purely from
/// sandbox state and availability so it is unit-testable without a working
/// sandbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SandboxGate {
    /// Run confined (sandbox on, supported, available).
    Confine,
    /// Run unconfined because sandboxing is off.
    Unconfined,
    /// Refuse: sandboxing is enabled but cannot initialize here. `reason`
    /// is surfaced in the model-facing error; the user is told to run
    /// `/sandbox off`.
    Refuse { reason: String },
}

/// Decide whether a `bash` command can run in the shell sandbox, given whether
/// sandboxing is on for this session+platform (`sandbox_on`) and the
/// once-probed environment availability (`availability`).
///
/// Pure and total — the seam the unit tests drive with an injected
/// `availability` so the gating logic is covered without a live bwrap.
///
///   - sandbox off → `Unconfined`.
///   - on + available → `Confine`.
///   - on + unavailable → `Refuse` (never silently unconfined).
pub fn gate_decision(sandbox_on: bool, availability: &SandboxAvailability) -> SandboxGate {
    if !sandbox_on {
        return SandboxGate::Unconfined;
    }
    match availability {
        SandboxAvailability::Available => SandboxGate::Confine,
        SandboxAvailability::Unavailable { reason, .. } => SandboxGate::Refuse {
            reason: reason.clone(),
        },
        SandboxAvailability::UnsupportedPlatform { .. } => SandboxGate::Unconfined,
    }
}

/// Decide a shell gate where a caller must enforce filesystem confinement for
/// a local-KB fence. Unlike ordinary sandbox use, unsupported platforms may
/// not fall back to an approved unconfined process on this path.
pub fn gate_decision_requiring_confinement(
    sandbox_on: bool,
    confinement_required: bool,
    availability: &SandboxAvailability,
) -> SandboxGate {
    if confinement_required {
        return match availability {
            SandboxAvailability::Available => SandboxGate::Confine,
            SandboxAvailability::Unavailable { reason, .. }
            | SandboxAvailability::UnsupportedPlatform { reason } => SandboxGate::Refuse {
                reason: reason.clone(),
            },
        };
    }
    gate_decision(sandbox_on, availability)
}

impl SandboxAvailability {
    /// The diagnosed host user-namespace restriction behind an `Unavailable`
    /// result, when the probe identified one. Derived from the exact fix
    /// command (or, for older in-memory values, the reason text) so every
    /// surface maps a diagnosis to the same fix / persist / alternative trio.
    pub fn userns_restriction(&self) -> Option<UsernsRestriction> {
        match self {
            Self::Unavailable {
                fix_command: Some(fix),
                ..
            } => UsernsRestriction::from_fix_command(fix),
            Self::Unavailable {
                reason,
                fix_command: None,
            } => UsernsRestriction::from_reason(reason),
            Self::Available | Self::UnsupportedPlatform { .. } => None,
        }
    }

    /// Host command that keeps the `fix_command` effective across reboots,
    /// when the diagnosis has one (the one-shot `sysctl -w` fix is lost on
    /// reboot; this writes the matching `/etc/sysctl.d` drop-in).
    pub fn persist_command(&self) -> Option<&'static str> {
        self.userns_restriction()
            .map(UsernsRestriction::persist_command)
    }
}

/// Refreshable process-wide cache for the shell-sandbox environment probe.
///
/// The probe is comparatively expensive (it spawns the zerobox helper and
/// bwrap), so its result is shared by every session, the `bash` gate, custom
/// tools, and background jobs. Unlike a process-lifetime `OnceCell`, the
/// cached value is replaced whenever a host-capability refresh re-probes
/// ([`probe_host_sandbox`] records its result) and dropped by
/// [`invalidate_sandbox_availability`] (for example when the user re-enables
/// the sandbox), so fixing the host (`sysctl`) takes effect without a daemon
/// restart.
///
/// Concurrent misses are single-flighted through `probe_gate`. Every
/// `record`/`invalidate` bumps `epoch`; a probe that started before such a
/// change never overwrites the newer value with its possibly stale result.
pub struct SandboxAvailabilityCache {
    state: std::sync::Mutex<SandboxAvailabilityCacheState>,
    probe_gate: tokio::sync::Mutex<()>,
}

struct SandboxAvailabilityCacheState {
    epoch: u64,
    value: Option<SandboxAvailability>,
}

impl Default for SandboxAvailabilityCache {
    fn default() -> Self {
        Self::new()
    }
}

impl SandboxAvailabilityCache {
    pub const fn new() -> Self {
        Self {
            state: std::sync::Mutex::new(SandboxAvailabilityCacheState {
                epoch: 0,
                value: None,
            }),
            probe_gate: tokio::sync::Mutex::const_new(()),
        }
    }

    fn lock_state(&self) -> std::sync::MutexGuard<'_, SandboxAvailabilityCacheState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// The currently cached availability, if any probe result is live.
    pub fn cached(&self) -> Option<SandboxAvailability> {
        self.lock_state().value.clone()
    }

    /// Drop the cached result so the next [`Self::get_or_probe`] re-probes.
    pub fn invalidate(&self) {
        let mut state = self.lock_state();
        state.epoch = state.epoch.wrapping_add(1);
        state.value = None;
    }

    /// Replace the cached result with a fresh authoritative probe (a host
    /// capability boot/refresh probe).
    pub fn record(&self, availability: SandboxAvailability) {
        let mut state = self.lock_state();
        state.epoch = state.epoch.wrapping_add(1);
        state.value = Some(availability);
    }

    /// Return the cached availability, probing (single-flight) on a miss.
    pub async fn get_or_probe<F, Fut>(&self, probe: F) -> SandboxAvailability
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = SandboxAvailability>,
    {
        if let Some(value) = self.cached() {
            return value;
        }
        let _gate = self.probe_gate.lock().await;
        let epoch = {
            let state = self.lock_state();
            if let Some(value) = &state.value {
                return value.clone();
            }
            state.epoch
        };
        let fresh = probe().await;
        let mut state = self.lock_state();
        if state.epoch == epoch {
            state.value = Some(fresh.clone());
            fresh
        } else {
            // A refresh recorded (or invalidated) while this probe ran. A
            // recorded value is newer truth; after an invalidation this
            // probe's result is still returned but not cached.
            state.value.clone().unwrap_or(fresh)
        }
    }
}

/// Process-wide cache for the environment probe (see
/// [`SandboxAvailabilityCache`]).
static SANDBOX_AVAILABILITY: SandboxAvailabilityCache = SandboxAvailabilityCache::new();

/// Whether the sandbox can initialize in this environment, served from the
/// refreshable process-wide cache and probed on a miss.
///
/// The probe builds a confined `true` in a valid cwd (`probe_cwd`, the
/// session cwd, falling back to a fresh temp dir) and spawns it. A
/// sandboxed `true` can only fail on sandbox init — never on the command
/// itself — so a spawn failure or non-zero exit means the sandbox is
/// unavailable here. The probe's stderr is captured as the reason string
/// (this avoids brittle stderr matching for the *decision* — the exit code
/// alone gates — while still surfacing a human-readable cause).
pub async fn sandbox_available(probe_cwd: &std::path::Path) -> SandboxAvailability {
    SANDBOX_AVAILABILITY
        .get_or_probe(|| probe_sandbox(probe_cwd))
        .await
}

/// Forget the cached availability so the next [`sandbox_available`] call
/// re-probes. Called when the user re-enables the sandbox (`/sandbox on`),
/// so a host fix applied since the last probe is observed.
pub fn invalidate_sandbox_availability() {
    SANDBOX_AVAILABILITY.invalidate();
}

/// Uncached host-sandbox (zerobox) probe. The capability snapshot calls this
/// on boot and refresh; the fresh result also replaces the shared cache that
/// gates `bash`, custom tools, and background jobs, so a capability refresh
/// that observes a fixed host immediately un-refuses them.
pub async fn probe_host_sandbox(probe_cwd: &std::path::Path) -> SandboxAvailability {
    let availability = probe_sandbox(probe_cwd).await;
    SANDBOX_AVAILABILITY.record(availability.clone());
    availability
}

/// Run the actual probe (no caching). Split out so the cache wrapper stays
/// trivial; the cwd fallback to a fresh temp dir lives here.
async fn probe_sandbox(probe_cwd: &std::path::Path) -> SandboxAvailability {
    if !shell_sandbox_supported() {
        return SandboxAvailability::UnsupportedPlatform {
            reason: "filesystem confinement is unavailable on this platform; shell commands run unconfined and require approval unless granted".to_string(),
        };
    }
    // Prefer the supplied (session) cwd; if it is not a usable directory,
    // fall back to a fresh temp dir so the probe always has a real cwd.
    let _fallback = if probe_cwd.is_dir() {
        None
    } else {
        Some(tempfile::tempdir())
    };
    let cwd: &std::path::Path = match &_fallback {
        None => probe_cwd,
        Some(Ok(dir)) => dir.path(),
        Some(Err(e)) => {
            return SandboxAvailability::Unavailable {
                reason: format!("no usable working directory for the sandbox probe: {e}"),
                fix_command: None,
            };
        }
    };

    // vars_os + lossy values: never panic on non-Unicode ambient values.
    let probe_env: std::collections::HashMap<String, String> = std::env::vars_os()
        .filter_map(|(key, value)| {
            let key = key.to_str()?.to_string();
            if key.starts_with("SEALED_") || crate::redact::env_scrub_patterns(&key) {
                return None;
            }
            Some((key, value.to_string_lossy().into_owned()))
        })
        .collect();
    let mut cmd = match build_sandboxed_command("true", cwd, None, &[], &probe_env, &[], None).await
    {
        Ok(c) => c,
        Err(e) => {
            return unavailable_from_raw(&e.to_string()).await;
        }
    };
    cmd.stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped());

    let output = match cmd.output().await {
        Ok(o) => o,
        Err(e) => {
            return unavailable_from_raw(&e.to_string()).await;
        }
    };

    if output.status.success() {
        SandboxAvailability::Available
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        unavailable_from_raw(&stderr).await
    }
}

/// Build structured unavailability metadata from a probe failure: prefer the
/// targeted user-namespace diagnosis (Linux only — see
/// [`diagnose_userns_restriction`]), falling back to the terse bwrap tail line.
async fn unavailable_from_raw(raw: &str) -> SandboxAvailability {
    match diagnose_userns_restriction(raw).await {
        Some(diagnosis) => SandboxAvailability::Unavailable {
            reason: diagnosis.reason,
            fix_command: diagnosis.fix_command,
        },
        None if raw.trim().is_empty() => SandboxAvailability::Unavailable {
            reason: "the sandbox helper exited non-zero".to_string(),
            fix_command: None,
        },
        None => SandboxAvailability::Unavailable {
            reason: clean_reason(raw),
            fix_command: None,
        },
    }
}

/// Derive the exact user-copyable host fix command from an already-diagnosed
/// sandbox-unavailable reason. This keeps older in-memory reasons usable while
/// the wire event carries the command as structured data for new clients.
pub fn fix_command_for_reason(reason: &str) -> Option<String> {
    UsernsRestriction::from_reason(reason).map(|restriction| restriction.fix_command().to_string())
}

/// The reboot-persistent companion of a diagnosed one-shot `fix_command`
/// (`None` for any command cockpit did not itself diagnose).
pub fn persist_command_for_fix_command(fix_command: &str) -> Option<String> {
    UsernsRestriction::from_fix_command(fix_command)
        .map(|restriction| restriction.persist_command().to_string())
}

/// `/proc` knob (Ubuntu 23.10+/24.04 default) that, when `1`, lets a process
/// create an unprivileged user namespace but strips the capabilities needed
/// to populate its uid/gid map unless it has an AppArmor profile granting
/// `userns` — which the distro `bwrap` does not, so map setup EPERMs.
#[cfg(target_os = "linux")]
const APPARMOR_USERNS_SYSCTL: &str = "/proc/sys/kernel/apparmor_restrict_unprivileged_userns";
/// Debian/older-Ubuntu knob: `0` forbids unprivileged `CLONE_NEWUSER`.
#[cfg(target_os = "linux")]
const USERNS_CLONE_SYSCTL: &str = "/proc/sys/kernel/unprivileged_userns_clone";
/// Generic knob: `0` forbids creating any user namespace.
#[cfg(target_os = "linux")]
const MAX_USER_NAMESPACES_SYSCTL: &str = "/proc/sys/user/max_user_namespaces";

pub const APPARMOR_USERNS_FIX_COMMAND: &str =
    "sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0";
pub const APPARMOR_USERNS_PERSIST_COMMAND: &str = "echo 'kernel.apparmor_restrict_unprivileged_userns=0' | sudo tee /etc/sysctl.d/60-cockpit-userns.conf";
pub const USERNS_CLONE_FIX_COMMAND: &str = "sudo sysctl -w kernel.unprivileged_userns_clone=1";
pub const USERNS_CLONE_PERSIST_COMMAND: &str =
    "echo 'kernel.unprivileged_userns_clone=1' | sudo tee /etc/sysctl.d/60-cockpit-userns.conf";
pub const MAX_USER_NAMESPACES_FIX_COMMAND: &str = "sudo sysctl -w user.max_user_namespaces=15000";
pub const MAX_USER_NAMESPACES_PERSIST_COMMAND: &str =
    "echo 'user.max_user_namespaces=15000' | sudo tee /etc/sysctl.d/60-cockpit-userns.conf";

/// A diagnosed host policy that stops bwrap from entering its user
/// namespace. Each variant owns its exact one-shot fix, its reboot-persistent
/// companion, and (where one exists) a narrower alternative. cockpit only
/// *diagnoses*: it never runs these commands or touches AppArmor itself
/// (host-security mutation is the user's call, not the harness's).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsernsRestriction {
    /// `kernel.apparmor_restrict_unprivileged_userns=1` (Ubuntu 23.10+).
    AppArmor,
    /// `kernel.unprivileged_userns_clone=0` (Debian / older Ubuntu).
    UnprivilegedUsernsClone,
    /// `user.max_user_namespaces=0`.
    MaxUserNamespaces,
}

impl UsernsRestriction {
    pub const ALL: [Self; 3] = [
        Self::AppArmor,
        Self::UnprivilegedUsernsClone,
        Self::MaxUserNamespaces,
    ];

    /// One-shot host command that lifts the restriction until reboot.
    pub const fn fix_command(self) -> &'static str {
        match self {
            Self::AppArmor => APPARMOR_USERNS_FIX_COMMAND,
            Self::UnprivilegedUsernsClone => USERNS_CLONE_FIX_COMMAND,
            Self::MaxUserNamespaces => MAX_USER_NAMESPACES_FIX_COMMAND,
        }
    }

    /// Host command that keeps [`Self::fix_command`] across reboots.
    pub const fn persist_command(self) -> &'static str {
        match self {
            Self::AppArmor => APPARMOR_USERNS_PERSIST_COMMAND,
            Self::UnprivilegedUsernsClone => USERNS_CLONE_PERSIST_COMMAND,
            Self::MaxUserNamespaces => MAX_USER_NAMESPACES_PERSIST_COMMAND,
        }
    }

    /// Map an exact (diagnosed) fix command back to its restriction.
    pub fn from_fix_command(command: &str) -> Option<Self> {
        let command = command.trim();
        Self::ALL
            .into_iter()
            .find(|restriction| restriction.fix_command() == command)
    }

    /// Map a diagnosed reason (which always embeds the fix command) back to
    /// its restriction.
    pub fn from_reason(reason: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|restriction| reason.contains(restriction.fix_command()))
    }

    /// Terse, model- and user-facing reason naming the policy and the fix.
    pub fn reason(self) -> String {
        match self {
            Self::AppArmor => format!(
                "unprivileged user namespaces are restricted by AppArmor (Ubuntu 23.10+); `{}` re-enables confinement",
                APPARMOR_USERNS_FIX_COMMAND
            ),
            Self::UnprivilegedUsernsClone => format!(
                "unprivileged user namespaces are disabled (kernel.unprivileged_userns_clone=0); `{}` re-enables confinement",
                USERNS_CLONE_FIX_COMMAND
            ),
            Self::MaxUserNamespaces => format!(
                "user namespaces are disabled (user.max_user_namespaces=0); `{}` re-enables confinement",
                MAX_USER_NAMESPACES_FIX_COMMAND
            ),
        }
    }

    /// A narrower remedy than the host-wide sysctl, when one exists. For the
    /// AppArmor restriction that is a profile granting `userns` to the bwrap
    /// binary zerobox actually launches — never to cockpit itself.
    pub fn alternative(self) -> Option<String> {
        match self {
            Self::AppArmor => Some(apparmor_bwrap_profile_hint(&bwrap_path_for_hint())),
            Self::UnprivilegedUsernsClone | Self::MaxUserNamespaces => None,
        }
    }

    #[cfg(target_os = "linux")]
    fn diagnosis(self) -> SandboxDiagnosis {
        SandboxDiagnosis {
            reason: self.reason(),
            fix_command: Some(self.fix_command().to_string()),
        }
    }
}

/// The narrower AppArmor remedy text for the bwrap binary at `bwrap`.
pub fn apparmor_bwrap_profile_hint(bwrap: &str) -> String {
    format!(
        "Narrower alternative: keep the restriction and grant user namespaces only to bwrap with an AppArmor profile, e.g. /etc/apparmor.d/bwrap containing `abi <abi/4.0>, profile bwrap {bwrap} flags=(unconfined) {{ userns, }}`, then run `sudo apparmor_parser -r /etc/apparmor.d/bwrap`."
    )
}

/// The bwrap binary zerobox prefers: the first `bwrap` on `PATH`
/// (canonicalized), else the distro default path.
fn bwrap_path_for_hint() -> String {
    std::env::var_os("PATH")
        .and_then(|path| {
            std::env::split_paths(&path)
                .map(|dir| dir.join("bwrap"))
                .find(|candidate| candidate.is_file())
        })
        .map(|found| std::fs::canonicalize(&found).unwrap_or(found))
        .map(|path| path.display().to_string())
        .unwrap_or_else(|| "/usr/bin/bwrap".to_string())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SandboxDiagnosis {
    reason: String,
    fix_command: Option<String>,
}

/// Linux only: diagnose *why* the sandbox cannot enter its user namespace.
///
/// The primary signal is stderr-independent: a forked child performs the
/// exact kernel steps bwrap needs (`unshare(CLONE_NEWUSER)`, deny
/// `setgroups`, write `uid_map`) and reports which step failed with which
/// errno, classified against the userns sysctls
/// ([`classify_userns_restriction`]). bwrap's stderr (`setting up uid map:
/// Permission denied`, …) is kept as a secondary signal for hosts where the
/// restriction applies to bwrap but not to cockpit's own probe. `None`
/// (caller keeps the generic reason) when neither identifies a restriction.
#[cfg(target_os = "linux")]
async fn diagnose_userns_restriction(raw: &str) -> Option<SandboxDiagnosis> {
    let sysctls = UsernsSysctls::read();
    let probe = probe_userns().await;
    classify_userns_restriction(probe, sysctls)
        .or_else(|| stderr_userns_restriction(raw, sysctls))
        .map(UsernsRestriction::diagnosis)
}

/// No AppArmor / `/proc` on macOS or Windows — the probe keeps its generic
/// reason there, byte-for-byte unchanged.
#[cfg(not(target_os = "linux"))]
async fn diagnose_userns_restriction(_raw: &str) -> Option<SandboxDiagnosis> {
    None
}

/// Pure core of the stderr-based AppArmor-userns diagnosis, split out so the
/// signature match is unit-testable without reading `/proc`: given the
/// probe-failure text and whether the AppArmor sysctl is engaged, return the
/// actionable reason when the failure is the uid/gid-map permission denial
/// under that policy.
#[cfg(all(test, target_os = "linux"))]
fn userns_restriction_reason(raw: &str, apparmor_restricted: bool) -> Option<SandboxDiagnosis> {
    if !apparmor_restricted || !stderr_reports_map_denial(raw) {
        return None;
    }
    Some(UsernsRestriction::AppArmor.diagnosis())
}

#[cfg(target_os = "linux")]
fn stderr_reports_map_denial(raw: &str) -> bool {
    let lc = raw.to_ascii_lowercase();
    (lc.contains("uid map") || lc.contains("gid map")) && lc.contains("permission denied")
}

/// Secondary (stderr) signal: bwrap's own wording, classified against the
/// same sysctl readings as the primary probe.
#[cfg(target_os = "linux")]
fn stderr_userns_restriction(raw: &str, sysctls: UsernsSysctls) -> Option<UsernsRestriction> {
    if sysctls.apparmor_restricted() && stderr_reports_map_denial(raw) {
        return Some(UsernsRestriction::AppArmor);
    }
    let lc = raw.to_ascii_lowercase();
    let namespace_denied = lc.contains("namespace")
        && (lc.contains("operation not permitted")
            || lc.contains("no permission")
            || lc.contains("no space left")
            || lc.contains("permission denied"));
    if !namespace_denied {
        return None;
    }
    sysctls.disabled_restriction()
}

/// Which kernel step of the userns probe failed.
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UsernsProbeStage {
    Unshare,
    Setgroups,
    UidMap,
}

/// The errno classes the classifier distinguishes (everything else is
/// `Other`). Kept as a closed set so the child can report it in its exit
/// status without allocating.
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UsernsProbeErrno {
    Eperm,
    Eacces,
    Enospc,
    Eusers,
    Einval,
    Other,
}

/// Outcome of the forked userns probe.
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UsernsProbeResult {
    /// All three steps succeeded: user namespaces work for this process.
    Created,
    Failed {
        stage: UsernsProbeStage,
        errno: UsernsProbeErrno,
    },
    /// The probe itself could not run or reported something unexpected.
    Inconclusive,
}

/// Userns-related sysctl readings (`None` when the knob does not exist on
/// this kernel or cannot be read).
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct UsernsSysctls {
    apparmor_restrict_unprivileged_userns: Option<u64>,
    unprivileged_userns_clone: Option<u64>,
    max_user_namespaces: Option<u64>,
}

#[cfg(target_os = "linux")]
impl UsernsSysctls {
    fn read() -> Self {
        fn read_u64(path: &str) -> Option<u64> {
            std::fs::read_to_string(path).ok()?.trim().parse().ok()
        }
        Self {
            apparmor_restrict_unprivileged_userns: read_u64(APPARMOR_USERNS_SYSCTL),
            unprivileged_userns_clone: read_u64(USERNS_CLONE_SYSCTL),
            max_user_namespaces: read_u64(MAX_USER_NAMESPACES_SYSCTL),
        }
    }

    fn apparmor_restricted(self) -> bool {
        self.apparmor_restrict_unprivileged_userns == Some(1)
    }

    /// A knob that forbids creating the namespace outright.
    fn disabled_restriction(self) -> Option<UsernsRestriction> {
        if self.unprivileged_userns_clone == Some(0) {
            Some(UsernsRestriction::UnprivilegedUsernsClone)
        } else if self.max_user_namespaces == Some(0) {
            Some(UsernsRestriction::MaxUserNamespaces)
        } else {
            None
        }
    }
}

/// Pure classifier over the forked probe result and the sysctl readings.
///
/// - `unshare` refused (EPERM/EACCES/ENOSPC/EUSERS) → whichever knob forbids
///   namespace creation (`unprivileged_userns_clone=0`, then
///   `max_user_namespaces=0`); with neither, an engaged AppArmor restriction
///   explains an EPERM/EACCES.
/// - `setgroups`/`uid_map` write refused (EPERM/EACCES) with the AppArmor
///   sysctl engaged → the AppArmor restriction (the namespace is created but
///   stripped of the capabilities needed to map ids).
/// - Anything else (namespace works, unrelated errno, inconclusive) → `None`.
#[cfg(target_os = "linux")]
fn classify_userns_restriction(
    probe: UsernsProbeResult,
    sysctls: UsernsSysctls,
) -> Option<UsernsRestriction> {
    match probe {
        UsernsProbeResult::Failed {
            stage: UsernsProbeStage::Unshare,
            errno,
        } => {
            if !matches!(
                errno,
                UsernsProbeErrno::Eperm
                    | UsernsProbeErrno::Eacces
                    | UsernsProbeErrno::Enospc
                    | UsernsProbeErrno::Eusers
            ) {
                return None;
            }
            sysctls.disabled_restriction().or_else(|| {
                (sysctls.apparmor_restricted()
                    && matches!(errno, UsernsProbeErrno::Eperm | UsernsProbeErrno::Eacces))
                .then_some(UsernsRestriction::AppArmor)
            })
        }
        UsernsProbeResult::Failed {
            stage: UsernsProbeStage::Setgroups | UsernsProbeStage::UidMap,
            errno: UsernsProbeErrno::Eperm | UsernsProbeErrno::Eacces,
        } if sysctls.apparmor_restricted() => Some(UsernsRestriction::AppArmor),
        UsernsProbeResult::Created
        | UsernsProbeResult::Failed { .. }
        | UsernsProbeResult::Inconclusive => None,
    }
}

/// Exit-status encoding for the forked probe: `0` = namespace created and
/// mapped; `100 + stage * 10 + errno` = the step that failed.
#[cfg(target_os = "linux")]
const USERNS_PROBE_EXIT_BASE: i32 = 100;

#[cfg(target_os = "linux")]
const fn userns_probe_stage_code(stage: UsernsProbeStage) -> i32 {
    match stage {
        UsernsProbeStage::Unshare => 1,
        UsernsProbeStage::Setgroups => 2,
        UsernsProbeStage::UidMap => 3,
    }
}

/// Raw errno → closed errno class code. Pure integer matching, so it is
/// async-signal-safe inside the forked child.
#[cfg(target_os = "linux")]
const fn userns_probe_errno_code(raw: i32) -> i32 {
    match raw {
        libc::EPERM => 1,
        libc::EACCES => 2,
        libc::ENOSPC => 3,
        libc::EUSERS => 4,
        libc::EINVAL => 5,
        _ => 9,
    }
}

#[cfg(target_os = "linux")]
const fn userns_probe_exit_code(stage: UsernsProbeStage, raw_errno: i32) -> i32 {
    USERNS_PROBE_EXIT_BASE
        + userns_probe_stage_code(stage) * 10
        + userns_probe_errno_code(raw_errno)
}

/// Decode the child's exit code (`None` = killed by a signal).
#[cfg(target_os = "linux")]
fn decode_userns_probe_exit(code: Option<i32>) -> UsernsProbeResult {
    let Some(code) = code else {
        return UsernsProbeResult::Inconclusive;
    };
    if code == 0 {
        return UsernsProbeResult::Created;
    }
    let offset = code - USERNS_PROBE_EXIT_BASE;
    if !(10..40).contains(&offset) {
        return UsernsProbeResult::Inconclusive;
    }
    let stage = match offset / 10 {
        1 => UsernsProbeStage::Unshare,
        2 => UsernsProbeStage::Setgroups,
        3 => UsernsProbeStage::UidMap,
        _ => return UsernsProbeResult::Inconclusive,
    };
    let errno = match offset % 10 {
        1 => UsernsProbeErrno::Eperm,
        2 => UsernsProbeErrno::Eacces,
        3 => UsernsProbeErrno::Enospc,
        4 => UsernsProbeErrno::Eusers,
        5 => UsernsProbeErrno::Einval,
        9 => UsernsProbeErrno::Other,
        _ => return UsernsProbeResult::Inconclusive,
    };
    UsernsProbeResult::Failed { stage, errno }
}

/// Fork a child that performs bwrap's user-namespace steps and exits with the
/// encoded outcome. The child never execs: it `_exit`s from `pre_exec`, so
/// the `true` program name is never resolved or run.
#[cfg(target_os = "linux")]
async fn probe_userns() -> UsernsProbeResult {
    // SAFETY: getuid has no preconditions and cannot fail.
    let uid = unsafe { libc::getuid() };
    let uid_map = format!("0 {uid} 1").into_bytes();
    let mut command = tokio::process::Command::new("true");
    command
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true);
    // SAFETY: the closure runs in the forked child before exec and performs
    // only async-signal-safe syscalls (unshare/open/write/close/_exit) over
    // memory captured before the fork; it never allocates or takes a lock.
    unsafe {
        command.pre_exec(move || -> std::io::Result<()> { userns_probe_child(&uid_map) });
    }
    match tokio::time::timeout(std::time::Duration::from_secs(5), command.status()).await {
        Ok(Ok(status)) => decode_userns_probe_exit(status.code()),
        Ok(Err(_)) | Err(_) => UsernsProbeResult::Inconclusive,
    }
}

/// Child half of [`probe_userns`]. Never returns.
#[cfg(target_os = "linux")]
fn userns_probe_child(uid_map: &[u8]) -> ! {
    // SAFETY: called only in the single-threaded forked child; every call is
    // an async-signal-safe syscall and `_exit` skips all user-space cleanup.
    unsafe {
        if libc::unshare(libc::CLONE_NEWUSER) != 0 {
            libc::_exit(userns_probe_exit_code(
                UsernsProbeStage::Unshare,
                last_errno(),
            ));
        }
        // `setgroups` must be denied before an unprivileged gid map; kernels
        // older than 3.19 lack the file, which is not a restriction.
        if let Err(errno) = write_proc_self(c"/proc/self/setgroups", b"deny")
            && errno != libc::ENOENT
        {
            libc::_exit(userns_probe_exit_code(UsernsProbeStage::Setgroups, errno));
        }
        if let Err(errno) = write_proc_self(c"/proc/self/uid_map", uid_map) {
            libc::_exit(userns_probe_exit_code(UsernsProbeStage::UidMap, errno));
        }
        libc::_exit(0)
    }
}

#[cfg(target_os = "linux")]
fn last_errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// Write `contents` to a `/proc/self` file with raw syscalls, returning the
/// errno of the failing step.
///
/// # Safety
/// Must only be used where raw `open`/`write`/`close` are sound (it is
/// called from the forked probe child).
#[cfg(target_os = "linux")]
unsafe fn write_proc_self(path: &std::ffi::CStr, contents: &[u8]) -> Result<(), i32> {
    // SAFETY: `path` is a valid NUL-terminated string.
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(last_errno());
    }
    // SAFETY: `fd` is open and `contents` is a valid readable buffer.
    let written = unsafe { libc::write(fd, contents.as_ptr().cast(), contents.len()) };
    let result = if written < 0 {
        Err(last_errno())
    } else if written as usize != contents.len() {
        Err(libc::EIO)
    } else {
        Ok(())
    };
    // SAFETY: `fd` was opened above and is closed exactly once.
    unsafe { libc::close(fd) };
    result
}

/// Condense a multi-line probe failure into a single terse reason fragment
/// for the one-sentence model-facing error (token economy §10): trim, take
/// the last non-empty line (bwrap's actual error is usually the tail), and
/// cap the length.
fn clean_reason(raw: &str) -> String {
    const REASON_CAP: usize = 160;
    let line = raw
        .lines()
        .map(str::trim)
        .rfind(|l| !l.is_empty())
        .unwrap_or("")
        .trim();
    let line = if line.is_empty() {
        "sandbox initialization failed"
    } else {
        line
    };
    if line.len() > REASON_CAP {
        let mut s: String = line.chars().take(REASON_CAP).collect();
        s.push('…');
        s
    } else {
        line.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supported_off_only_on_windows() {
        assert_eq!(shell_sandbox_supported(), cfg!(not(windows)));
    }

    // ---- availability-gating decision (injectable availability) -----------
    //
    // The gating decision is a pure function of (sandbox_on, availability),
    // so the three outcomes are covered here without ever
    // exercising a real bwrap — the availability result is injected.

    #[test]
    fn gate_available_and_enabled_confines() {
        let avail = SandboxAvailability::Available;
        assert_eq!(
            gate_decision(true, &avail),
            SandboxGate::Confine,
            "sandbox on + available → confine",
        );
    }

    #[test]
    fn gate_unavailable_and_enabled_refuses_with_reason() {
        let avail = SandboxAvailability::Unavailable {
            reason: "bwrap: No permission to create new namespace".to_string(),
            fix_command: None,
        };
        match gate_decision(true, &avail) {
            SandboxGate::Refuse { reason } => {
                assert!(
                    reason.contains("namespace"),
                    "reason carried through: {reason}"
                );
            }
            other => panic!("expected Refuse, got {other:?}"),
        }
    }

    #[test]
    fn gate_unsupported_platform_runs_unconfined_when_enabled() {
        let availability = SandboxAvailability::UnsupportedPlatform {
            reason: "no Windows backend".to_string(),
        };
        assert_eq!(gate_decision(true, &availability), SandboxGate::Unconfined);
    }

    #[test]
    fn gate_unsupported_platform_refuses_when_a_kb_fence_requires_confinement() {
        let availability = SandboxAvailability::UnsupportedPlatform {
            reason: "no Windows backend".to_string(),
        };
        assert_eq!(
            gate_decision_requiring_confinement(true, true, &availability),
            SandboxGate::Refuse {
                reason: "no Windows backend".to_string()
            }
        );
    }

    #[test]
    fn gate_unavailable_but_disabled_runs_unconfined() {
        let avail = SandboxAvailability::Unavailable {
            reason: "bwrap absent".to_string(),
            fix_command: None,
        };
        // `/sandbox off` → no probe consulted for the decision, run as today.
        assert_eq!(
            gate_decision(false, &avail),
            SandboxGate::Unconfined,
            "sandbox off → unconfined even when unavailable",
        );
    }

    #[test]
    fn gate_decision_ignores_grants() {
        // A command grant authorizes a later unconfined escalation rerun; it
        // never changes the sandbox gate. This stands in for any grant-derived
        // fact the caller may have computed.
        let _grant_would_authorize_escalation = true;
        assert_eq!(
            gate_decision(true, &SandboxAvailability::Available),
            SandboxGate::Confine
        );
        match gate_decision(
            true,
            &SandboxAvailability::Unavailable {
                reason: "x".to_string(),
                fix_command: None,
            },
        ) {
            SandboxGate::Refuse { reason } => assert_eq!(reason, "x"),
            other => panic!("expected Refuse, got {other:?}"),
        }
    }

    // ---- AppArmor-userns diagnosis (Linux only) ---------------------------
    //
    // The `/proc`-read wrapper is environment-dependent, so the signature
    // match is tested through the pure core with the sysctl state injected.

    #[cfg(target_os = "linux")]
    #[test]
    fn userns_diagnosis_fires_on_uid_map_denial_under_apparmor() {
        let raw = "bwrap: setting up uid map: Permission denied";
        let r = userns_restriction_reason(raw, true).expect("diagnosis fires");
        assert!(r.reason.contains("AppArmor"), "names the policy: {:?}", r);
        assert_eq!(
            r.fix_command.as_deref(),
            Some(APPARMOR_USERNS_FIX_COMMAND),
            "gives the exact sysctl command"
        );
        assert!(
            r.reason.contains(APPARMOR_USERNS_FIX_COMMAND),
            "keeps the command visible in the reason: {:?}",
            r
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn userns_diagnosis_silent_when_apparmor_not_engaged() {
        // Same failure, but the restriction isn't on → keep the generic reason.
        let raw = "bwrap: setting up uid map: Permission denied";
        assert_eq!(userns_restriction_reason(raw, false), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn userns_diagnosis_silent_on_unrelated_failure() {
        // bwrap absent / a different EPERM → not the uid-map signature.
        let raw = "bwrap: execvp true: No such file or directory";
        assert_eq!(userns_restriction_reason(raw, true), None);
    }

    #[test]
    fn clean_reason_takes_terse_tail_line() {
        let raw = "bwrap: setting up namespace\nsome noise\nbwrap: Loopback: Failed RTM_NEWADDR: Operation not permitted\n";
        let r = clean_reason(raw);
        assert_eq!(
            r,
            "bwrap: Loopback: Failed RTM_NEWADDR: Operation not permitted"
        );
    }

    #[test]
    fn clean_reason_caps_length() {
        let raw = "x".repeat(500);
        let r = clean_reason(&raw);
        assert!(
            r.chars().count() <= 161,
            "capped, got {} chars",
            r.chars().count()
        );
        assert!(r.ends_with('…'));
    }

    #[test]
    fn clean_reason_empty_falls_back() {
        assert_eq!(clean_reason("   \n  \n"), "sandbox initialization failed");
    }

    /// §6.5 platform gate: macOS/Windows have no AppArmor userns restriction,
    /// so the userns diagnosis is a no-op stub there — even on the exact
    /// uid-map-denial signature. With no diagnosis, the §6.5 user-facing notice
    /// is never raised on those platforms (the `Refuse` path only fires when
    /// the probe actually reports the sandbox unavailable).
    #[cfg(not(target_os = "linux"))]
    #[tokio::test]
    async fn userns_diagnosis_is_noop_off_linux() {
        assert_eq!(
            diagnose_userns_restriction("bwrap: setting up uid map: Permission denied").await,
            None
        );
    }

    // ---- stderr-independent userns classifier (Linux only) ---------------

    #[cfg(target_os = "linux")]
    fn sysctls(apparmor: Option<u64>, clone: Option<u64>, max: Option<u64>) -> UsernsSysctls {
        UsernsSysctls {
            apparmor_restrict_unprivileged_userns: apparmor,
            unprivileged_userns_clone: clone,
            max_user_namespaces: max,
        }
    }

    #[cfg(target_os = "linux")]
    fn failed(stage: UsernsProbeStage, errno: UsernsProbeErrno) -> UsernsProbeResult {
        UsernsProbeResult::Failed { stage, errno }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn classifier_uid_map_eperm_under_apparmor_is_apparmor_restriction() {
        for stage in [UsernsProbeStage::UidMap, UsernsProbeStage::Setgroups] {
            for errno in [UsernsProbeErrno::Eperm, UsernsProbeErrno::Eacces] {
                assert_eq!(
                    classify_userns_restriction(
                        failed(stage, errno),
                        sysctls(Some(1), None, Some(15000))
                    ),
                    Some(UsernsRestriction::AppArmor),
                    "{stage:?}/{errno:?}"
                );
            }
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn classifier_uid_map_eperm_without_apparmor_is_not_diagnosed() {
        assert_eq!(
            classify_userns_restriction(
                failed(UsernsProbeStage::UidMap, UsernsProbeErrno::Eperm),
                sysctls(Some(0), None, Some(15000))
            ),
            None
        );
        assert_eq!(
            classify_userns_restriction(
                failed(UsernsProbeStage::UidMap, UsernsProbeErrno::Eperm),
                sysctls(None, None, None)
            ),
            None
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn classifier_unshare_refused_names_the_disabling_knob() {
        for errno in [
            UsernsProbeErrno::Eperm,
            UsernsProbeErrno::Eacces,
            UsernsProbeErrno::Enospc,
            UsernsProbeErrno::Eusers,
        ] {
            assert_eq!(
                classify_userns_restriction(
                    failed(UsernsProbeStage::Unshare, errno),
                    sysctls(None, Some(0), Some(15000))
                ),
                Some(UsernsRestriction::UnprivilegedUsernsClone),
                "{errno:?}"
            );
            assert_eq!(
                classify_userns_restriction(
                    failed(UsernsProbeStage::Unshare, errno),
                    sysctls(None, Some(1), Some(0))
                ),
                Some(UsernsRestriction::MaxUserNamespaces),
                "{errno:?}"
            );
        }
        // Both knobs off: the clone knob is named first (it is checked first
        // by the kernel for unprivileged callers).
        assert_eq!(
            classify_userns_restriction(
                failed(UsernsProbeStage::Unshare, UsernsProbeErrno::Enospc),
                sysctls(None, Some(0), Some(0))
            ),
            Some(UsernsRestriction::UnprivilegedUsernsClone)
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn classifier_unshare_eperm_with_only_apparmor_is_apparmor() {
        assert_eq!(
            classify_userns_restriction(
                failed(UsernsProbeStage::Unshare, UsernsProbeErrno::Eperm),
                sysctls(Some(1), None, Some(15000))
            ),
            Some(UsernsRestriction::AppArmor)
        );
        // ENOSPC is a namespace-count limit, not an AppArmor denial.
        assert_eq!(
            classify_userns_restriction(
                failed(UsernsProbeStage::Unshare, UsernsProbeErrno::Enospc),
                sysctls(Some(1), None, Some(15000))
            ),
            None
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn classifier_is_silent_when_userns_works_or_probe_inconclusive() {
        let restricted = sysctls(Some(1), Some(0), Some(0));
        assert_eq!(
            classify_userns_restriction(UsernsProbeResult::Created, restricted),
            None
        );
        assert_eq!(
            classify_userns_restriction(UsernsProbeResult::Inconclusive, restricted),
            None
        );
        assert_eq!(
            classify_userns_restriction(
                failed(UsernsProbeStage::Unshare, UsernsProbeErrno::Einval),
                restricted
            ),
            None
        );
        assert_eq!(
            classify_userns_restriction(
                failed(UsernsProbeStage::UidMap, UsernsProbeErrno::Other),
                restricted
            ),
            None
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn probe_exit_codes_round_trip() {
        for (stage, raw, errno) in [
            (
                UsernsProbeStage::Unshare,
                libc::EPERM,
                UsernsProbeErrno::Eperm,
            ),
            (
                UsernsProbeStage::Unshare,
                libc::ENOSPC,
                UsernsProbeErrno::Enospc,
            ),
            (
                UsernsProbeStage::Unshare,
                libc::EUSERS,
                UsernsProbeErrno::Eusers,
            ),
            (
                UsernsProbeStage::Setgroups,
                libc::EACCES,
                UsernsProbeErrno::Eacces,
            ),
            (
                UsernsProbeStage::UidMap,
                libc::EPERM,
                UsernsProbeErrno::Eperm,
            ),
            (
                UsernsProbeStage::UidMap,
                libc::EINVAL,
                UsernsProbeErrno::Einval,
            ),
            (UsernsProbeStage::UidMap, libc::EIO, UsernsProbeErrno::Other),
        ] {
            let code = userns_probe_exit_code(stage, raw);
            assert!((0..=255).contains(&code), "exit code fits a status byte");
            assert_eq!(
                decode_userns_probe_exit(Some(code)),
                UsernsProbeResult::Failed { stage, errno }
            );
        }
        assert_eq!(
            decode_userns_probe_exit(Some(0)),
            UsernsProbeResult::Created
        );
        assert_eq!(
            decode_userns_probe_exit(None),
            UsernsProbeResult::Inconclusive
        );
        assert_eq!(
            decode_userns_probe_exit(Some(1)),
            UsernsProbeResult::Inconclusive
        );
        assert_eq!(
            decode_userns_probe_exit(Some(127)),
            UsernsProbeResult::Inconclusive
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn stderr_signal_is_secondary_and_uses_the_same_sysctls() {
        let apparmor = sysctls(Some(1), None, Some(15000));
        assert_eq!(
            stderr_userns_restriction("bwrap: setting up uid map: Permission denied", apparmor),
            Some(UsernsRestriction::AppArmor)
        );
        assert_eq!(
            stderr_userns_restriction(
                "bwrap: No permission to create new namespace, likely because the kernel does not allow non-privileged user namespaces",
                sysctls(None, Some(0), None)
            ),
            Some(UsernsRestriction::UnprivilegedUsernsClone)
        );
        assert_eq!(
            stderr_userns_restriction(
                "bwrap: Creating new namespace failed: No space left on device",
                sysctls(None, None, Some(0))
            ),
            Some(UsernsRestriction::MaxUserNamespaces)
        );
        assert_eq!(
            stderr_userns_restriction(
                "bwrap: execvp true: No such file or directory",
                sysctls(Some(1), Some(0), Some(0))
            ),
            None
        );
    }

    /// Live smoke check of the forked probe: whatever this host allows, the
    /// probe must terminate with a decodable result and never hang or panic.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn userns_probe_terminates_with_a_decodable_result() {
        let result = probe_userns().await;
        assert!(matches!(
            result,
            UsernsProbeResult::Created
                | UsernsProbeResult::Failed { .. }
                | UsernsProbeResult::Inconclusive
        ));
    }

    // ---- remedy mapping ----------------------------------------------------

    #[test]
    fn every_restriction_has_a_matching_fix_and_persist_command() {
        for restriction in UsernsRestriction::ALL {
            let fix = restriction.fix_command();
            assert_eq!(UsernsRestriction::from_fix_command(fix), Some(restriction));
            assert_eq!(
                UsernsRestriction::from_reason(&restriction.reason()),
                Some(restriction)
            );
            assert_eq!(
                persist_command_for_fix_command(fix).as_deref(),
                Some(restriction.persist_command())
            );
            assert_eq!(
                fix_command_for_reason(&restriction.reason()).as_deref(),
                Some(fix)
            );
            // The persisted drop-in sets the same key=value as the one-shot fix.
            let setting = fix.trim_start_matches("sudo sysctl -w ");
            assert!(
                restriction
                    .persist_command()
                    .contains(&format!("'{setting}'")),
                "{restriction:?}: {}",
                restriction.persist_command()
            );
            assert!(
                restriction
                    .persist_command()
                    .contains("/etc/sysctl.d/60-cockpit-userns.conf")
            );
        }
        assert_eq!(
            persist_command_for_fix_command("sudo apt-get install demo"),
            None
        );
    }

    #[test]
    fn availability_exposes_persist_command_only_for_diagnosed_restrictions() {
        let diagnosed = SandboxAvailability::Unavailable {
            reason: UsernsRestriction::AppArmor.reason(),
            fix_command: Some(APPARMOR_USERNS_FIX_COMMAND.to_string()),
        };
        assert_eq!(
            diagnosed.persist_command(),
            Some(APPARMOR_USERNS_PERSIST_COMMAND)
        );
        let legacy = SandboxAvailability::Unavailable {
            reason: UsernsRestriction::MaxUserNamespaces.reason(),
            fix_command: None,
        };
        assert_eq!(
            legacy.persist_command(),
            Some(MAX_USER_NAMESPACES_PERSIST_COMMAND)
        );
        let generic = SandboxAvailability::Unavailable {
            reason: "bwrap: execvp true: No such file or directory".to_string(),
            fix_command: None,
        };
        assert_eq!(generic.persist_command(), None);
        assert_eq!(SandboxAvailability::Available.persist_command(), None);
    }

    #[test]
    fn apparmor_alternative_targets_bwrap_not_cockpit() {
        let hint = apparmor_bwrap_profile_hint("/usr/bin/bwrap");
        assert!(hint.contains("profile bwrap /usr/bin/bwrap flags=(unconfined) { userns, }"));
        assert!(!hint.contains("cockpit"), "{hint}");
        assert!(UsernsRestriction::AppArmor.alternative().is_some());
        assert!(
            UsernsRestriction::UnprivilegedUsernsClone
                .alternative()
                .is_none()
        );
    }

    // ---- refreshable availability cache -----------------------------------

    fn unavailable(reason: &str) -> SandboxAvailability {
        SandboxAvailability::Unavailable {
            reason: reason.to_string(),
            fix_command: None,
        }
    }

    #[tokio::test]
    async fn cache_probes_once_until_invalidated() {
        let cache = SandboxAvailabilityCache::new();
        let calls = std::sync::atomic::AtomicUsize::new(0);
        let calls = &calls;
        let probe = move || async move {
            calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            unavailable("restricted")
        };
        assert_eq!(cache.get_or_probe(probe).await, unavailable("restricted"));
        assert_eq!(cache.get_or_probe(probe).await, unavailable("restricted"));
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);

        // The user fixed the host and re-enabled the sandbox: the stale
        // refusal is dropped and the next gate re-probes.
        cache.invalidate();
        assert_eq!(cache.cached(), None);
        let fixed = cache
            .get_or_probe(|| async { SandboxAvailability::Available })
            .await;
        assert_eq!(fixed, SandboxAvailability::Available);
        assert_eq!(cache.cached(), Some(SandboxAvailability::Available));
    }

    #[tokio::test]
    async fn capability_refresh_record_replaces_a_stale_refusal_without_reprobe() {
        let cache = SandboxAvailabilityCache::new();
        cache
            .get_or_probe(|| async { unavailable("restricted") })
            .await;
        // A host-capability refresh re-probed and found the host fixed.
        cache.record(SandboxAvailability::Available);
        let reprobes = std::sync::atomic::AtomicUsize::new(0);
        let reprobes = &reprobes;
        let served = cache
            .get_or_probe(move || async move {
                reprobes.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                unavailable("stale")
            })
            .await;
        assert_eq!(served, SandboxAvailability::Available);
        assert_eq!(
            reprobes.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "a recorded value must be served, not re-probed"
        );
    }

    #[tokio::test]
    async fn in_flight_probe_does_not_clobber_a_newer_recorded_value() {
        let cache = SandboxAvailabilityCache::new();
        let cache_ref = &cache;
        let served = cache
            .get_or_probe(move || async move {
                // A capability refresh lands while this (stale) probe runs.
                cache_ref.record(SandboxAvailability::Available);
                unavailable("stale")
            })
            .await;
        assert_eq!(served, SandboxAvailability::Available);
        assert_eq!(cache.cached(), Some(SandboxAvailability::Available));
    }

    #[tokio::test]
    async fn in_flight_probe_is_not_cached_after_an_invalidation() {
        let cache = SandboxAvailabilityCache::new();
        let cache_ref = &cache;
        let served = cache
            .get_or_probe(move || async move {
                cache_ref.invalidate();
                unavailable("started before the fix")
            })
            .await;
        assert_eq!(served, unavailable("started before the fix"));
        assert_eq!(
            cache.cached(),
            None,
            "a pre-invalidation result is not cached"
        );
    }

    /// The confined command builds to a runnable `tokio::process::Command`
    /// with cwd + tmp as the write area (sandboxing part 2). Gated to
    /// Unix; the Linux backend needs the helper, which `init` installs
    /// (idempotent — safe to call from a test). We assert the *builder*
    /// succeeds and targets the right program, not EPERM enforcement
    /// (that needs a child + the helper re-entry, impractical to assert
    /// from a unit test without spawning).
    #[cfg(unix)]
    #[tokio::test]
    async fn builds_confined_command() {
        init();
        let cwd = tempfile::tempdir().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let cmd = build_sandboxed_command(
            "true",
            cwd.path(),
            Some(tmp.path()),
            &[("SECRET_KEY".to_string(), String::new())],
            &std::collections::HashMap::new(),
            &[],
            None,
        )
        .await
        .expect("sandbox command builds");
        // The prepared command is real and runnable. On Linux it re-execs
        // through the sandbox helper alias, so the program is the helper
        // binary, not `sh` directly; either way it's a non-empty program.
        let dbg = format!("{cmd:?}");
        assert!(!dbg.is_empty());
    }

    #[test]
    fn confined_policy_denies_daemon_control_plane() {
        let cwd = tempfile::tempdir().unwrap();
        let policy = sandbox_policy(
            cwd.path(),
            None,
            &std::collections::HashMap::new(),
            &[],
            None,
        );
        let denied = crate::daemon::control_plane_deny_paths();
        assert!(
            !denied.is_empty(),
            "daemon control-plane paths must resolve so confined children cannot reach the socket"
        );
        for path in &denied {
            assert!(
                policy.deny_paths.contains(path),
                "sandbox policy must deny {}",
                path.display()
            );
        }
    }

    /// Issue #296 acceptance: a confined child cannot read the owner-capability
    /// file or reach the daemon socket, even when those paths sit under an
    /// allowed parent (cwd). Policy-content assertions above cannot catch a
    /// defect in zerobox deny translation or deny-over-allow precedence.
    #[cfg(unix)]
    #[tokio::test]
    async fn confined_child_cannot_reach_daemon_socket_or_owner_capability() {
        init();
        let env = crate::test_env::lock_async().await;

        let cwd = tempfile::tempdir().unwrap();
        let state_home = cwd.path().join("xdg-state");
        let data_home = cwd.path().join("xdg-data");
        std::fs::create_dir_all(&state_home).unwrap();
        std::fs::create_dir_all(&data_home).unwrap();
        env.remove_var("XDG_RUNTIME_DIR");
        env.set_var("TMPDIR", cwd.path());
        env.set_var("XDG_STATE_HOME", &state_home);
        env.set_var("XDG_DATA_HOME", &data_home);

        let canonical = crate::daemon::DaemonPaths::resolve_canonical()
            .expect("resolve fallback daemon control plane");
        let cockpit_runtime = canonical.socket.parent().unwrap().to_path_buf();
        // With no XDG runtime root, rendezvous must fall back beneath the
        // allowed cwd. The nested deny is therefore the load-bearing boundary.
        assert!(
            cockpit_runtime.starts_with(cwd.path()),
            "{cockpit_runtime:?}"
        );
        let per_user_root = cockpit_runtime
            .parent()
            .and_then(std::path::Path::parent)
            .expect("fallback rendezvous has a per-user root");
        assert_eq!(per_user_root.parent(), Some(cwd.path()));
        assert!(
            per_user_root
                .file_name()
                .is_some_and(|name| name.to_string_lossy().starts_with("cockpit-"))
        );
        assert_eq!(
            cockpit_runtime.parent().and_then(|path| path.file_name()),
            Some(std::ffi::OsStr::new("cockpit"))
        );
        assert!(
            cockpit_runtime
                .file_name()
                .is_some_and(|name| name.len() == 24)
        );

        let capability = canonical.owner_capability_path();
        let socket = canonical.socket;
        let _listener = std::os::unix::net::UnixListener::bind(&socket).expect("bind test socket");
        std::fs::write(&capability, "owner-capability-must-not-leak\n").unwrap();

        let allowed_marker = cwd.path().join("allowed.txt");
        std::fs::write(&allowed_marker, "visible\n").unwrap();

        let denied = crate::daemon::control_plane_deny_paths();
        assert!(
            denied.contains(&cockpit_runtime),
            "fallback rendezvous dir must resolve to the test control plane: {denied:?}"
        );
        assert!(
            denied.contains(&state_home.join("cockpit")),
            "state dir must resolve to the test control plane: {denied:?}"
        );
        let policy = sandbox_policy(
            cwd.path(),
            None,
            &std::collections::HashMap::new(),
            &[],
            None,
        );
        for path in &denied {
            assert!(
                policy.deny_paths.contains(path),
                "sandbox policy must deny {}",
                path.display()
            );
        }

        let extra_env = [
            (
                "COCKPIT_TEST_MARKER".to_string(),
                allowed_marker.display().to_string(),
            ),
            (
                "COCKPIT_TEST_CAP".to_string(),
                capability.display().to_string(),
            ),
            (
                "COCKPIT_TEST_SOCK".to_string(),
                socket.display().to_string(),
            ),
        ];
        let session_env = std::collections::HashMap::from([(
            "PATH".to_string(),
            std::env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin".to_string()),
        )]);
        let command = r#"
marker=0; cap=0; sock=0; connected=0
if cat "$COCKPIT_TEST_MARKER" >/dev/null 2>&1; then marker=1; fi
if cat "$COCKPIT_TEST_CAP" >/dev/null 2>&1; then cap=1; fi
if [ -e "$COCKPIT_TEST_SOCK" ]; then sock=1; fi
if command -v python3 >/dev/null 2>&1; then
  python3 -c 'import socket,sys; s=socket.socket(socket.AF_UNIX); s.connect(sys.argv[1])' "$COCKPIT_TEST_SOCK" >/dev/null 2>&1 && connected=1
else
  connected=$sock
fi
printf 'marker=%s cap=%s sock=%s connected=%s\n' "$marker" "$cap" "$sock" "$connected"
"#;
        let mut cmd = build_sandboxed_command(
            command,
            cwd.path(),
            None,
            &extra_env,
            &session_env,
            &[],
            None,
        )
        .await
        .expect("sandbox command builds");

        let argv_blob = cmd
            .as_std()
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join("\n");
        for path in &denied {
            let rendered = path.display().to_string();
            let canonical = path
                .canonicalize()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|_| rendered.clone());
            assert!(
                argv_blob.contains(&rendered) || argv_blob.contains(&canonical),
                "prepared sandbox command must carry deny path {rendered}: {argv_blob}"
            );
        }

        #[cfg(target_os = "linux")]
        {
            let profile = linux_permission_profile_json(&cmd)
                .expect("Linux helper argv must carry --permission-profile JSON");
            for path in &denied {
                let rendered = path.display().to_string();
                let canonical = path
                    .canonicalize()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|_| rendered.clone());
                assert!(
                    json_has_fs_access(&profile, &rendered, "none")
                        || json_has_fs_access(&profile, &canonical, "none"),
                    "zerobox profile must deny {rendered} (canonical {canonical}): {profile}"
                );
            }
            assert!(
                json_has_fs_access(&profile, "/run", "read"),
                "net-enabled sandbox must still grant /run so the control-plane deny is the load-bearing carve-out: {profile}"
            );
        }

        cmd.stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        let output = tokio::time::timeout(std::time::Duration::from_secs(30), cmd.output())
            .await
            .expect("confined child must not hang")
            .expect("spawn confined child");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !stdout.contains("marker=") {
            // Helper re-exec / userns blocked: deny translation was still
            // asserted on the prepared command. A successful exit without
            // the reachability line would be a silent fail-open.
            assert!(
                !output.status.success(),
                "confined child exited 0 without reporting reachability: stdout={stdout:?} stderr={stderr:?}"
            );
            return;
        }
        assert!(
            stdout.contains("marker=1"),
            "child must have run inside the box so denials are not a spawn-failed false pass: stdout={stdout:?} stderr={stderr:?}"
        );
        assert!(
            stdout.contains("cap=0"),
            "confined child must not read the owner-capability file: stdout={stdout:?} stderr={stderr:?}"
        );
        assert!(
            stdout.contains("sock=0"),
            "confined child must not see the daemon socket: stdout={stdout:?} stderr={stderr:?}"
        );
        assert!(
            stdout.contains("connected=0"),
            "confined child must not connect to the daemon socket: stdout={stdout:?} stderr={stderr:?}"
        );
    }

    #[cfg(target_os = "linux")]
    fn linux_permission_profile_json(cmd: &tokio::process::Command) -> Option<serde_json::Value> {
        let args: Vec<String> = cmd
            .as_std()
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();
        args.windows(2)
            .find(|pair| pair[0] == "--permission-profile")
            .and_then(|pair| serde_json::from_str(&pair[1]).ok())
    }

    #[cfg(target_os = "linux")]
    fn json_has_fs_access(value: &serde_json::Value, path: &str, access: &str) -> bool {
        match value {
            serde_json::Value::Object(map) => {
                let this_path = map.get("path").and_then(|path_value| {
                    path_value
                        .get("path")
                        .and_then(serde_json::Value::as_str)
                        .or_else(|| path_value.as_str())
                });
                let this_access = map.get("access").and_then(serde_json::Value::as_str);
                (this_path == Some(path) && this_access == Some(access))
                    || map
                        .values()
                        .any(|child| json_has_fs_access(child, path, access))
            }
            serde_json::Value::Array(items) => items
                .iter()
                .any(|child| json_has_fs_access(child, path, access)),
            _ => false,
        }
    }

    #[test]
    fn sandbox_profile_narrows_write_to_scope() {
        let cwd = tempfile::tempdir().unwrap();
        let scope = cwd.path().join("crates/core");
        std::fs::create_dir_all(&scope).unwrap();
        let env = std::collections::HashMap::new();

        let unscoped = sandbox_policy(cwd.path(), None, &env, &[], None);
        assert!(
            unscoped
                .allow_read_roots
                .contains(&cwd.path().to_path_buf())
        );
        let denied = crate::daemon::control_plane_deny_paths();
        assert!(
            !denied.is_empty(),
            "daemon control-plane deny paths must resolve"
        );
        for path in &denied {
            assert!(
                unscoped.deny_paths.contains(path),
                "confined policy must deny daemon control plane {}",
                path.display()
            );
        }
        assert!(
            unscoped
                .allow_write_roots
                .contains(&cwd.path().to_path_buf())
        );

        let scoped = sandbox_policy(cwd.path(), None, &env, &[], Some(&scope));
        assert!(scoped.allow_read_roots.contains(&cwd.path().to_path_buf()));
        assert!(!scoped.allow_write_roots.contains(&cwd.path().to_path_buf()));
        assert!(scoped.allow_write_roots.contains(&scope));
    }

    #[test]
    fn leased_policy_does_not_admit_shared_session_tmp() {
        let lease_root = tempfile::tempdir().unwrap();
        let shared_tmp = tempfile::tempdir().unwrap();
        let policy = sandbox_policy_for_workspace_lease(
            lease_root.path(),
            Some(shared_tmp.path()),
            &std::collections::HashMap::new(),
            &[],
            None,
        );
        assert!(
            policy
                .allow_read_roots
                .contains(&lease_root.path().to_path_buf())
        );
        assert!(
            policy
                .allow_write_roots
                .contains(&lease_root.path().to_path_buf())
        );
        assert!(
            !policy
                .allow_read_roots
                .contains(&shared_tmp.path().to_path_buf())
                && !policy
                    .allow_write_roots
                    .contains(&shared_tmp.path().to_path_buf()),
            "a shared session temp dir must not escape a workspace lease"
        );
    }

    #[test]
    fn leased_policy_admits_durable_workspace_scratch() {
        let lease_root = tempfile::tempdir().unwrap();
        let workspace_scratch = tempfile::tempdir().unwrap();
        let policy = sandbox_policy_with_visibility_restriction(
            lease_root.path(),
            None,
            Some(workspace_scratch.path()),
            &std::collections::HashMap::new(),
            &[],
            Some(std::path::Path::new("/__cockpit-deny-writes__")),
            true,
            false,
        );
        assert!(
            policy
                .allow_read_roots
                .contains(&workspace_scratch.path().to_path_buf())
        );
        assert!(
            policy
                .allow_write_roots
                .contains(&workspace_scratch.path().to_path_buf())
        );
    }

    /// The scratch dir is wired into `TMPDIR`/`TMP`/`TEMP` on the confined
    /// command, so `mktemp` / `tempfile` / `std::env::temp_dir()` resolve to
    /// the one writable area instead of bare `/tmp` (denied) or an inherited
    /// `TMPDIR` pointing outside the box. Asserted on the built command's env
    /// (deterministic, no bwrap spawn — the helper re-exec can't run under the
    /// test harness, so a spawn-based check would only ever skip).
    #[cfg(unix)]
    #[tokio::test]
    async fn confined_command_points_tmpdir_at_scratch() {
        init();
        let cwd = tempfile::tempdir().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let want = tmp.path().to_string_lossy().into_owned();
        let cmd = build_sandboxed_command(
            "true",
            cwd.path(),
            Some(tmp.path()),
            &[],
            &std::collections::HashMap::new(),
            &[],
            None,
        )
        .await
        .expect("sandbox command builds");
        let envs: std::collections::HashMap<_, _> = cmd
            .as_std()
            .get_envs()
            .filter_map(|(k, v)| Some((k.to_str()?.to_string(), v?.to_str()?.to_string())))
            .collect();
        for key in ["TMPDIR", "TMP", "TEMP"] {
            assert_eq!(
                envs.get(key).map(String::as_str),
                Some(want.as_str()),
                "`{key}` must point at the session scratch dir inside the sandbox",
            );
        }
    }

    /// With no scratch dir the temp-dir override is omitted entirely — we
    /// don't blank or repoint `TMPDIR` to a path the box can't write.
    #[cfg(unix)]
    #[tokio::test]
    async fn no_scratch_dir_leaves_tmpdir_untouched() {
        init();
        let cwd = tempfile::tempdir().unwrap();
        let session_env =
            std::collections::HashMap::from([("TMPDIR".to_string(), "/session/tmp".to_string())]);
        let cmd = build_sandboxed_command("true", cwd.path(), None, &[], &session_env, &[], None)
            .await
            .expect("sandbox command builds");
        // We didn't set TMPDIR; whatever value appears is purely inherited,
        // never one cockpit injected pointing at a missing scratch dir. The
        // assertion that matters: cockpit added no temp-dir override of its
        // own, so the inherited value (if any) equals the process's own.
        let got = cmd
            .as_std()
            .get_envs()
            .find(|(k, _)| k.to_str() == Some("TMPDIR"))
            .and_then(|(_, v)| v)
            .map(|v| v.to_string_lossy().into_owned());
        assert_eq!(
            got,
            Some("/session/tmp".to_string()),
            "with no scratch dir, TMPDIR must come from the session env",
        );
    }

    #[test]
    fn runtime_manager_paths_are_derived_from_path_without_home_root() {
        let env = crate::test_env::lock();
        env.set_var("HOME", "/home/alice");
        let paths = crate::env_snapshot::user_runtime_read_paths_from_path(Some(
            "/usr/bin:/home/alice/.nvm/versions/node/v20/bin:/home/alice/.asdf/shims",
        ));
        assert!(paths.contains(&std::path::PathBuf::from("/home/alice/.nvm")));
        assert!(paths.contains(&std::path::PathBuf::from("/home/alice/.asdf")));
        assert!(!paths.contains(&std::path::PathBuf::from("/home/alice")));
    }

    /// AC2: confined sandbox command env must never carry SEALED_* keys or
    /// sentinel sealed values, even if a caller forgets to scrub first.
    #[cfg(unix)]
    #[tokio::test]
    async fn sealed_bindings_and_noninference_process_egress_are_absent_for_shell_sandbox() {
        init();
        let cwd = tempfile::tempdir().unwrap();
        let mut session_env = std::collections::HashMap::new();
        session_env.insert("PATH".to_string(), "/usr/bin".to_string());
        session_env.insert(
            "SEALED_PROD_TOKEN".to_string(),
            "very-secret-sentinel-value".to_string(),
        );
        let extra_env = [(
            "SEALED_EXTRA".to_string(),
            "very-secret-sentinel-value".to_string(),
        )];
        let cmd = build_sandboxed_command(
            "true",
            cwd.path(),
            None,
            &extra_env,
            &session_env,
            &[],
            None,
        )
        .await
        .expect("sandbox command builds");
        let envs: std::collections::HashMap<_, _> = cmd
            .as_std()
            .get_envs()
            .filter_map(|(k, v)| Some((k.to_str()?.to_string(), v?.to_str()?.to_string())))
            .collect();
        assert!(
            !envs.keys().any(|k| k.starts_with("SEALED_")),
            "confined child must not receive SEALED_* keys: {envs:?}"
        );
        assert!(
            !envs
                .values()
                .any(|v| v.contains("very-secret-sentinel-value")),
            "confined child must not receive sealed sentinel: {envs:?}"
        );
        assert_eq!(envs.get("PATH").map(String::as_str), Some("/usr/bin"));
    }
}
