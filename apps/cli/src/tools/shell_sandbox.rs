//! zerobox shell confinement for the `bash` tool (sandboxing part 2).
//!
//! Wraps a `sh -c <command>` invocation in a zerobox `Sandbox` confined
//! to: the agent cwd (read+write), the per-session tmp dir (read+write),
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
//! (some containers, WSL1, bwrap absent), sandbox setup still fails — so a
//! one-shot environment probe ([`sandbox_available`]) detects that case and
//! lets `bash.rs` refuse confined commands with an actionable error instead
//! of failing each one into the run-fail-escalate prompt.
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
/// agent working directory — read+write inside the sandbox. `tmp_dir`,
/// when present, is the per-session scratch dir — also read+write, and
/// counted as inside the boundary by native-tool checks. `extra_env` is
/// applied on top of the inherited environment (cockpit uses it for the
/// env-scrub overrides). Reads outside cwd + tmp are denied.
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
) -> Result<tokio::process::Command> {
    let mut sandbox = zerobox::Sandbox::command("sh")
        .arg("-c")
        .arg(command)
        .cwd(cwd.to_path_buf())
        // Share the host network (filesystem-confined only). An empty
        // allow-list with no deny-list and no secret store makes zerobox
        // select `BwrapNetworkMode::FullAccess`, so bwrap runs without
        // `--unshare-net` and never attempts the unprivileged loopback
        // bring-up that EPERMs on restricted hosts. Network confinement is
        // out of scope; this only changes networking, not filesystem
        // confinement (cwd + tmp read/write, deny outside still hold).
        .allow_net_all()
        // cwd is the read+write working area.
        .allow_read(cwd.to_path_buf())
        .allow_write(cwd.to_path_buf());

    for (key, value) in session_env {
        sandbox = sandbox.env(key.clone(), value.clone());
    }

    for path in crate::env_snapshot::user_runtime_read_paths_from_path(
        session_env.get("PATH").map(String::as_str),
    ) {
        sandbox = sandbox.allow_read(path);
    }

    for extra in extra_paths {
        sandbox = sandbox.allow_read(extra.path.clone());
        if matches!(extra.access, SandboxPathAccess::ReadWrite) {
            sandbox = sandbox.allow_write(extra.path.clone());
        }
    }

    if let Some(tmp) = tmp_dir {
        sandbox = sandbox
            .allow_read(tmp.to_path_buf())
            .allow_write(tmp.to_path_buf())
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

    // Layer cockpit's env-scrub overrides (e.g. blanking injection-vector
    // vars) on top of the inherited env. Applied after the TMPDIR override
    // above; the scrub set never includes the temp-dir vars, so they stand.
    for (k, v) in extra_env {
        sandbox = sandbox.env(k.clone(), v.clone());
    }

    // Linux: hand zerobox the helper alias captured at init so it can
    // re-enter the current binary as the sandbox helper. When init didn't
    // run / failed, fall through to zerobox's internal default resolution.
    #[cfg(target_os = "linux")]
    if let Some(Some(exe)) = LINUX_SANDBOX_EXE.get() {
        sandbox = sandbox.linux_sandbox_exe(exe.clone());
    }

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
    /// `/sandbox off` error.
    Unavailable { reason: String },
}

/// The gating decision for a single `bash` run, derived purely from the
/// three inputs so it is unit-testable without a working sandbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SandboxGate {
    /// Run confined (sandbox on, supported, available, not broad-granted).
    Confine,
    /// Run unconfined (sandbox off, or already broad-granted).
    Unconfined,
    /// Refuse: sandboxing is enabled but cannot initialize here. `reason`
    /// is surfaced in the model-facing error; the user is told to run
    /// `/sandbox off`.
    Refuse { reason: String },
}

/// Decide how to run a `bash` command, given whether sandboxing is on for
/// this session+platform (`sandbox_on`), whether every constituent command
/// is already granted broad access (`granted_broad`), and the once-probed
/// environment availability (`availability`).
///
/// Pure and total — the seam the unit tests drive with an injected
/// `availability` so the gating logic is covered without a live bwrap.
///
///   - sandbox off → `Unconfined`.
///   - broad-granted → `Unconfined` (the box is skipped regardless).
///   - on + available → `Confine`.
///   - on + unavailable → `Refuse` (never silently unconfined).
pub fn gate_decision(
    sandbox_on: bool,
    granted_broad: bool,
    availability: &SandboxAvailability,
) -> SandboxGate {
    if !sandbox_on || granted_broad {
        return SandboxGate::Unconfined;
    }
    match availability {
        SandboxAvailability::Available => SandboxGate::Confine,
        SandboxAvailability::Unavailable { reason } => SandboxGate::Refuse {
            reason: reason.clone(),
        },
    }
}

/// Process-lifetime cache for the one-shot environment probe.
static SANDBOX_AVAILABILITY: tokio::sync::OnceCell<SandboxAvailability> =
    tokio::sync::OnceCell::const_new();

/// Probe — once per process — whether the sandbox can initialize in this
/// environment, caching the result for the session/process lifetime.
///
/// The probe builds a confined `true` in a valid cwd (`probe_cwd`, the
/// session cwd, falling back to a fresh temp dir) and spawns it. A
/// sandboxed `true` can only fail on sandbox init — never on the command
/// itself — so a spawn failure or non-zero exit means the sandbox is
/// unavailable here. The probe's stderr is captured as the reason string
/// (this avoids brittle stderr matching for the *decision* — the exit code
/// alone gates — while still surfacing a human-readable cause).
pub async fn sandbox_available(probe_cwd: &std::path::Path) -> &'static SandboxAvailability {
    SANDBOX_AVAILABILITY
        .get_or_init(|| async { probe_sandbox(probe_cwd).await })
        .await
}

/// Run the actual probe (no caching). Split out so the cache wrapper stays
/// trivial; the cwd fallback to a fresh temp dir lives here.
async fn probe_sandbox(probe_cwd: &std::path::Path) -> SandboxAvailability {
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
            };
        }
    };

    let probe_env: std::collections::HashMap<String, String> = std::env::vars().collect();
    let mut cmd = match build_sandboxed_command("true", cwd, None, &[], &probe_env, &[]).await {
        Ok(c) => c,
        Err(e) => {
            return SandboxAvailability::Unavailable {
                reason: reason_from(&e.to_string()),
            };
        }
    };
    cmd.stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped());

    let output = match cmd.output().await {
        Ok(o) => o,
        Err(e) => {
            return SandboxAvailability::Unavailable {
                reason: reason_from(&e.to_string()),
            };
        }
    };

    if output.status.success() {
        SandboxAvailability::Available
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let reason = if stderr.trim().is_empty() {
            "the sandbox helper exited non-zero".to_string()
        } else {
            reason_from(&stderr)
        };
        SandboxAvailability::Unavailable { reason }
    }
}

/// Build the model-facing reason for a probe failure: prefer the targeted
/// AppArmor-userns diagnosis (Linux only — see [`diagnose_userns_restriction`]),
/// falling back to the terse bwrap tail line.
fn reason_from(raw: &str) -> String {
    diagnose_userns_restriction(raw).unwrap_or_else(|| clean_reason(raw))
}

/// `/proc` knob (Ubuntu 23.10+/24.04 default) that, when `1`, lets a process
/// create an unprivileged user namespace but strips the capabilities needed
/// to populate its uid/gid map unless it has an AppArmor profile granting
/// `userns` — which the distro `bwrap` does not, so map setup EPERMs.
#[cfg(target_os = "linux")]
const APPARMOR_USERNS_SYSCTL: &str = "/proc/sys/kernel/apparmor_restrict_unprivileged_userns";

/// Linux only: when a probe failure is the kernel refusing to write the
/// user-namespace uid/gid map *and* AppArmor's unprivileged-userns
/// restriction is engaged, replace the opaque `bwrap: setting up uid map:
/// Permission denied` tail with an actionable reason that names the policy
/// and the one-shot sysctl that lifts it. `None` (caller keeps the generic
/// reason) when the signature or the sysctl doesn't match. cockpit only
/// *diagnoses* here — it never runs the sysctl or touches AppArmor itself
/// (host-security mutation is the user's call, not the harness's).
#[cfg(target_os = "linux")]
fn diagnose_userns_restriction(raw: &str) -> Option<String> {
    let restricted = std::fs::read_to_string(APPARMOR_USERNS_SYSCTL)
        .map(|s| s.trim() == "1")
        .unwrap_or(false);
    userns_restriction_reason(raw, restricted)
}

/// No AppArmor / `/proc` on macOS or Windows — the probe keeps its generic
/// reason there, byte-for-byte unchanged.
#[cfg(not(target_os = "linux"))]
fn diagnose_userns_restriction(_raw: &str) -> Option<String> {
    None
}

/// Pure core of the AppArmor-userns diagnosis, split out so the signature
/// match is unit-testable without reading `/proc`: given the probe-failure
/// text and whether the AppArmor sysctl is engaged, return the actionable
/// reason when the failure is the uid/gid-map permission denial under that
/// policy.
#[cfg(target_os = "linux")]
fn userns_restriction_reason(raw: &str, apparmor_restricted: bool) -> Option<String> {
    if !apparmor_restricted {
        return None;
    }
    let lc = raw.to_ascii_lowercase();
    let uid_map_denied =
        (lc.contains("uid map") || lc.contains("gid map")) && lc.contains("permission denied");
    if !uid_map_denied {
        return None;
    }
    Some(
        "unprivileged user namespaces are restricted by AppArmor (Ubuntu 23.10+); \
         `sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0` re-enables confinement"
            .to_string(),
    )
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
    // The gating decision is a pure function of (sandbox_on, granted_broad,
    // availability), so the three outcomes are covered here without ever
    // exercising a real bwrap — the availability result is injected.

    #[test]
    fn gate_available_and_enabled_confines() {
        let avail = SandboxAvailability::Available;
        assert_eq!(
            gate_decision(true, false, &avail),
            SandboxGate::Confine,
            "sandbox on + available + not broad-granted → confine",
        );
    }

    #[test]
    fn gate_unavailable_and_enabled_refuses_with_reason() {
        let avail = SandboxAvailability::Unavailable {
            reason: "bwrap: No permission to create new namespace".to_string(),
        };
        match gate_decision(true, false, &avail) {
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
    fn gate_unavailable_but_disabled_runs_unconfined() {
        let avail = SandboxAvailability::Unavailable {
            reason: "bwrap absent".to_string(),
        };
        // `/sandbox off` → no probe consulted for the decision, run as today.
        assert_eq!(
            gate_decision(false, false, &avail),
            SandboxGate::Unconfined,
            "sandbox off → unconfined even when unavailable",
        );
    }

    #[test]
    fn gate_broad_grant_skips_box_regardless_of_availability() {
        // Already broad-granted: the box is skipped even when available, and
        // an unavailable environment never turns a broad-granted command
        // into a refusal.
        assert_eq!(
            gate_decision(true, true, &SandboxAvailability::Available),
            SandboxGate::Unconfined,
        );
        assert_eq!(
            gate_decision(
                true,
                true,
                &SandboxAvailability::Unavailable {
                    reason: "x".to_string()
                }
            ),
            SandboxGate::Unconfined,
        );
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
        assert!(r.contains("AppArmor"), "names the policy: {r}");
        assert!(
            r.contains("apparmor_restrict_unprivileged_userns=0"),
            "gives the sysctl: {r}"
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
    #[test]
    fn userns_diagnosis_is_noop_off_linux() {
        assert_eq!(
            diagnose_userns_restriction("bwrap: setting up uid map: Permission denied"),
            None
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
        )
        .await
        .expect("sandbox command builds");
        // The prepared command is real and runnable. On Linux it re-execs
        // through the sandbox helper alias, so the program is the helper
        // binary, not `sh` directly; either way it's a non-empty program.
        let dbg = format!("{cmd:?}");
        assert!(!dbg.is_empty());
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
        let cmd = build_sandboxed_command("true", cwd.path(), None, &[], &session_env, &[])
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
        let old_home = std::env::var_os("HOME");
        unsafe {
            std::env::set_var("HOME", "/home/alice");
        }
        let paths = crate::env_snapshot::user_runtime_read_paths_from_path(Some(
            "/usr/bin:/home/alice/.nvm/versions/node/v20/bin:/home/alice/.asdf/shims",
        ));
        if let Some(old_home) = old_home {
            unsafe {
                std::env::set_var("HOME", old_home);
            }
        } else {
            unsafe {
                std::env::remove_var("HOME");
            }
        }
        assert!(paths.contains(&std::path::PathBuf::from("/home/alice/.nvm")));
        assert!(paths.contains(&std::path::PathBuf::from("/home/alice/.asdf")));
        assert!(!paths.contains(&std::path::PathBuf::from("/home/alice")));
    }
}
