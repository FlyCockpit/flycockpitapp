//! Preflight checks before invoking an external harness: the command is
//! on `PATH`, and the harness is authenticated.
//!
//! Auth resolves in one step (implementation note §5, post
//! external-harness-trust-custody-policy):
//! 1. If `auth_probe_args` is non-empty, run
//!    `command auth_probe_args` and treat exit 0 as authenticated.
//! 2. If no probe is configured, assume authenticated (let a real run
//!    surface the failure) — we never block a harness the user wired up
//!    without an auth hint.
//!
//! The former `auth_env_vars` path is retired: external harnesses receive no
//! Cockpit-provided secret environment value, including a dedicated harness
//! authentication token. A harness must authenticate independently without a
//! Cockpit-provided secret.

use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::config::extended::HarnessConfig;
use crate::harness::env::harness_child_env;

/// A preflight failure, with the harness name + command baked into the
/// message per cockpit error conventions (backticked identifiers).
#[derive(Debug)]
pub enum PreflightError {
    /// The command isn't on `PATH`.
    NotOnPath {
        harness: String,
        command: String,
        dependency_line: Option<String>,
    },
    /// The harness is on `PATH` but not authenticated.
    NotAuthenticated { harness: String, command: String },
}

impl std::fmt::Display for PreflightError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PreflightError::NotOnPath {
                harness,
                command,
                dependency_line,
            } => match dependency_line {
                Some(line) => f.write_str(line),
                None => write!(
                    f,
                    "harness `{harness}` is not installed: `{command}` was not found on PATH. \
                     Install it or fix the `command` in /settings.",
                ),
            },
            PreflightError::NotAuthenticated { harness, command } => write!(
                f,
                "harness `{harness}` is not authenticated: `{command}` has no credentials. \
                 Run its login flow or configure an `auth_probe_args` probe, then retry. \
                 Cockpit does not provide secret environment values to external harnesses.",
            ),
        }
    }
}

impl std::error::Error for PreflightError {}

/// Run the preflight for `harness_name`/`cfg`. `Ok(())` means the harness
/// is on `PATH` and authenticated (or has no auth hint). The auth probe
/// runs in `cwd` and is bounded by a short timeout so a hung probe can't
/// wedge the invoke tool.
pub async fn preflight_with_env(
    harness_name: &str,
    cfg: &HarnessConfig,
    cwd: &Path,
    session_overlay: Option<&std::collections::HashMap<String, String>>,
) -> Result<(), PreflightError> {
    // Shared external-runtime health is the sole missing-state source (no
    // separate which_on_path branch). Catalog presets only when the configured
    // command is the bare preset name. Overrides use ConfiguredCommand only —
    // never inherit a trusted-catalog recipe by name resemblance.
    if is_unmodified_catalog_preset(harness_name, &cfg.command) {
        let adapter_id = format!("harness.{harness_name}");
        if let Err(err) =
            crate::external_runtime::require_live_available_for_launch(&adapter_id, cwd)
        {
            return Err(PreflightError::NotOnPath {
                harness: harness_name.to_string(),
                command: format!("{} ({err})", cfg.command),
                dependency_line: crate::external_runtime::current_dependency_context_line(
                    &adapter_id,
                ),
            });
        }
    } else {
        let input =
            crate::external_runtime::ConfiguredCommandInput::new(harness_name, cfg.command.clone());
        let _ = crate::external_runtime::require_configured_command_available_for_launch(
            crate::external_runtime::custom_harness_id(harness_name),
            &format!("harness.custom.{harness_name}"),
            &input,
            cwd,
        )
        .map_err(|err| PreflightError::NotOnPath {
            harness: harness_name.to_string(),
            command: format!("{} ({err})", cfg.command),
            dependency_line: crate::external_runtime::current_dependency_context_line(&format!(
                "harness.custom.{harness_name}"
            )),
        })?;
    }

    if is_authenticated(cfg, cwd, session_overlay).await {
        Ok(())
    } else {
        Err(PreflightError::NotAuthenticated {
            harness: harness_name.to_string(),
            command: cfg.command.clone(),
        })
    }
}

/// Whether `harness_name` is a known preset whose configured command is still
/// the stock bare preset executable (exact string match only).
///
/// Path wrappers such as `/opt/wrappers/claude` are **not** catalog presets —
/// they use ConfiguredCommand resolution for the exact configured executable.
fn is_unmodified_catalog_preset(harness_name: &str, command: &str) -> bool {
    crate::external_runtime::known_harness_preset_names().contains(&harness_name)
        && command == harness_name
}

/// Resolve `command` against `PATH`, honoring `PATHEXT` on Windows.
/// Returns the first executable match. An absolute/relative path is accepted
/// as-is when it points at something spawnable on the current platform.
pub fn which_on_path(command: &str) -> Option<PathBuf> {
    let p = Path::new(command);
    if p.components().count() > 1 {
        // Looks like a path, not a bare name.
        return if is_spawnable_file(p) {
            Some(p.to_path_buf())
        } else {
            None
        };
    }
    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        let candidate = dir.join(command);
        if is_spawnable_file(&candidate) {
            return Some(candidate);
        }
        #[cfg(windows)]
        {
            if let Some(exts) = std::env::var_os("PATHEXT") {
                for ext in std::env::split_paths(&exts) {
                    let ext = ext.to_string_lossy();
                    let ext = ext.trim_start_matches('.');
                    let with_ext = dir.join(format!("{command}.{ext}"));
                    if is_spawnable_file(&with_ext) {
                        return Some(with_ext);
                    }
                }
            }
        }
    }
    None
}

#[cfg(unix)]
fn is_spawnable_file(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;

    match std::fs::metadata(path) {
        Ok(meta) => meta.is_file() && meta.permissions().mode() & 0o111 != 0,
        Err(_) => false,
    }
}

#[cfg(not(unix))]
fn is_spawnable_file(path: &Path) -> bool {
    path.is_file()
}

/// Whether the harness is authenticated, per the probe-only policy.
async fn is_authenticated(
    cfg: &HarnessConfig,
    cwd: &Path,
    session_overlay: Option<&std::collections::HashMap<String, String>>,
) -> bool {
    if !cfg.auth_probe_args.is_empty() {
        return run_auth_probe(cfg, cwd, session_overlay).await;
    }
    // No auth hint configured: don't block — let a real run surface any
    // failure rather than refusing a harness the user wired up.
    true
}

/// Run `command auth_probe_args` in `cwd`; exit 0 ⇒ authenticated. Bounded
/// by a short timeout. Any spawn/timeout failure is treated as *not*
/// authenticated (fail closed for the probe path).
async fn run_auth_probe(
    cfg: &HarnessConfig,
    cwd: &Path,
    session_overlay: Option<&std::collections::HashMap<String, String>>,
) -> bool {
    let mut cmd = tokio::process::Command::new(&cfg.command);
    cmd.args(&cfg.auth_probe_args)
        .current_dir(cwd)
        .env_clear()
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true);
    for (key, value) in harness_child_env(cfg, session_overlay) {
        cmd.env(key, value);
    }
    let fut = cmd.status();
    match tokio::time::timeout(Duration::from_secs(15), fut).await {
        Ok(Ok(status)) => status.success(),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::extended::{ArgvOverflowBehavior, PromptInputMode};

    #[cfg(unix)]
    fn write_file(path: &Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;

        std::fs::write(path, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    fn base(command: &str) -> HarnessConfig {
        HarnessConfig {
            command: command.to_string(),
            args: vec![],
            prompt_input: PromptInputMode::Stdin,
            argv_overflow: ArgvOverflowBehavior::SpillToTempfile,
            model_args: vec![],
            default_model: None,
            models: vec![],
            model_list_args: vec![],
            supports_json_output: false,
            json_output_args: vec![],
            supports_agent_file: false,
            agent_file_args: vec![],
            agent_file_env: None,
            trust: crate::config::extended::HarnessTrust::Untrusted,
            auth_probe_args: vec![],
            always_allow: false,
            timeout_secs: 60,
        }
    }

    #[tokio::test]
    async fn missing_command_errors_with_name_and_command() {
        let cfg = base("definitely-not-a-real-binary-xyz");
        let err = preflight_with_env("ghost", &cfg, std::env::temp_dir().as_path(), None)
            .await
            .unwrap_err();
        assert!(matches!(err, PreflightError::NotOnPath { .. }));
        let msg = format!("{err}");
        assert!(msg.contains("`ghost`"), "{msg}");
        assert!(msg.contains("definitely-not-a-real-binary-xyz"), "{msg}");
    }

    #[test]
    fn path_wrapper_named_like_preset_is_not_catalog() {
        // `/opt/wrappers/claude` must not inherit the trusted claude catalog
        // recipe solely because its basename matches a preset.
        assert!(!is_unmodified_catalog_preset(
            "claude",
            "/opt/wrappers/claude"
        ));
        assert!(!is_unmodified_catalog_preset("claude", "my-claude-wrapper"));
        assert!(is_unmodified_catalog_preset("claude", "claude"));
        assert!(!is_unmodified_catalog_preset("shell", "sh"));
    }

    #[cfg(unix)]
    #[test]
    fn which_on_path_rejects_non_executable_path_entry() {
        let temp = tempfile::tempdir().unwrap();
        write_file(&temp.path().join("shadowed"), 0o644);
        let guard = crate::test_env::lock();
        guard.set_var("PATH", temp.path());

        assert_eq!(which_on_path("shadowed"), None);
    }

    #[cfg(unix)]
    #[test]
    fn which_on_path_accepts_executable_path_entry() {
        let temp = tempfile::tempdir().unwrap();
        let executable = temp.path().join("runner");
        write_file(&executable, 0o755);
        let guard = crate::test_env::lock();
        guard.set_var("PATH", temp.path());

        assert_eq!(
            which_on_path("runner").as_deref(),
            Some(executable.as_path())
        );
    }

    #[cfg(unix)]
    #[test]
    fn which_on_path_rejects_non_executable_explicit_path() {
        let _guard = crate::test_env::lock();
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("tool");
        write_file(&path, 0o644);

        assert_eq!(which_on_path(path.to_str().unwrap()), None);
    }

    #[tokio::test]
    async fn on_path_no_auth_hint_is_ok() {
        let _env = crate::test_env::lock_async().await;
        // `sh` is on PATH and has no auth hint → authenticated by policy.
        let cfg = base("sh");
        assert!(
            preflight_with_env("shell", &cfg, std::env::temp_dir().as_path(), None)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn auth_probe_exit_zero_authenticates() {
        let mut cfg = base("sh");
        cfg.auth_probe_args = vec!["-c".to_string(), "exit 0".to_string()];
        assert!(
            preflight_with_env("x", &cfg, std::env::temp_dir().as_path(), None)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn auth_probe_uses_curated_env() {
        let env = crate::test_env::lock_async().await;
        let mut cfg = base("sh");
        cfg.auth_probe_args = vec![
            "-c".to_string(),
            "test \"${SECRET_API_KEY-unset}\" = unset && test \"$ALLOWED_NONSECRET\" = visible"
                .to_string(),
        ];
        env.set_var("SECRET_API_KEY", "hidden");
        let mut overlay = std::collections::HashMap::new();
        overlay.insert("ALLOWED_NONSECRET".to_string(), "visible".to_string());

        assert!(
            preflight_with_env("x", &cfg, std::env::temp_dir().as_path(), Some(&overlay))
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn auth_probe_nonzero_is_unauthenticated() {
        let mut cfg = base("sh");
        cfg.auth_probe_args = vec!["-c".to_string(), "exit 1".to_string()];
        let err = preflight_with_env("x", &cfg, std::env::temp_dir().as_path(), None)
            .await
            .unwrap_err();
        assert!(matches!(err, PreflightError::NotAuthenticated { .. }));
    }
}
