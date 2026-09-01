//! Startup splash shown when launching the interactive TUI via bare
//! `cockpit`.
//!
//! Only the raw-stdout splash and the `LaunchInfo` struct that the TUI
//! reads on boot live here. Config-directory discovery lives in
//! `config::dirs`; provider/model detection lives in `config::provider`;
//! the ratatui-side chrome lives in the TUI crate's chrome module.

use std::env;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::banner::render_unconditional;
use crate::git::{self, repo_counts};
pub use cockpit_proto::{LaunchBundle, LaunchInfo};

pub const APP_NAME: &str = "FlyCockpit";
pub const INPUT_PREFIX: &str = "❯ ";
const ONBOARDING_STATE_FILE: &str = "onboarding.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OnboardingStage {
    Welcome,
    Profile,
    Provider,
    Model,
    Complete,
}

impl Default for OnboardingStage {
    fn default() -> Self {
        Self::Welcome
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct OnboardingState {
    stage: OnboardingStage,
    /// A provider save is in flight or has committed but still needs its
    /// live validation. Keeping this alongside the stage lets a restart
    /// resume validation instead of opening a fresh add wizard; an explicit
    /// offline continuation advances the stage and clears this marker.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    provider_pending_validation: Option<String>,
}

fn onboarding_state_path() -> Result<PathBuf> {
    Ok(crate::config::dirs::global_config_dir()
        .context("resolving global config directory for onboarding")?
        .join(ONBOARDING_STATE_FILE))
}

pub fn onboarding_stage() -> OnboardingStage {
    let Ok(path) = onboarding_state_path() else {
        // A directory-resolution failure must never disable onboarding. The
        // caller will retry the normal durable state write before advancing.
        return OnboardingStage::Welcome;
    };
    onboarding_stage_at(&path)
}

fn onboarding_stage_at(path: &Path) -> OnboardingStage {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            // A missing state file is first-run only when the config directory
            // did not already exist. Established installs must never be pushed
            // into onboarding merely because they predate onboarding.json.
            return if path.parent().is_some_and(|parent| parent.exists()) {
                OnboardingStage::Complete
            } else {
                OnboardingStage::Welcome
            };
        }
        Err(_) => {
            // Permission and I/O failures are not evidence that onboarding
            // completed. Resume conservatively, where progress writes will
            // expose the underlying failure to the user.
            return OnboardingStage::Welcome;
        }
    };
    serde_json::from_slice::<OnboardingState>(&bytes)
        .map(|state| state.stage)
        .unwrap_or(OnboardingStage::Welcome)
}

pub fn onboarding_provider_pending_validation() -> Option<String> {
    let path = onboarding_state_path().ok()?;
    let bytes = std::fs::read(path).ok()?;
    serde_json::from_slice::<OnboardingState>(&bytes)
        .ok()?
        .provider_pending_validation
}

pub fn persist_onboarding_provider_pending_validation(provider_id: &str) -> Result<()> {
    let path = onboarding_state_path()?;
    persist_onboarding_state_at(
        &path,
        OnboardingState {
            stage: OnboardingStage::Provider,
            provider_pending_validation: Some(provider_id.to_string()),
        },
    )
}

/// Establish the durable Welcome marker before another startup owner (notably
/// the daemon) creates the config directory. Existing config directories are
/// deliberately left untouched.
pub fn initialize_onboarding_if_first_run() -> Result<bool> {
    let path = onboarding_state_path()?;
    initialize_onboarding_at(&path)
}

fn initialize_onboarding_at(path: &Path) -> Result<bool> {
    let Some(parent) = path.parent() else {
        anyhow::bail!("onboarding state has no parent");
    };
    if parent.exists() {
        return Ok(false);
    }
    persist_onboarding_stage_at(path, OnboardingStage::Welcome)?;
    Ok(true)
}

pub fn persist_onboarding_stage(stage: OnboardingStage) -> Result<()> {
    let path = onboarding_state_path()?;
    persist_onboarding_stage_at(&path, stage)
}

fn persist_onboarding_stage_at(path: &Path, stage: OnboardingStage) -> Result<()> {
    persist_onboarding_state_at(
        path,
        OnboardingState {
            stage,
            provider_pending_validation: None,
        },
    )
}

fn persist_onboarding_state_at(path: &Path, state: OnboardingState) -> Result<()> {
    let parent = path.parent().context("onboarding state has no parent")?;
    std::fs::create_dir_all(parent).context("creating onboarding state directory")?;
    let bytes = serde_json::to_vec_pretty(&state).context("serializing onboarding state")?;
    let _guard = crate::config::hold_config_mutation_lock(&path)?;
    crate::config::write_config_bytes_atomic(&path, &bytes)
        .context("publishing onboarding state")?;
    Ok(())
}

const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const GREY: &str = "\x1b[38;5;250m";
const BRANCH_BADGE: &str = "\x1b[30;48;5;220m";
/// Right half-block (▐) in yellow-220 foreground on terminal default.
/// Painted as the left edge of the branch pill so the badge fades from
/// the surrounding terminal background instead of slamming into it.
const BADGE_LEFT_EDGE: &str = "\x1b[38;5;220m▐\x1b[0m";
/// Left half-block (▌) in yellow-220 foreground — right edge of the
/// pill, same fade behavior as `BADGE_LEFT_EDGE`.
const BADGE_RIGHT_EDGE: &str = "\x1b[38;5;220m▌\x1b[0m";

/// Build the launch splash/chrome info for `project`.
///
/// `fetch_git` controls whether `git status` runs synchronously here:
/// the headless `print`/`header_lines` splash passes `true` (it has no
/// event loop to fill the branch pill in later), while the TUI
/// `App::new` path passes `false` and lets the async `spawn_git_refresh`
/// poller populate `repo_status` a few ms after the first frame — so a
/// giant-repo `git status` never blocks the first paint.
pub fn load(project: Option<&Path>, fetch_git: bool) -> LaunchInfo {
    load_bundle(project, fetch_git).launch
}

pub fn load_bundle(project: Option<&Path>, fetch_git: bool) -> LaunchBundle {
    let cwd = resolve_launch_dir(project);
    let providers = crate::secret_ref::load_effective(&cwd);
    let extended = crate::config::extended::load_for_cwd(&cwd);
    let launch = build_launch_info(cwd, fetch_git, &providers, &extended);
    LaunchBundle {
        launch,
        providers,
        extended,
    }
}

/// The TUI's pre-attach bootstrap bundle (`tui-config-single-source`).
///
/// Identical to [`load_bundle`] except provider config is loaded WITHOUT
/// resolving credentials (no credential-store access, no `$secret:` migration),
/// so it performs exactly one config resolution — the `ExtendedConfig` read —
/// and never counts as a credential resolution. Provider/credential resolution
/// is the daemon's job; the daemon pushes the resolved snapshot on attach. The
/// returned `providers` carry config values (models, trust, favorites) for the
/// launch header but no resolved credential material.
pub fn load_bundle_bootstrap(project: Option<&Path>, fetch_git: bool) -> LaunchBundle {
    let cwd = resolve_launch_dir(project);
    let paths = crate::config::dirs::config_file_paths_for_load(&cwd);
    // Pre-attach bootstrap is still a config *resolution*, so it must observe
    // the same effective-default barrier: a layer with a pending session or
    // correlated transaction is masked to its recorded prior bytes rather than
    // showing whichever half is already on disk.
    let providers = crate::config::providers::ConfigDoc::providers_from_paths_masked(&paths);
    let extended = crate::config::extended::load_for_cwd(&cwd);
    let launch = build_launch_info(cwd, fetch_git, &providers, &extended);
    LaunchBundle {
        launch,
        providers,
        extended,
    }
}

/// Bootstrap projection for the TUI. Provider credential-bearing fields are
/// removed before the bundle crosses into the presentation crate; detached
/// mode still gets model/catalog metadata from the local config.
pub fn load_bundle_bootstrap_redacted(project: Option<&Path>, fetch_git: bool) -> LaunchBundle {
    let mut bundle = load_bundle_bootstrap(project, fetch_git);
    for provider in bundle.providers.providers.values_mut() {
        provider.credential_ref = None;
        for header in &mut provider.headers {
            if !header.value.trim().is_empty() {
                header.value = "********".to_string();
            }
        }
    }
    bundle
}

fn build_launch_info(
    cwd: PathBuf,
    fetch_git: bool,
    providers: &crate::config::providers::ProvidersConfig,
    extended: &crate::config::extended::ExtendedConfig,
) -> LaunchInfo {
    let active_model = detect_provider_model_from_loaded(providers);
    let provider_line = active_model
        .clone()
        .map(|(provider, model)| format!("{provider} / {model}"))
        .unwrap_or_else(|| "No providers configured - run /settings to edit".to_string());

    let active_model_is_favorite = active_model
        .as_ref()
        .map(|(p, m)| is_favorite_model(providers, p, m))
        .unwrap_or(false);
    let active_model_is_trusted = active_model
        .as_ref()
        .map(|(p, m)| providers.resolve_trust(p, m).is_trusted())
        .unwrap_or(false);
    let active_model_max_context = active_model
        .as_ref()
        .and_then(|(p, m)| lookup_model_context(providers, p, m));
    let active_model_supports_images = active_model
        .as_ref()
        .map(|(p, m)| model_supports_images(providers, p, m))
        .unwrap_or(false);
    let repo_status = if fetch_git {
        git::repo_status(&cwd).ok().flatten()
    } else {
        None
    };
    let user_name = extended
        .name
        .as_deref()
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(ToString::to_string);
    let banner_enabled = extended.tui.banner.enabled;
    let agent_name = extended.default_primary_agent.agent_name().to_string();

    LaunchInfo {
        version: env!("CARGO_PKG_VERSION").to_string(),
        session_id: None,
        session_short_id: None,
        provider_line,
        active_model,
        active_model_diverged: false,
        active_model_is_favorite,
        active_model_is_trusted,
        active_model_max_context,
        active_model_supports_images,
        cwd_display: display_path(&cwd),
        cwd,
        repo_status,
        agent_name,
        user_name,
        banner_enabled,
    }
}

fn detect_provider_model_from_loaded(
    cfg: &crate::config::providers::ProvidersConfig,
) -> Option<(String, String)> {
    let provider = env::var("COCKPIT_PROVIDER")
        .ok()
        .filter(|s| !s.trim().is_empty());
    let model = env::var("COCKPIT_MODEL")
        .ok()
        .filter(|s| !s.trim().is_empty());

    match (provider, model) {
        (Some(provider), Some(model)) => return Some((provider, model)),
        (None, Some(model)) => return crate::config::provider::split_provider_model(&model),
        _ => {}
    }

    if let Some(active) = &cfg.active_model {
        return Some((active.provider.clone(), active.model.clone()));
    }
    for (provider, entry) in &cfg.providers {
        if let Some(model) = entry.models.first() {
            return Some((provider.clone(), model.id.clone()));
        }
    }
    None
}

fn is_favorite_model(
    cfg: &crate::config::providers::ProvidersConfig,
    provider_id: &str,
    model_id: &str,
) -> bool {
    cfg.providers
        .get(provider_id)
        .and_then(|entry| entry.models.iter().find(|m| m.id == model_id))
        .map(|model| model.favorite)
        .unwrap_or(false)
}

fn lookup_model_context(
    cfg: &crate::config::providers::ProvidersConfig,
    provider_id: &str,
    model_id: &str,
) -> Option<u32> {
    cfg.resolve_effective_model_capabilities(provider_id, model_id, cfg.resolution_generation)
        .context_tokens
}

fn model_supports_images(
    cfg: &crate::config::providers::ProvidersConfig,
    provider_id: &str,
    model_id: &str,
) -> bool {
    cfg.resolve_effective_model_capabilities(provider_id, model_id, cfg.resolution_generation)
        .supports_image_input()
}

pub fn print(project: Option<&Path>, sandbox_enabled: bool) {
    // Headless splash: no event loop to fill the branch pill in later, so
    // fetch git status synchronously here.
    let info = load(project, true);
    // Headless output is immediate. It may project an already-complete shared
    // snapshot, but never waits for dependency probes before its first byte.
    // Emit and flush the first usable output before starting the bounded
    // dependency construction. Piped/headless startup must never hold its
    // first byte behind host probes.
    for line in header_lines(&info) {
        println!("{line}");
    }
    let _ = std::io::Write::flush(&mut std::io::stdout());
    print_dependency_warning(&info.cwd, sandbox_enabled);
    println!();
    println!("{INPUT_PREFIX}");
    println!("{}", info.agent_name);
}

/// Complete the bounded startup projection after the caller has emitted and
/// flushed its first bytes.
pub fn print_dependency_warning(cwd: &Path, sandbox_enabled: bool) {
    if let Ok(projection) =
        crate::diagnostics::dependency_projection_with_deadline_and_publish_for_run(
            cwd.to_path_buf(),
            std::time::Duration::from_secs(2),
            sandbox_enabled,
        )
        && let Some(summary) =
            crate::external_runtime::startup_dependency_policy(&projection).summary
    {
        println!("dependency warning: {summary}");
    }
}

/// The 6-line launch header as ANSI-styled strings (logo + title,
/// logo + provider, logo + path, logo + branch, two art-only rows).
/// Shared by `print_header` (startup, raw `println!`) and the TUI's
/// `/new` path (mid-session, piped through `insert_above_viewport`).
///
/// Spacing: the P51 art is 18 columns wide with a 2-space left indent
/// baked in (20 cols total); the 3-space separator lines content up at
/// column 23, matching the TUI's 11-wide icon column + 2-space text
/// indent.
pub fn header_lines(info: &LaunchInfo) -> Vec<String> {
    let art = render_unconditional();
    let title = format!("{BOLD}{APP_NAME}{RESET} {GREY}v{}{RESET}", info.version);
    match info.user_name.as_deref() {
        Some(name) if !name.is_empty() => {
            // Shift content down by one row so the welcome line slots
            // between the title and provider line. The two art-only rows
            // at the bottom are the new art's natural padding.
            vec![
                art[0].clone(), // art only, no text
                format!("{}   {}", art[1], title),
                format!("{}   {GREY}Welcome, {BOLD}{name}{RESET}", art[2]),
                format!("{}   {GREY}{}{RESET}", art[3], info.provider_line),
                format!("{}   {}", art[4], path_line_ansi(info)),
                art[5].clone(),
            ]
        }
        _ => vec![
            art[0].clone(), // art only, no text
            format!("{}   {}", art[1], title),
            format!("{}   {GREY}{}{RESET}", art[2], info.provider_line),
            format!("{}   {}", art[3], path_line_ansi(info)),
            art[4].clone(),
            art[5].clone(),
        ],
    }
}

/// Print just the launch header. Used by the TUI at startup so the
/// header lands in normal terminal output — it scrolls naturally with
/// the chat and ends up in scrollback once enough messages arrive.
pub fn print_header(info: &LaunchInfo) {
    print_header_with_projection(info, None);
}

fn print_header_with_projection(
    info: &LaunchInfo,
    fresh: Option<&crate::external_runtime::DependencyProjection>,
) {
    for line in header_lines(info) {
        println!("{line}");
    }
    let policy = fresh
        .map(crate::external_runtime::startup_dependency_policy)
        .or_else(crate::external_runtime::current_startup_dependency_policy);
    if let Some(policy) = policy
        && let Some(summary) = policy.summary
    {
        println!("dependency warning: {summary}");
    }
}

fn resolve_launch_dir(project: Option<&Path>) -> PathBuf {
    let base = env::current_dir().unwrap_or_else(|_| PathBuf::from("."));

    match project {
        Some(path) if path.is_absolute() => path.to_path_buf(),
        Some(path) => base.join(path),
        None => base,
    }
}

pub fn display_path(path: &Path) -> String {
    if let Some(home) = dirs::home_dir()
        && let Ok(relative) = path.strip_prefix(&home)
    {
        if relative.as_os_str().is_empty() {
            return "~".to_string();
        }
        return format!("~/{}", relative.display());
    }
    path.display().to_string()
}

fn path_line_ansi(info: &LaunchInfo) -> String {
    let mut line = format!("{GREY}{}{RESET}", info.cwd_display);
    if let Some(repo) = &info.repo_status {
        line.push(' ');
        line.push_str(BADGE_LEFT_EDGE);
        line.push_str(BRANCH_BADGE);
        line.push(' ');
        line.push_str(&repo.branch);
        let counts = repo_counts(repo);
        if !counts.is_empty() {
            line.push(' ');
            line.push_str(&counts);
        }
        line.push(' ');
        line.push_str(RESET);
        line.push_str(BADGE_RIGHT_EDGE);
    }
    line
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::providers::{
        CapabilityStatus, ModelCapabilities, ModelEntry, ProviderEntry, ProvidersConfig,
    };

    #[test]
    fn missing_state_on_existing_install_is_complete() {
        let root = tempfile::tempdir().unwrap();
        assert_eq!(
            onboarding_stage_at(&root.path().join(ONBOARDING_STATE_FILE)),
            OnboardingStage::Complete
        );
    }

    #[test]
    fn only_absent_config_directory_initializes_onboarding() {
        let root = tempfile::tempdir().unwrap();
        let config = root.path().join("new-config");
        let state = config.join(ONBOARDING_STATE_FILE);
        assert!(initialize_onboarding_at(&state).unwrap());
        assert_eq!(onboarding_stage_at(&state), OnboardingStage::Welcome);
        std::fs::remove_file(&state).unwrap();
        assert!(!initialize_onboarding_at(&state).unwrap());
        assert_eq!(onboarding_stage_at(&state), OnboardingStage::Complete);
    }

    #[test]
    fn unreadable_state_path_resumes_onboarding() {
        let root = tempfile::tempdir().unwrap();
        let state = root.path().join(ONBOARDING_STATE_FILE);
        std::fs::create_dir(&state).unwrap();

        assert_eq!(onboarding_stage_at(&state), OnboardingStage::Welcome);
    }

    #[test]
    fn provider_validation_continuation_is_durable() {
        let root = tempfile::tempdir().unwrap();
        let state = root.path().join("new-config").join(ONBOARDING_STATE_FILE);

        persist_onboarding_state_at(
            &state,
            OnboardingState {
                stage: OnboardingStage::Provider,
                provider_pending_validation: Some("openai".into()),
            },
        )
        .unwrap();
        let decoded: OnboardingState =
            serde_json::from_slice(&std::fs::read(&state).unwrap()).unwrap();

        assert_eq!(decoded.stage, OnboardingStage::Provider);
        assert_eq!(
            decoded.provider_pending_validation.as_deref(),
            Some("openai")
        );
    }

    #[test]
    fn image_support_uses_resolved_model_capabilities() {
        let mut cfg = ProvidersConfig::default();
        cfg.providers.insert(
            "p".into(),
            ProviderEntry {
                models: vec![ModelEntry {
                    id: "m".into(),
                    capabilities: ModelCapabilities {
                        image_input: CapabilityStatus::Supported,
                        tool_calling: CapabilityStatus::Unsupported,
                        ..ModelCapabilities::default()
                    },
                    ..ModelEntry::default()
                }],
                ..ProviderEntry::default()
            },
        );

        assert!(model_supports_images(&cfg, "p", "m"));
    }
}
