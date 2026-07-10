//! Startup splash shown when launching the interactive TUI via bare
//! `cockpit`.
//!
//! Only the raw-stdout splash and the `LaunchInfo` struct that the TUI
//! reads on boot live here. Config-directory discovery lives in
//! `config::dirs`; provider/model detection lives in `config::provider`;
//! the ratatui-side chrome lives in `tui::chrome`.

use std::env;
use std::path::{Path, PathBuf};

use crate::banner::render_unconditional;
use crate::git::{self, RepoStatus};
use crate::tui::chrome::repo_counts;
use crate::tui::composer::INPUT_PREFIX;

pub const APP_NAME: &str = "Cockpit CLI";

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

#[derive(Debug, Clone)]
pub struct LaunchBundle {
    pub launch: LaunchInfo,
    pub providers: crate::config::providers::ProvidersConfig,
    pub extended: crate::config::extended::ExtendedConfig,
}

#[derive(Debug, Clone)]
pub struct LaunchInfo {
    pub version: &'static str,
    /// Current session id, used for internal routing (e.g. `/copy-id`). Not
    /// shown in the banner — the user-facing short id is displayed instead
    /// (see `session_short_id`). `None` at `load` time; the daemon assigns it
    /// when the TUI attaches, after which the TUI sets it.
    pub session_id: Option<uuid::Uuid>,
    /// Current session's 6-char Crockford base32 short id, shown in the TUI
    /// startup graphic right after the version (session-id-short-display).
    /// `None` at `load` time — the daemon assigns it when the TUI attaches,
    /// after which the TUI sets it and re-renders the banner. TUI-only: the
    /// headless `print` / `header_lines` splash never shows it.
    pub session_short_id: Option<String>,
    pub provider_line: String,
    /// Currently selected (provider_id, model_id). None when nothing
    /// has been picked yet.
    pub active_model: Option<(String, String)>,
    /// True when the active model has `favorite: true` in config.
    pub active_model_is_favorite: bool,
    /// True when the active provider/model resolves to `trust: "trusted"`.
    pub active_model_is_trusted: bool,
    /// Max context window of the active model, in tokens, when the
    /// config carries it. Drives the `(max Nk)` part of the chrome's
    /// context indicator.
    pub active_model_max_context: Option<u32>,
    /// True when the active model declares `inputs.images: true` in
    /// config (vision-capable). Drives the composer image-paste send-time
    /// decision: bytes vs. text note. Recomputed on every
    /// `reload_launch_info` so a `/model` switch round-trips images
    /// without a re-paste (composer-paste-handling).
    pub active_model_supports_images: bool,
    pub cwd: PathBuf,
    pub cwd_display: String,
    pub repo_status: Option<RepoStatus>,
    pub agent_name: String,
    /// User's configured display name from `config.json`.
    /// When `Some`, the splash renders `Welcome, {name}` between the
    /// title and provider lines.
    pub user_name: Option<String>,
    /// Whether the pixel-banner splash (GOALS §1g) is enabled. Read
    /// from `tui.banner.enabled` in `config.json`. Even when
    /// `true`, the banner suppresses itself on `NO_COLOR`, non-TTY
    /// stdout, or narrow terminals. A truthy `COCKPIT_ROOSTER`
    /// (`true`/`1`/`yes`, case-insensitive) does not suppress — it
    /// renders the rooster art instead of the P-51.
    pub banner_enabled: bool,
}

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
    let providers = crate::config::providers::ConfigDoc::load_effective(&cwd);
    let extended = crate::config::extended::load_for_cwd(&cwd);
    let launch = build_launch_info(cwd, fetch_git, &providers, &extended);
    LaunchBundle {
        launch,
        providers,
        extended,
    }
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
    let agent_name = crate::agents::resolve_primary_for_flag(
        extended.default_primary_agent.agent_name(),
        extended.experimental_mode,
    );

    LaunchInfo {
        version: env!("CARGO_PKG_VERSION"),
        session_id: None,
        session_short_id: None,
        provider_line,
        active_model,
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
    cfg.providers
        .get(provider_id)
        .and_then(|entry| entry.models.iter().find(|m| m.id == model_id))
        .and_then(|model| model.context_length)
}

fn model_supports_images(
    cfg: &crate::config::providers::ProvidersConfig,
    provider_id: &str,
    model_id: &str,
) -> bool {
    cfg.providers
        .get(provider_id)
        .and_then(|entry| entry.models.iter().find(|m| m.id == model_id))
        .and_then(|model| model.inputs.as_ref())
        .and_then(|inputs| inputs.images)
        .unwrap_or(false)
}

pub fn print(project: Option<&Path>) {
    // Headless splash: no event loop to fill the branch pill in later, so
    // fetch git status synchronously here.
    let info = load(project, true);
    print_header(&info);
    println!();
    println!("{INPUT_PREFIX}");
    println!("{}", info.agent_name);
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
    for line in header_lines(info) {
        println!("{line}");
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
