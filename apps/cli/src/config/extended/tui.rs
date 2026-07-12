use super::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TuiConfig {
    #[serde(default, deserialize_with = "deserialize_vim_mode_setting")]
    pub vim_mode: VimModeSetting,
    #[serde(default)]
    pub thinking: ThinkingDisplay,
    /// Render assistant output through the markdown emitter. Default
    /// on — chat models routinely emit fenced code, bullets, bold.
    #[serde(default = "default_true")]
    pub render_agent_markdown: bool,
    /// Render the user's own message bubble through the markdown
    /// emitter. Default off — most user prompts are plain prose; turning
    /// this on is opt-in for users who paste markdown into the composer.
    #[serde(default)]
    pub render_user_markdown: bool,
    pub show_cwd: bool,
    pub show_branch: bool,
    /// Pixel banner on TUI startup (GOALS §1g). Default on; suppressed
    /// when stdout is not a TTY, `NO_COLOR` is set, or the window is
    /// narrower than the art. A truthy `COCKPIT_ROOSTER`
    /// (`true`/`1`/`yes`, case-insensitive) renders the rooster art
    /// instead of the P-51.
    #[serde(default)]
    pub banner: BannerConfig,
    /// How `edit` / `editunlock` (and, later, `write` /
    /// `writeunlock`) tool calls render their changes in the history
    /// pane. SideBySide degrades to Inline when the terminal is
    /// narrower than 80 columns.
    #[serde(default)]
    pub diff_style: DiffStyle,
    /// Capture mouse events. With capture on we get click-to-position
    /// in the composer, drag-select in chat history, and clickable
    /// chips. Native terminal selection requires holding the
    /// terminal's bypass modifier (Shift / Option / Fn) while
    /// capture is on; we provide in-app drag-select + Ctrl+Shift+C
    /// for the common path.
    #[serde(default = "default_true")]
    pub mouse_capture: bool,
    /// Emit OSC 8 terminal hyperlinks for registered TUI links. Terminals
    /// without OSC 8 support ignore them; disable for misbehaving terminals.
    #[serde(default = "default_true")]
    pub hyperlinks: bool,
    /// Allow `Ctrl+Shift+Y` to copy the focused agent message as
    /// rich text (HTML to the system clipboard via the local OS
    /// clipboard layer; falls back to plain text over SSH).
    #[serde(default = "default_true")]
    pub rich_text_copy: bool,
    /// Lines of conversation tail to dump back into terminal
    /// scrollback at TUI exit (GOALS §1d). Default 100. `0` disables
    /// the dump entirely; `-1` dumps the whole session.
    #[serde(default = "default_exit_tail_lines")]
    pub exit_tail_lines: i32,
    /// Use emoji glyphs in the chat (tool-call boxes, the rooster
    /// splash, …). Default off — many terminals can't render emoji and
    /// show tofu boxes instead, so cockpit ships text-only and lets the
    /// user opt in.
    #[serde(default)]
    pub use_emojis: bool,
    /// `/caffeinate` display scope. When `true`, an active caffeination
    /// also keeps the display awake; default `false` keeps only the
    /// machine awake (and prevents lid-close suspend) while letting the
    /// display turn off — saves screen wear/power on overnight runs.
    /// System-idle + lid-close prevention are always on while caffeinated
    /// regardless of this; the setting only governs the display.
    #[serde(default)]
    pub caffeinate_display_awake: bool,
    /// Attention notifications for events that want the user back in the TUI
    /// (implementation note): in-TUI toast (default on),
    /// optional terminal bell, optional desktop notification.
    #[serde(default)]
    pub attention: crate::tui::attention::AttentionConfig,
}

/// Sleep scope `/caffeinate` keeps awake — derived from the
/// `caffeinate_display_awake` UI setting. System-idle + lid-close are
/// always suppressed while caffeinated; this only governs the display.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SleepScope {
    /// Keep the machine awake + prevent lid-close suspend; let the display
    /// turn off (default).
    SystemOnly,
    /// Also keep the display on.
    SystemAndDisplay,
}

impl TuiConfig {
    /// The `/caffeinate` sleep scope implied by the display-awake setting.
    pub fn sleep_scope(&self) -> SleepScope {
        if self.caffeinate_display_awake {
            SleepScope::SystemAndDisplay
        } else {
            SleepScope::SystemOnly
        }
    }
}

default_const!(default_exit_tail_lines, i32, 100);

/// Diff rendering mode for edit/write tool calls.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum DiffStyle {
    /// Two columns: old text on the left, new on the right, separated
    /// by a vertical rule. Falls back to [`Self::Inline`] dynamically
    /// when the terminal is narrower than 80 columns.
    #[default]
    SideBySide,
    /// Unified diff: `-` red for removed lines, `+` green for added,
    /// ` ` for context.
    Inline,
    /// Show only a one-line summary (`edited {path} (+N -M)`).
    Hidden,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BannerConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
}

impl Default for BannerConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

/// How reasoning/thinking is surfaced in the chat pane.
///
/// `Condensed` (default) — show a clickable "thought for Xs" chip that
/// expands to the full reasoning on click.
/// `Hidden` — show only the live "Thinking…" placeholder; once the turn
/// finalizes, the chip and reasoning are not rendered at all.
/// `Verbose` — always render the full reasoning text inline (as if every
/// entry were pre-expanded).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum ThinkingDisplay {
    #[default]
    Condensed,
    Hidden,
    Verbose,
}

/// One user-defined bash-command tool. Placeholder substitution uses
/// `{name}` markers (matched against the tool's declared arg list at
/// dispatch time). Stored under `tools.<tool-name>` in `config.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCommandTemplate {
    /// Enable/disable this tool without deleting its config.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Bash command template with `{placeholder}` substitution.
    /// E.g. `curl -sSL --max-time 15 {url}` for `webfetch`.
    pub command: String,
    /// One-sentence description shown to the model. Kept terse to
    /// respect the token-economy rule (project guidance).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum WebProvider {
    #[default]
    Firecrawl,
    Tinyfish,
    Custom,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct WebConfig {
    #[serde(default)]
    pub provider: WebProvider,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub firecrawl_base_url: Option<String>,
}

impl WebConfig {
    pub fn is_default(&self) -> bool {
        self == &Self::default()
    }
}

/// Tri-state vim mode: `hint` (default; vim enabled, hint shown on
/// entry to Normal), `enabled` (vim on, no hint), `disabled` (vim off).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum VimModeSetting {
    #[default]
    Hint,
    Enabled,
    Disabled,
}

impl VimModeSetting {
    pub fn vim_enabled(self) -> bool {
        !matches!(self, Self::Disabled)
    }

    pub fn show_hint(self) -> bool {
        matches!(self, Self::Hint)
    }
}

/// Accept the legacy `vim_mode: bool` schema as well as the new
/// string enum. `true` maps to `Hint` (the default), `false` to
/// `Disabled`. Lets us roll the schema forward without breaking
/// existing configs on disk.
fn deserialize_vim_mode_setting<'de, D>(d: D) -> Result<VimModeSetting, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error;
    let v = serde_json::Value::deserialize(d)?;
    match v {
        serde_json::Value::Bool(true) => Ok(VimModeSetting::Hint),
        serde_json::Value::Bool(false) => Ok(VimModeSetting::Disabled),
        serde_json::Value::String(s) => match s.as_str() {
            "hint" => Ok(VimModeSetting::Hint),
            "enabled" => Ok(VimModeSetting::Enabled),
            "disabled" => Ok(VimModeSetting::Disabled),
            other => Err(D::Error::custom(format!(
                "unknown vim_mode `{other}` (expected hint|enabled|disabled)"
            ))),
        },
        serde_json::Value::Null => Ok(VimModeSetting::default()),
        _ => Err(D::Error::custom("vim_mode must be a string or bool")),
    }
}

impl Default for TuiConfig {
    fn default() -> Self {
        Self {
            vim_mode: VimModeSetting::default(),
            thinking: ThinkingDisplay::default(),
            render_agent_markdown: true,
            render_user_markdown: false,
            show_cwd: true,
            show_branch: true,
            banner: BannerConfig::default(),
            diff_style: DiffStyle::default(),
            mouse_capture: true,
            hyperlinks: true,
            rich_text_copy: true,
            exit_tail_lines: default_exit_tail_lines(),
            use_emojis: false,
            caffeinate_display_awake: false,
            attention: crate::tui::attention::AttentionConfig::default(),
        }
    }
}
