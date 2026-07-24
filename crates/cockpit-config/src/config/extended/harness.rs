use super::*;

/// Resolve the effective `harnesses` map for `cwd` by **deep-merging**
/// every layer's `harnesses` block in walk order (home → machine-local →
/// project, so the more-specific layer wins), per the GOALS §4 merge-mode
/// table (`harnesses` is `deep-merge`). A project layer that sets only
/// `harnesses.claude.default_model` overrides that one field without
/// nuking the inherited `command`/`args`/etc. — the recursion happens at
/// the raw-JSON level so unset fields don't stomp lower layers with their
/// type-level defaults. The final merged object is parsed into typed
/// [`HarnessConfig`] values; any harness entry that fails to parse (e.g. a
/// hand-edit missing the required `command`) is dropped with a trace,
/// never crashing the resolve.
pub fn resolve_harnesses(cwd: &Path) -> HashMap<String, HarnessConfig> {
    let paths = config_file_paths_for_load(cwd);
    resolve_harnesses_from_paths(&paths)
}

/// Layering core for [`resolve_harnesses`], split out so the deep-merge
/// semantics are unit-testable without touching `$HOME`. `paths` is in
/// walk order (least- to most-specific).
pub(super) fn resolve_harnesses_from_paths(paths: &[PathBuf]) -> HashMap<String, HarnessConfig> {
    // Accumulate the merged raw `harnesses` object across layers, then
    // parse once at the end.
    let mut merged: Map<String, Value> = Map::new();
    for path in paths {
        if !path.exists() {
            continue;
        }
        let Ok(doc) = ExtendedConfigDoc::load(path) else {
            continue;
        };
        let Some(block) = doc.raw.get("harnesses").and_then(Value::as_object) else {
            continue;
        };
        for (name, layer_val) in block {
            match merged.get_mut(name) {
                // Same harness named in a lower layer: deep-merge this
                // layer's object into it so per-field overrides land
                // without dropping inherited fields.
                Some(existing) => deep_merge_value(existing, layer_val),
                None => {
                    merged.insert(name.clone(), layer_val.clone());
                }
            }
        }
    }
    let mut out = HashMap::new();
    for (name, val) in merged {
        match serde_json::from_value::<HarnessConfig>(val) {
            Ok(hc) => {
                out.insert(name, hc);
            }
            Err(e) => {
                tracing::debug!(harness = %name, error = %e, "skipping unparseable harness entry");
            }
        }
    }
    out
}

/// Recursively deep-merge `overlay` into `base`: for two objects, recurse
/// per key (overlay keys win, base keys absent from overlay survive); for
/// `providers.<id>.models` arrays, merge entries by model `id`; for anything
/// else, `overlay` replaces `base` outright. The map-shaped `deep-merge` mode
/// from GOALS §2b, applied to raw config values before typed parsing.
/// System-prompt assembly knobs (GOALS §17g).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemPromptConfig {
    /// Minimum gap (in minutes) between `[time: ...]` preludes on
    /// user messages. The first user message always carries a
    /// prelude; subsequent messages get one only when this many
    /// minutes have elapsed since the last. The system prompt
    /// itself never carries the time.
    #[serde(default = "default_time_injection_interval")]
    pub time_injection_interval_minutes: u32,
}

impl Default for SystemPromptConfig {
    fn default() -> Self {
        Self {
            time_injection_interval_minutes: default_time_injection_interval(),
        }
    }
}

default_const!(default_time_injection_interval, u32, 5);

/// One external coding harness registered for delegation (GOALS §6,
/// implementation note). cockpit-native; modeled on the
/// proven ralph-rs `HarnessConfig` shape but owning its own field set and
/// JSON layout. Stored under `harnesses.<name>` in `config.json`
/// and editable in `/settings`. Every field carries a `#[serde(default)]`
/// so a partially-specified user/preset entry parses (defensive against
/// hand-edited config); only `command` is required.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarnessConfig {
    /// The executable name (resolved on `PATH`).
    pub command: String,
    /// Non-interactive argv template. Supports `{prompt}`, `{model}`, and
    /// `{agent_file}` placeholders; a missing `{prompt}` means the prompt
    /// is appended as the trailing positional (or piped via stdin in
    /// `stdin` mode).
    #[serde(default)]
    pub args: Vec<String>,
    /// How the prompt reaches the child (`stdin`/`argv`/`tempfile`).
    /// Default `stdin` so large prompts never trip the argv size cap.
    #[serde(default)]
    pub prompt_input: PromptInputMode,
    /// What to do when `prompt_input = argv` but the prompt exceeds the
    /// kernel argv ceiling. Unused for `stdin`/`tempfile` modes.
    #[serde(default)]
    pub argv_overflow: ArgvOverflowBehavior,
    /// Template for the model flag, e.g. `["--model", "{model}"]`. Empty
    /// means the harness is invoked without any model flag.
    #[serde(default)]
    pub model_args: Vec<String>,
    /// The model used when an invocation supplies no explicit `model`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_model: Option<String>,
    /// Static list of selectable models, shown by the list tool and
    /// editable in `/settings`. A successful `refresh` probe (when
    /// `model_list_args` is set) caches the live list back here.
    #[serde(default)]
    pub models: Vec<String>,
    /// Template that, when set, lists the harness's live models on stdout
    /// (one per line), e.g. `["models"]` for opencode. Empty disables the
    /// probe (the list tool falls back to the static `models` silently).
    #[serde(default)]
    pub model_list_args: Vec<String>,
    /// Whether the harness can emit machine-readable JSON metadata.
    #[serde(default)]
    pub supports_json_output: bool,
    /// Flags appended to request JSON output (e.g. `["--output-format",
    /// "json"]`). Applied only when `supports_json_output`.
    #[serde(default)]
    pub json_output_args: Vec<String>,
    /// Whether the harness accepts a system-prompt / agent file via a
    /// `{agent_file}` flag template ([`Self::agent_file_args`]).
    #[serde(default)]
    pub supports_agent_file: bool,
    /// Flag template carrying the agent-file path, e.g.
    /// `["--append-system-prompt-file", "{agent_file}"]`. Applied only
    /// when `supports_agent_file` and an agent file is supplied.
    #[serde(default)]
    pub agent_file_args: Vec<String>,
    /// Env var that, when set, conveys the agent-file path to a harness
    /// with no native flag (e.g. goose's `GOOSE_SYSTEM_PROMPT_FILE_PATH`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_file_env: Option<String>,
    /// Env vars whose presence proves the harness is authenticated. The
    /// preflight check treats any one being set as authed before falling
    /// back to [`Self::auth_probe_args`].
    #[serde(default)]
    pub auth_env_vars: Vec<String>,
    /// A non-mutating command (relative to [`Self::command`]) whose exit 0
    /// means the harness is authenticated. Run only when no
    /// `auth_env_vars` are set. Empty skips the probe (assume authed).
    #[serde(default)]
    pub auth_probe_args: Vec<String>,
    /// Skip the per-session harness-invocation approval for this harness.
    /// Editable in `/settings -> Harnesses`; stored as `always_allow` under
    /// `harnesses.<name>` in `config.json`. Defaults to `false`.
    #[serde(default)]
    pub always_allow: bool,
    /// Per-harness wall-clock timeout (seconds) for a non-interactive
    /// invocation. The invoke tool kills the child (process group on
    /// Unix) when this elapses. Default [`DEFAULT_HARNESS_TIMEOUT_SECS`].
    #[serde(default = "default_harness_timeout_secs")]
    pub timeout_secs: u64,
}

/// Default per-harness invocation timeout: 30 minutes. Headless coding
/// runs can be long; the cap exists to bound a wedged child, not to clip
/// legitimate work.
pub const DEFAULT_HARNESS_TIMEOUT_SECS: u64 = 30 * 60;

default_const!(
    default_harness_timeout_secs,
    u64,
    DEFAULT_HARNESS_TIMEOUT_SECS
);

/// How the prompt reaches the external harness's process. Default
/// [`Self::Stdin`] so a large prompt never trips the kernel argv ceiling
/// (`MAX_ARG_STRLEN`, ~128 KB on Linux).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum PromptInputMode {
    /// Pipe the prompt to the child's stdin; the `{prompt}` placeholder is
    /// stripped from argv (the default — argv-cap-proof).
    #[default]
    Stdin,
    /// Substitute the raw prompt text into the `{prompt}` argv slot (or
    /// append it). Past the argv-size threshold, [`ArgvOverflowBehavior`]
    /// decides what happens.
    Argv,
    /// Write the prompt to a temp file and substitute that path into the
    /// `{prompt}` slot. For harnesses with a `--prompt-file`-style flag.
    Tempfile,
}

impl PromptInputMode {
    /// The lowercase config/serde spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            PromptInputMode::Stdin => "stdin",
            PromptInputMode::Argv => "argv",
            PromptInputMode::Tempfile => "tempfile",
        }
    }

    /// Cycle to the next choice — the `/settings` row's toggle action
    /// (`stdin → argv → tempfile → stdin`).
    pub fn cycled(self) -> Self {
        match self {
            PromptInputMode::Stdin => PromptInputMode::Argv,
            PromptInputMode::Argv => PromptInputMode::Tempfile,
            PromptInputMode::Tempfile => PromptInputMode::Stdin,
        }
    }
}

/// What to do when [`PromptInputMode::Argv`] is selected but the prompt
/// exceeds the argv-size safety threshold (mirrors ralph-rs). Unused for
/// the other two modes.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum ArgvOverflowBehavior {
    /// Spill the prompt to a temp file and pass its path (the default —
    /// works for harnesses that accept a file path in the prompt slot).
    #[default]
    SpillToTempfile,
    /// Spill the prompt to the child's stdin (strip the `{prompt}` slot).
    SpillToStdin,
    /// Refuse with a clear error rather than risk a broken invocation —
    /// for harnesses (e.g. copilot) that accept the prompt ONLY as inline
    /// argv text.
    Error,
}

impl ArgvOverflowBehavior {
    /// The snake_case config/serde spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            ArgvOverflowBehavior::SpillToTempfile => "spill_to_tempfile",
            ArgvOverflowBehavior::SpillToStdin => "spill_to_stdin",
            ArgvOverflowBehavior::Error => "error",
        }
    }

    /// Cycle to the next choice — the `/settings` row's toggle action.
    pub fn cycled(self) -> Self {
        match self {
            ArgvOverflowBehavior::SpillToTempfile => ArgvOverflowBehavior::SpillToStdin,
            ArgvOverflowBehavior::SpillToStdin => ArgvOverflowBehavior::Error,
            ArgvOverflowBehavior::Error => ArgvOverflowBehavior::SpillToTempfile,
        }
    }
}

/// The bundled, flag-verified harness presets (`external-harness-
/// tool.md` §1/§2). Returned as an ordered list so `/settings` and the
/// "seed presets" action are deterministic. Each preset's flags were
/// verified against the installed binary's `--help` and/or the reference
/// checkouts / `kcl` (see the function body comments). A fresh install
/// ships **no** harnesses (the `harnesses` map starts empty); the user
/// seeds these from `/settings`, keeping the daemon free of assumptions
/// about which CLIs are present.
pub fn builtin_harness_presets() -> Vec<(String, HarnessConfig)> {
    vec![
        // claude — verified against the installed `claude --help`:
        //   -p/--print (headless), reads the prompt from stdin in print mode,
        //   --output-format json (single result), --model <model>,
        //   --permission-mode bypassPermissions (skip interactive approval),
        //   --append-system-prompt-file <path> (agent file). No stable
        //   model-list command, so no `model_list_args`.
        (
            "claude".to_string(),
            HarnessConfig {
                command: "claude".to_string(),
                args: vec![
                    "-p".to_string(),
                    "--permission-mode".to_string(),
                    "bypassPermissions".to_string(),
                ],
                prompt_input: PromptInputMode::Stdin,
                argv_overflow: ArgvOverflowBehavior::SpillToTempfile,
                model_args: vec!["--model".to_string(), "{model}".to_string()],
                default_model: None,
                models: vec![
                    "sonnet".to_string(),
                    "opus".to_string(),
                    "haiku".to_string(),
                ],
                model_list_args: vec![],
                supports_json_output: true,
                json_output_args: vec!["--output-format".to_string(), "json".to_string()],
                supports_agent_file: true,
                agent_file_args: vec![
                    "--append-system-prompt-file".to_string(),
                    "{agent_file}".to_string(),
                ],
                agent_file_env: None,
                auth_env_vars: vec!["ANTHROPIC_API_KEY".to_string()],
                auth_probe_args: vec![],
                always_allow: false,
                timeout_secs: DEFAULT_HARNESS_TIMEOUT_SECS,
            },
        ),
        // codex — verified against the installed `codex exec --help` and the
        // reference checkout (codex-rs/exec/src/cli.rs +
        // utils/cli/src/shared_options.rs):
        //   `codex exec`, prompt read from stdin when no positional given,
        //   --json (JSONL events), -m/--model, -s/--sandbox workspace-write,
        //   --skip-git-repo-check, -c approval_policy=never. `codex debug
        //   models` exists (verified in cli/src/main.rs) — used for refresh.
        (
            "codex".to_string(),
            HarnessConfig {
                command: "codex".to_string(),
                args: vec![
                    "exec".to_string(),
                    "--skip-git-repo-check".to_string(),
                    "--sandbox".to_string(),
                    "workspace-write".to_string(),
                    "-c".to_string(),
                    "approval_policy=never".to_string(),
                ],
                prompt_input: PromptInputMode::Stdin,
                argv_overflow: ArgvOverflowBehavior::SpillToTempfile,
                model_args: vec!["-m".to_string(), "{model}".to_string()],
                default_model: None,
                models: vec![],
                model_list_args: vec!["debug".to_string(), "models".to_string()],
                supports_json_output: true,
                json_output_args: vec!["--json".to_string()],
                supports_agent_file: false,
                agent_file_args: vec![],
                agent_file_env: None,
                auth_env_vars: vec!["OPENAI_API_KEY".to_string()],
                auth_probe_args: vec![],
                always_allow: false,
                timeout_secs: DEFAULT_HARNESS_TIMEOUT_SECS,
            },
        ),
        // opencode — verified against the installed binary (`opencode run
        // --help`, `opencode models`) and kcl (packages/opencode src):
        //   `opencode run`, prompt positional or stdin (read when not a TTY),
        //   --format json, -m provider/model, `opencode models` lists 448
        //   models (one `provider/model` per line). No auth env var (opencode
        //   manages its own auth store), so the preflight skips auth.
        (
            "opencode".to_string(),
            HarnessConfig {
                command: "opencode".to_string(),
                args: vec!["run".to_string()],
                prompt_input: PromptInputMode::Stdin,
                argv_overflow: ArgvOverflowBehavior::SpillToTempfile,
                model_args: vec!["-m".to_string(), "{model}".to_string()],
                default_model: None,
                models: vec![],
                model_list_args: vec!["models".to_string()],
                supports_json_output: true,
                json_output_args: vec!["--format".to_string(), "json".to_string()],
                supports_agent_file: false,
                agent_file_args: vec![],
                agent_file_env: None,
                auth_env_vars: vec![],
                auth_probe_args: vec![],
                always_allow: false,
                timeout_secs: DEFAULT_HARNESS_TIMEOUT_SECS,
            },
        ),
        // copilot — verified against the reference checkout (copilot-cli
        // README + changelog): -p/--prompt (non-interactive, argv-only — no
        // stdin/file per github/copilot-cli#1046), --output-format json
        // (JSONL), --model, --allow-all/--allow-all-paths (skip permission
        // gating), auth via COPILOT_GITHUB_TOKEN / GH_TOKEN / GITHUB_TOKEN.
        // Argv-only ⇒ argv_overflow=error (spilling would feed a path as the
        // prompt and silently break the run).
        (
            "copilot".to_string(),
            HarnessConfig {
                command: "copilot".to_string(),
                args: vec![
                    "-p".to_string(),
                    "{prompt}".to_string(),
                    "--allow-all".to_string(),
                    "--allow-all-paths".to_string(),
                ],
                prompt_input: PromptInputMode::Argv,
                argv_overflow: ArgvOverflowBehavior::Error,
                model_args: vec!["--model".to_string(), "{model}".to_string()],
                default_model: None,
                models: vec![],
                model_list_args: vec![],
                supports_json_output: true,
                json_output_args: vec!["--output-format".to_string(), "json".to_string()],
                supports_agent_file: false,
                agent_file_args: vec![],
                agent_file_env: None,
                auth_env_vars: vec![
                    "COPILOT_GITHUB_TOKEN".to_string(),
                    "GH_TOKEN".to_string(),
                    "GITHUB_TOKEN".to_string(),
                ],
                auth_probe_args: vec![],
                always_allow: false,
                timeout_secs: DEFAULT_HARNESS_TIMEOUT_SECS,
            },
        ),
        // goose — verified against the installed `goose run --help`:
        //   `goose run`, -i - (read instructions from stdin), --output-format
        //   json, --model <model>, --no-session (don't persist), agent file
        //   via the GOOSE_SYSTEM_PROMPT_FILE_PATH env var (no native flag).
        //   No simple stdout model-list command (only `goose local-models`),
        //   so no `model_list_args`. Goose auth is provider-key driven; the
        //   common case is a provider key in the environment, but the exact
        //   var depends on GOOSE_PROVIDER — leave auth_env_vars empty so the
        //   preflight doesn't false-negative, and let a failed run surface.
        (
            "goose".to_string(),
            HarnessConfig {
                command: "goose".to_string(),
                args: vec![
                    "run".to_string(),
                    "-i".to_string(),
                    "-".to_string(),
                    "--no-session".to_string(),
                ],
                prompt_input: PromptInputMode::Stdin,
                argv_overflow: ArgvOverflowBehavior::SpillToTempfile,
                model_args: vec!["--model".to_string(), "{model}".to_string()],
                default_model: None,
                models: vec![],
                model_list_args: vec![],
                supports_json_output: true,
                json_output_args: vec!["--output-format".to_string(), "json".to_string()],
                supports_agent_file: false,
                agent_file_args: vec![],
                agent_file_env: Some("GOOSE_SYSTEM_PROMPT_FILE_PATH".to_string()),
                auth_env_vars: vec![],
                auth_probe_args: vec![],
                always_allow: false,
                timeout_secs: DEFAULT_HARNESS_TIMEOUT_SECS,
            },
        ),
        // grok — verified against the installed `grok --help`, `grok
        // models`, and JSON-output verification via kcl:
        //   top-level `grok --prompt-file <path>` is single-turn/headless,
        //   --output-format json emits one JSON object with `text`,
        //   `stopReason`, `sessionId`, `requestId`, `thought`; -m/--model,
        //   --permission-mode bypassPermissions, and --agent <path> for an
        //   agent definition file. `grok models` is human-formatted
        //   ("Default model:", "Available models:", bullet lines), not one
        //   id per stdout line, so seed a minimal static list instead of
        //   wiring `model_list_args`.
        (
            "grok".to_string(),
            HarnessConfig {
                command: "grok".to_string(),
                args: vec![
                    "--prompt-file".to_string(),
                    "{prompt}".to_string(),
                    "--permission-mode".to_string(),
                    "bypassPermissions".to_string(),
                ],
                prompt_input: PromptInputMode::Tempfile,
                argv_overflow: ArgvOverflowBehavior::SpillToTempfile,
                model_args: vec!["-m".to_string(), "{model}".to_string()],
                default_model: Some("grok-build".to_string()),
                models: vec!["grok-build".to_string()],
                model_list_args: vec![],
                supports_json_output: true,
                json_output_args: vec!["--output-format".to_string(), "json".to_string()],
                supports_agent_file: true,
                agent_file_args: vec!["--agent".to_string(), "{agent_file}".to_string()],
                agent_file_env: None,
                auth_env_vars: vec![],
                always_allow: false,
                auth_probe_args: vec![],
                timeout_secs: DEFAULT_HARNESS_TIMEOUT_SECS,
            },
        ),
    ]
}
