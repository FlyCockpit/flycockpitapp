//! Clap definitions for the `cockpit` CLI surface.
//!
//! The shape mirrors opencode's CLI (per `the CLI design notes`)
//! plus the `cockpit`-specific additions: `meta`, `connect`, `--agent-file`.

use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};
use clap_complete::Shell;

use crate::agents::AgentMode;

#[derive(Debug, Parser)]
#[command(
    name = "cockpit",
    version,
    about = "AI coding harness with a codex-style TUI",
    propagate_version = true
)]
pub struct Cli {
    /// Project path for the no-subcommand TUI launch, or an alias for
    /// `cockpit run --cwd`. Without this flag, the current directory is used.
    #[arg(long, value_name = "PATH")]
    pub project: Option<PathBuf>,

    /// Print logs to stderr instead of dropping them.
    #[arg(long, global = true)]
    pub print_logs: bool,

    /// Log filter: trace / debug / info / warn / error, or a tracing
    /// `EnvFilter` string. Overrides `$COCKPIT_LOG`.
    #[arg(long, global = true, value_name = "LEVEL")]
    pub log_level: Option<String>,

    /// Disable plugins and other external extensions. Accepted for
    /// opencode CLI compatibility; cockpit has no plugins so this is a
    /// no-op.
    #[arg(long, global = true, hide = true)]
    pub pure: bool,

    /// **Debugging:** write each outbound inference request (system
    /// prompt, tool definitions, history, new prompt, params) as
    /// pretty-printed JSON to `<cwd>/.lastmessage`. Overwritten on
    /// every turn. The file is the *content* we hand to rig, not the
    /// exact serialized HTTP body — rig wraps it on the wire.
    #[arg(long, global = true)]
    pub debug_last_message: bool,

    /// Disable filesystem sandboxing for sessions this invocation
    /// creates (sandboxing part 2). The shell runs unconfined and native
    /// tools skip the cwd-boundary prompt. A per-session `/sandbox` flip
    /// still overrides. The daemon's own `--no-sandbox` (set at
    /// `cockpit daemon start`) outranks this for all sessions.
    #[arg(long, global = true)]
    pub no_sandbox: bool,

    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Ask a registered dependency package using the read-only docs agent.
    Ask(AskArgs),

    /// Run a one-shot prompt non-interactively (matches `opencode run`).
    #[command(
        after_long_help = "Exit codes:\n  0  turn succeeded\n  1  turn failed\n  2  usage or configuration error\n  3  workspace trust refused\n  4  daemon or connection error"
    )]
    Run(RunArgs),

    /// Manage agents.
    #[command(subcommand)]
    Agent(AgentCommand),

    /// Manage AI providers and credentials.
    #[command(subcommand, alias = "auth")]
    Providers(ProvidersCommand),

    /// List locally configured provider models; does not fetch from the network.
    Models(ModelsArgs),

    /// Show last provider model catalog refresh status; does not fetch from the network.
    #[command(name = "provider-catalog-status")]
    ProviderCatalogStatus(ProviderCatalogStatusArgs),

    /// Refresh model lists from every configured provider's /models endpoint.
    FetchModels(FetchModelsArgs),

    /// Manage the background daemon (`start`, `stop`, `status`).
    #[command(subcommand)]
    Daemon(DaemonCommand),

    /// Print read-only diagnostics, including trust/model policy and delegation status.
    Doctor(DoctorArgs),

    /// Manage sessions.
    #[command(subcommand)]
    Session(SessionCommand),

    /// Manage workspace trust decisions.
    #[command(subcommand)]
    Trust(TrustCommand),

    /// Export a redacted session debug bundle.
    Export(ExportArgs),

    /// Import session data from a JSON file.
    Import(ImportArgs),

    /// Show token usage and cost statistics.
    Stats(StatsArgs),

    /// Debug / introspection commands.
    #[command(subcommand)]
    Debug(DebugCommand),

    /// Export and import portable non-secret provider/model policy.
    #[command(subcommand)]
    Config(ConfigCommand),

    /// Meta-harness: invoke other harnesses on this device, manage ralph loops.
    Meta(MetaArgs),

    /// Manage MCP servers (GOALS §18): add, list, smoke-test.
    #[command(subcommand)]
    Mcp(McpCommand),

    /// Sign in to a Flycockpit account using browser device authorization.
    Login(LoginArgs),

    /// Sign out of the active Flycockpit account on this machine.
    Logout,

    /// Show the active Flycockpit account and instance.
    Whoami,

    /// Inspect enterprise org-policy synchronization.
    #[command(subcommand)]
    Sync(SyncCommand),

    /// Toggle outbound relay access for remote control on this instance; requires `cockpit login`.
    Connect(ConnectArgs),

    /// Fetch and check out a GitHub PR, then launch cockpit in the worktree.
    Pr(PrArgs),

    /// Manage the package registry the `docs` agent reads from.
    #[command(subcommand, alias = "dependency", alias = "dependencies")]
    Packages(PackagesCommand),

    /// Singular alias for package registry commands.
    #[command(subcommand)]
    Package(PackageCommand),

    /// One-way import of packages from a local `kcl` install's registry.
    #[command(subcommand)]
    Kcl(KclCommand),

    /// Explore the project with an agent and write its instructions file
    /// (default `AGENTS.md`); never touches `config.json`.
    Init(InitArgs),

    /// Inspect the `bash` post-result hint rules (`engine::bash_hints`).
    #[command(subcommand, name = "bash-hints")]
    BashHints(BashHintsCommand),

    /// Generate shell completion script.
    Completion { shell: Shell },
}

/// `cockpit bash-hints` subcommands.
#[derive(Debug, Subcommand)]
pub enum BashHintsCommand {
    /// List the built-in `bash` post-result hint rules (id + description).
    List,
}

#[derive(Debug, Subcommand)]
pub enum TrustCommand {
    /// Show the effective workspace trust root and stored mode.
    Status(TrustStatusArgs),
    /// Store a workspace trust mode for the effective root.
    Set(TrustSetArgs),
}

#[derive(Debug, Subcommand)]
pub enum ConfigCommand {
    /// Export portable provider/model policy JSON without credentials.
    #[command(name = "export-policy")]
    ExportPolicy(ConfigExportPolicyArgs),
    /// Import portable provider/model policy JSON without credentials.
    #[command(name = "import-policy")]
    ImportPolicy(ConfigImportPolicyArgs),
}

#[derive(Debug, clap::Args)]
pub struct ConfigExportPolicyArgs {
    /// Output JSON path. Defaults to stdout.
    #[arg(short, long, value_name = "PATH")]
    pub output: Option<PathBuf>,
}

#[derive(Debug, clap::Args)]
pub struct ConfigImportPolicyArgs {
    /// Portable policy JSON created by `cockpit config export-policy`.
    pub file: PathBuf,

    /// Replace the target provider/model policy instead of merging.
    #[arg(long, conflicts_with = "merge")]
    pub replace: bool,

    /// Merge into the target config, with imported policy fields winning.
    #[arg(long, default_value_t = true)]
    pub merge: bool,
}

#[derive(Debug, clap::Args)]
pub struct TrustStatusArgs {
    /// Directory to inspect (defaults to the current directory).
    pub path: Option<PathBuf>,
}

#[derive(Debug, clap::Args)]
pub struct DoctorArgs {
    /// Directory to inspect (defaults to the current directory).
    pub path: Option<PathBuf>,
}

#[derive(Debug, clap::Args)]
pub struct TrustSetArgs {
    /// Directory whose effective trust root should be updated.
    pub path: Option<PathBuf>,

    /// Workspace trust mode to store.
    #[arg(long, value_enum)]
    pub mode: TrustModeArg,
}

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
pub enum TrustModeArg {
    Trust,
    IgnoreConfig,
    Untrusted,
}

// ---- shared arg shapes ----

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
pub enum OutputFormat {
    /// Human-readable formatted output (default).
    Default,
    /// Newline-delimited JSON events.
    #[value(alias = "ndjson", alias = "jsonl")]
    Json,
}

#[derive(Debug, Clone, clap::Args)]
pub struct RunArgs {
    /// Message to send. When present, stdin is ignored. If absent, read
    /// --prompt-file or stdin to EOF.
    pub message: Vec<String>,

    /// Read the exact UTF-8 prompt body from a file.
    #[arg(long, value_name = "PATH")]
    pub prompt_file: Option<PathBuf>,

    /// Use a specific agent. Overrides the project's default.
    #[arg(long)]
    pub agent: Option<String>,

    /// **cockpit-specific:** load an agent definition from an arbitrary file
    /// path. The file does not need to live in `~/.config/opencode/agents/`.
    #[arg(long, value_name = "PATH")]
    pub agent_file: Option<PathBuf>,

    /// Override the model: `provider/model-id`.
    #[arg(short, long)]
    pub model: Option<String>,

    /// Continue the workspace's most recent session by last-message time.
    #[arg(short, long, conflicts_with = "session")]
    pub continue_session: bool,

    /// Continue a specific session id.
    #[arg(short, long, value_name = "ID", conflicts_with = "continue_session")]
    pub session: Option<String>,

    /// Run against this directory. Sets workspace trust, sandbox, relative
    /// attachment, and session-root resolution.
    #[arg(short = 'C', long, value_name = "DIR")]
    pub cwd: Option<PathBuf>,

    /// Auto-approve this existing approval taxonomy class for this run only.
    /// Repeatable; valid classes: command, path. Grants are never persisted.
    #[arg(long, value_name = "CLASS")]
    pub approve: Vec<crate::approval::store::GrantKind>,

    /// Fork instead of continuing in place.
    #[arg(long)]
    pub fork: bool,

    /// Output format.
    #[arg(long, value_enum, default_value_t = OutputFormat::Default)]
    pub format: OutputFormat,

    /// Emit newline-delimited JSON events.
    #[arg(long)]
    pub json: bool,

    /// Include raw daemon envelope details in JSON output.
    #[arg(long)]
    pub verbose: bool,

    /// Follow the session stream until the agent is waiting for input.
    #[arg(long)]
    pub follow: bool,

    /// File(s) to attach to the message.
    #[arg(short, long, value_name = "PATH")]
    pub file: Vec<PathBuf>,

    /// Show thinking blocks.
    #[arg(long)]
    pub thinking: bool,

    /// Force a fresh ephemeral daemon for this run instead of
    /// attaching to a long-running one. The daemon stops as soon as
    /// the run completes. Useful for CI and clean-state scripts.
    #[arg(long)]
    pub ephemeral: bool,
}

impl RunArgs {
    pub fn output_format(&self) -> OutputFormat {
        if self.json {
            OutputFormat::Json
        } else {
            self.format
        }
    }
}

// ---- agent subcommands ----

#[derive(Debug, Subcommand)]
pub enum AgentCommand {
    /// Create a new agent file.
    Create {
        #[arg(long, value_name = "PATH")]
        path: Option<PathBuf>,
        #[arg(long)]
        description: Option<String>,
        #[arg(long, value_enum)]
        mode: Option<AgentMode>,
        /// Comma-separated tool list.
        #[arg(long)]
        tools: Option<String>,
        #[arg(short, long)]
        model: Option<String>,
    },
    /// List all available agents (project + global + extended `agent_dirs`).
    List,
}

// ---- providers / models ----

#[derive(Debug, Subcommand)]
pub enum ProvidersCommand {
    #[command(alias = "ls")]
    List,
    /// Show vendor plan limits and quota for configured providers.
    Usage(ProvidersUsageArgs),
}

#[derive(Debug, clap::Args)]
pub struct ProvidersUsageArgs {
    /// Provider id to probe. Omit to probe every configured provider.
    #[arg(long, value_name = "ID")]
    pub provider: Option<String>,
}

#[derive(Debug, clap::Args)]
pub struct ModelsArgs {
    /// Provider id to list. Omit to list all providers that have configured models.
    #[arg(value_name = "PROVIDER")]
    pub provider: Option<String>,
}

#[derive(Debug, clap::Args)]
pub struct ProviderCatalogStatusArgs {
    /// Provider id to inspect. Omit to inspect every configured provider.
    #[arg(value_name = "PROVIDER")]
    pub provider: Option<String>,
}

#[derive(Debug, Subcommand)]
pub enum SyncCommand {
    /// Show enterprise org-policy session-log sync state.
    Status,
}

#[derive(Debug, Subcommand)]
pub enum DaemonCommand {
    /// Start the daemon (foreground by default; `--detach` spawns a child).
    Start {
        /// Run in the foreground. Used by the wrapper that spawns the
        /// child — you usually want `--detach` from the command line.
        #[arg(long)]
        foreground: bool,
        /// Spawn a detached background daemon and exit immediately.
        #[arg(long)]
        detach: bool,
        /// Disable filesystem sandboxing for ALL sessions this daemon
        /// hosts (sandboxing part 2) — the highest-precedence default.
        /// Outranks any client `--no-sandbox`. A per-session `/sandbox on`
        /// still re-enables confinement for that session.
        #[arg(long)]
        no_sandbox: bool,
        /// Resume all durable paused session work after startup instead of
        /// leaving it dormant for per-session reattach prompts.
        #[arg(long)]
        resume_all_sessions: bool,
    },
    /// Stop the running daemon.
    Stop {
        /// Grace period, in seconds, before forcing in-flight work to stop.
        #[arg(long, value_name = "SECS")]
        grace: Option<u64>,
    },
    /// Gracefully restart the daemon, resuming active sessions by default.
    #[command(
        after_help = "There is no --sandbox flag; to force sandboxing back on, run `cockpit daemon stop` then `cockpit daemon start --detach`."
    )]
    Restart {
        /// Grace period, in seconds, before forcing in-flight work to stop.
        #[arg(long, value_name = "SECS")]
        grace: Option<u64>,
        /// Start the replacement daemon without resuming paused work.
        #[arg(long)]
        no_resume: bool,
        /// Disable filesystem sandboxing for the replacement daemon.
        #[arg(long)]
        no_sandbox: bool,
    },
    /// Print whether the daemon is running.
    Status {
        /// Emit one JSON document with daemon, DB-path, and schema diagnostics.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, clap::Args)]
#[command(after_help = "Exit codes:
  0   login completed
  1   network/auth/server failure, denied approval, or expired device code
  64  invalid command usage")]
pub struct LoginArgs {
    /// Flycockpit server origin. HTTPS is required except for localhost development.
    #[arg(long, default_value = "https://app.flycockpit.dev", value_name = "URL")]
    pub server: String,

    /// Display name for this machine in Flycockpit. Defaults to the hostname.
    #[arg(long, value_name = "DISPLAY_NAME")]
    pub name: Option<String>,

    /// Replace the currently logged-in Flycockpit account without prompting.
    #[arg(long)]
    pub force: bool,
}

#[derive(Debug, clap::Args)]
pub struct FetchModelsArgs {
    /// Provider id to refresh. Omit to refresh every configured provider's model list.
    #[arg(value_name = "PROVIDER")]
    pub provider_arg: Option<String>,

    /// Only refresh this provider id. Kept as a compatibility alias for the positional provider.
    #[arg(long, value_name = "ID")]
    pub provider: Option<String>,

    /// `keep` | `remove` — skip the interactive prompt when configured
    /// models drift from the upstream listing.
    #[arg(long, value_name = "POLICY")]
    pub on_unlisted: Option<String>,

    /// Activate a provider's built-in fallback catalog when live discovery
    /// fails. Without this flag, existing live models are preserved.
    #[arg(long)]
    pub allow_fallback: bool,
}

// ---- sessions ----

#[derive(Debug, Subcommand)]
pub enum SessionCommand {
    List,
    /// Show a session's durable compaction handoffs and summary statistics.
    Show {
        #[arg(value_name = "SESSION_ID")]
        session_id: String,
        /// Emit one JSON document instead of formatted text.
        #[arg(long)]
        json: bool,
    },
    Delete {
        #[arg(value_name = "SESSION_ID")]
        session_id: String,
    },
    /// Answer a pending question or approval interrupt.
    Answer(SessionAnswerArgs),
}

#[derive(Debug, Clone, clap::Args)]
#[command(after_help = "\
Examples:
  cockpit session answer --session <session_id> --interrupt <interrupt_id> --choice yes --json
  cockpit session answer --session <session_id> --interrupt <interrupt_id> --choices a,b --json
  cockpit session answer --session <session_id> --interrupt <interrupt_id> --text \"Use the daemon path\" --json
  cockpit session answer --session <session_id> --interrupt <interrupt_id> --answers-json /tmp/answers.json --json
  cockpit session answer --session <session_id> --interrupt <interrupt_id> --cancel --json")]
pub struct SessionAnswerArgs {
    /// Session that owns the pending interrupt.
    #[arg(long, value_name = "SESSION_ID")]
    pub session: String,

    /// Interrupt id to resolve.
    #[arg(long, value_name = "INTERRUPT_ID")]
    pub interrupt: String,

    /// Selected option id for a single-select question.
    #[arg(long, value_name = "OPTION_ID")]
    pub choice: Option<String>,

    /// Comma-separated option ids for a multi-select question.
    #[arg(long, value_name = "OPTION_ID,...")]
    pub choices: Option<String>,

    /// Free-text answer.
    #[arg(long, value_name = "TEXT")]
    pub text: Option<String>,

    /// Batch answer JSON, either inline or a path to a JSON file.
    #[arg(long, value_name = "JSON_OR_PATH")]
    pub answers_json: Option<String>,

    /// Dismiss the interrupt without an answer.
    #[arg(long)]
    pub cancel: bool,

    /// Emit machine-readable JSON.
    #[arg(long)]
    pub json: bool,

    /// Stream the session continuation until the agent is idle.
    #[arg(long)]
    pub follow: bool,
}

#[derive(Debug, clap::Args)]
pub struct ExportArgs {
    /// Session to export: a 6-char `short_id` or a full UUID. Recurses
    /// the fork tree (target + all descendant forks).
    pub session_id: Option<String>,

    /// Output `.zip` path. Defaults to `./cockpit-session-<short_id>.zip`.
    /// Refuses to overwrite an existing file unless `--force`.
    #[arg(short, long, value_name = "PATH")]
    pub output: Option<PathBuf>,

    /// Overwrite the output path if it already exists.
    #[arg(long)]
    pub force: bool,

    /// Include generated/cache/prior-export artifacts from raw config layer copies.
    #[arg(long)]
    pub include_generated: bool,

    /// Include exact captured model/tool payloads. By default export scrubs
    /// sensitive strings through the configured redaction table.
    #[arg(long)]
    pub include_sensitive: bool,
}

#[derive(Debug, clap::Args)]
pub struct ImportArgs {
    pub file: PathBuf,
}

/// Scope toggle for `cockpit stats` (GOALS §15a / §15f).
#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
pub enum StatsProjectScope {
    /// The project rooted at the current working directory (default).
    Current,
    /// Every project recorded on this machine.
    All,
}

/// Range toggle for `cockpit stats` (GOALS §15a / §15f).
#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
pub enum StatsRangeArg {
    /// The last 7 days (default).
    #[value(name = "7d")]
    SevenDays,
    /// All recorded history.
    All,
}

/// Output format for `cockpit stats` (GOALS §15f).
#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
pub enum StatsFormat {
    /// Human-readable aligned columns (default).
    Table,
    /// Machine-readable JSON (the full roll-up struct).
    Json,
    /// One CSV stream per section, for scripting.
    Csv,
}

#[derive(Debug, clap::Args)]
pub struct StatsArgs {
    /// Which projects to include.
    #[arg(long = "project", value_enum, default_value_t = StatsProjectScope::Current)]
    pub project_scope: StatsProjectScope,

    /// Time window.
    #[arg(long, value_enum, default_value_t = StatsRangeArg::SevenDays)]
    pub range: StatsRangeArg,

    /// Output format.
    #[arg(long, value_enum, default_value_t = StatsFormat::Table)]
    pub format: StatsFormat,

    /// Add a per-role (agent) token/cost breakdown.
    #[arg(long)]
    pub by_role: bool,
}

// ---- debug ----

#[derive(Debug, Subcommand)]
pub enum DebugCommand {
    /// Show the resolved configuration.
    Config,
    /// Show the resolved global paths.
    Paths,
    /// List all known projects.
    Scrap,
    /// List all available skills.
    Skill,
    /// Show details for a specific agent.
    Agent { name: String },
    /// File-system debugging utilities.
    File,
    /// **cockpit-specific:** dump the redaction table that would apply to the
    /// next request.
    Redact,
    /// **cockpit-specific:** dump the full prompt (system + tools + history)
    /// that would be sent for the next turn, with token counts. Lets users
    /// audit cockpit's context overhead. See `the design notes` §10.
    Context,
    /// **cockpit-specific:** list recent tool calls that hard-failed
    /// (and optionally those that fired any recovery). Surfaces
    /// candidates for the §12 repair catalog.
    FailedCalls(FailedCallsArgs),
    /// Wait indefinitely (for debugging).
    Wait,
}

#[derive(Debug, clap::Args)]
pub struct FailedCallsArgs {
    /// Only failures within the last N days. Default: 7.
    #[arg(long, default_value_t = 7)]
    pub days: u32,
    /// Only this tool name (e.g. `editunlock`, `bash`).
    #[arg(long)]
    pub tool: Option<String>,
    /// Only this model id.
    #[arg(long)]
    pub model: Option<String>,
    /// Project path (resolves to project_id). Defaults to all projects.
    #[arg(long, value_name = "PATH")]
    pub project: Option<PathBuf>,
    /// Max rows. Default: 50.
    #[arg(long, default_value_t = 50)]
    pub limit: u32,
    /// Also include rows that succeeded after a recovery fired (any
    /// non-NULL `recovery_kind`).
    #[arg(long)]
    pub include_recovered: bool,
    /// Emit NDJSON instead of formatted text.
    #[arg(long)]
    pub json: bool,
}

// ---- meta / connect / pr / init ----

#[derive(Debug, clap::Args)]
pub struct MetaArgs {
    /// Message to seed the meta-harness with. If absent, drop into the TUI.
    pub message: Vec<String>,

    /// Use a specific harness as the meta agent's executor (defaults to cockpit).
    #[arg(long)]
    pub harness: Option<String>,
}

// ---- packages / kcl import ----

#[derive(Debug, clap::Args)]
pub struct AskArgs {
    /// Registered package identifier (e.g. `tokio`, `cargo:tokio`, `npm:@scope/pkg`).
    pub package_id: String,
    /// Question to answer. If omitted, the question is read from stdin.
    #[arg(value_name = "QUESTION", num_args = 0..)]
    pub question: Vec<String>,
}

#[derive(Debug, Subcommand)]
pub enum PackagesCommand {
    /// List every registered package.
    #[command(alias = "ls")]
    List,
    /// Register a package: `--git <url>` clones (shallow by default);
    /// `--path <dir>` registers a local directory in place.
    Add(PackagesAddArgs),
    /// Import packages from one local checkout or a directory of checkouts.
    Import(PackagesImportArgs),
    /// Delete stale Cockpit-owned Git clone directories; registry rows remain.
    Prune(PackagesPruneArgs),
}

#[derive(Debug, clap::Args)]
pub struct PackagesImportArgs {
    /// Scan immediate child directories and import each package.
    #[arg(long, value_name = "DIR", conflicts_with = "package")]
    pub dir: Option<PathBuf>,
    /// Import one package directory.
    #[arg(long, value_name = "DIR", conflicts_with = "dir")]
    pub package: Option<PathBuf>,
    /// Override the derived identifier for single-package import.
    #[arg(long, value_name = "IDENTIFIER", conflicts_with = "dir")]
    pub id: Option<String>,
    /// Register exact local paths instead of Git-managed Cockpit clones.
    #[arg(long)]
    pub path: bool,
}

#[derive(Debug, Subcommand)]
pub enum PackageCommand {
    /// List every registered package.
    #[command(alias = "ls")]
    List,
    /// Register a package: `--git <url>` clones (shallow by default);
    /// `--path <dir>` registers a local directory in place.
    Add(PackagesAddArgs),
    /// Alias for `cockpit packages import --package <dir>`.
    Import(PackageImportArgs),
    /// Delete stale Cockpit-owned Git clone directories; registry rows remain.
    Prune(PackagesPruneArgs),
}

#[derive(Debug, clap::Args)]
pub struct PackageImportArgs {
    /// Import one package directory.
    #[arg(value_name = "DIR")]
    pub package: PathBuf,
    /// Override the derived identifier.
    #[arg(long, value_name = "IDENTIFIER")]
    pub id: Option<String>,
    /// Register the exact local path instead of a Git-managed Cockpit clone.
    #[arg(long)]
    pub path: bool,
}

#[derive(Debug, clap::Args)]
pub struct PackagesAddArgs {
    /// Canonical identifier (e.g. `tokio`, `cargo:tokio`, `@scope/pkg`).
    pub identifier: String,
    /// Clone this Git repo into the cockpit clone dir.
    #[arg(long, value_name = "URL")]
    pub git: Option<String>,
    /// Register this existing local directory (no clone).
    #[arg(long, value_name = "PATH")]
    pub path: Option<PathBuf>,
    /// Branch to clone (Git only).
    #[arg(long)]
    pub branch: Option<String>,
    /// Full clone. Default is a shallow `--depth 1 --no-single-branch` clone.
    #[arg(long, alias = "shallow")]
    pub deep: bool,
}

#[derive(Debug, clap::Args)]
pub struct PackagesPruneArgs {
    /// Delete clones not updated in the last N days.
    #[arg(long, default_value_t = crate::packages::DEFAULT_PRUNE_DAYS)]
    pub days: u32,
    /// Show what would be deleted without deleting anything.
    #[arg(long)]
    pub dry_run: bool,
}

// ---- MCP (GOALS §18) ----

#[derive(Debug, Subcommand)]
pub enum McpCommand {
    /// List configured MCP servers with transport, enabled state, and auth.
    #[command(alias = "ls")]
    List,
    /// Add an MCP server to the nearest writable `.cockpit/mcp.json`.
    Add(McpAddArgs),
    /// Smoke-test a server: connect, list tools, and dump the catalog.
    Test(McpTestArgs),
}

#[derive(Debug, clap::Args)]
pub struct McpAddArgs {
    /// Server name (the catalog/`mcp.invoke` identifier).
    pub name: String,
    /// Transport: `streamable` (HTTP), `stdio`, or `sse` (legacy).
    #[arg(long, default_value = "streamable")]
    pub transport: String,
    /// Remote endpoint URL (`streamable`/`sse`).
    #[arg(long, value_name = "URL")]
    pub endpoint: Option<String>,
    /// Subprocess command (`stdio`).
    #[arg(long)]
    pub command: Option<String>,
    /// Subprocess args (`stdio`), repeatable.
    #[arg(long = "arg", value_name = "ARG")]
    pub args: Vec<String>,
    /// Auth kind: `oauth`, `header`, `env`, or `none`.
    #[arg(long, default_value = "none")]
    pub auth: String,
    /// Static header value for `--auth header` (e.g. `Bearer $TOKEN`).
    #[arg(long, value_name = "VALUE")]
    pub header_value: Option<String>,
    /// Header name for `--auth header` (defaults to `Authorization`).
    #[arg(long, value_name = "NAME")]
    pub header_name: Option<String>,
    /// Add the server disabled.
    #[arg(long)]
    pub disabled: bool,
}

#[derive(Debug, clap::Args)]
pub struct McpTestArgs {
    /// Server name to smoke-test (must already be configured).
    pub name: String,
}

#[derive(Debug, Subcommand)]
pub enum KclCommand {
    /// Import every package cockpit lacks from kcl's registry.
    Import,
}

#[derive(Debug, clap::Args)]
pub struct ConnectArgs {
    #[command(subcommand)]
    pub command: Option<ConnectCommand>,
}

#[derive(Debug, Subcommand, Clone, Copy, PartialEq, Eq)]
pub enum ConnectCommand {
    /// Enable outbound remote access for this logged-in instance.
    On,
    /// Disable outbound remote access for this logged-in instance.
    Off,
    /// Show connector status.
    Status,
}

#[derive(Debug, clap::Args)]
pub struct PrArgs {
    pub number: u32,

    /// Repo override (`owner/name`); defaults to the current repo.
    #[arg(long)]
    pub repo: Option<String>,
}

#[derive(Debug, clap::Args)]
pub struct InitArgs {
    /// Target instructions file (defaults to the first configured
    /// `agent_guidance_files`, i.e. `AGENTS.md`).
    pub path: Option<String>,
    /// Regenerate (overwrite from scratch) an existing target file.
    #[arg(long)]
    pub force: bool,
    /// Force a fresh ephemeral daemon for this run instead of attaching
    /// to a long-running one.
    #[arg(long)]
    pub ephemeral: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{CommandFactory, error::ErrorKind};

    #[test]
    fn bare_cockpit_has_no_project_override_or_subcommand() {
        let cli = Cli::try_parse_from(["cockpit"]).unwrap();
        assert!(cli.project.is_none());
        assert!(cli.command.is_none());
    }

    #[test]
    fn bare_project_positional_is_not_accepted() {
        let err = Cli::try_parse_from(["cockpit", "."]).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidSubcommand);
    }

    #[test]
    fn explicit_project_flag_applies_to_tui_launch() {
        let cli = Cli::try_parse_from(["cockpit", "--project", "/tmp/example"]).unwrap();
        assert_eq!(cli.project, Some(PathBuf::from("/tmp/example")));
        assert!(cli.command.is_none());
    }

    #[test]
    fn run_message_varargs_do_not_compete_with_global_project() {
        let cli = Cli::try_parse_from(["cockpit", "run", "hi", "there"]).unwrap();
        match cli.command {
            Some(Command::Run(args)) => assert_eq!(args.message, ["hi", "there"]),
            other => panic!("expected run command, got {other:?}"),
        }
    }

    #[test]
    fn meta_message_varargs_do_not_compete_with_global_project() {
        let cli = Cli::try_parse_from(["cockpit", "meta", "hi", "there"]).unwrap();
        match cli.command {
            Some(Command::Meta(args)) => assert_eq!(args.message, ["hi", "there"]),
            other => panic!("expected meta command, got {other:?}"),
        }
    }

    #[test]
    fn export_include_generated_flag_parses() {
        let cli =
            Cli::try_parse_from(["cockpit", "export", "abc123", "--include-generated"]).unwrap();
        match cli.command {
            Some(Command::Export(args)) => {
                assert_eq!(args.session_id.as_deref(), Some("abc123"));
                assert!(args.include_generated);
                assert!(!args.include_sensitive);
            }
            other => panic!("expected export command, got {other:?}"),
        }

        let cli =
            Cli::try_parse_from(["cockpit", "export", "abc123", "--include-sensitive"]).unwrap();
        match cli.command {
            Some(Command::Export(args)) => {
                assert_eq!(args.session_id.as_deref(), Some("abc123"));
                assert!(args.include_sensitive);
            }
            other => panic!("expected export command, got {other:?}"),
        }
    }

    #[test]
    fn config_policy_commands_parse() {
        let cli = Cli::try_parse_from(["cockpit", "config", "export-policy", "-o", "policy.json"])
            .unwrap();
        match cli.command {
            Some(Command::Config(ConfigCommand::ExportPolicy(args))) => {
                assert_eq!(args.output, Some(PathBuf::from("policy.json")));
            }
            other => panic!("expected config export-policy command, got {other:?}"),
        }

        let cli = Cli::try_parse_from([
            "cockpit",
            "config",
            "import-policy",
            "policy.json",
            "--replace",
        ])
        .unwrap();
        match cli.command {
            Some(Command::Config(ConfigCommand::ImportPolicy(args))) => {
                assert_eq!(args.file, PathBuf::from("policy.json"));
                assert!(args.replace);
            }
            other => panic!("expected config import-policy command, got {other:?}"),
        }
    }

    #[test]
    fn doctor_parses_with_optional_path() {
        let cli = Cli::try_parse_from(["cockpit", "doctor", "/tmp/example"]).unwrap();
        match cli.command {
            Some(Command::Doctor(args)) => {
                assert_eq!(args.path, Some(PathBuf::from("/tmp/example")))
            }
            other => panic!("expected doctor command, got {other:?}"),
        }
    }

    #[test]
    fn run_and_meta_help_return_clap_help() {
        let run = Cli::command()
            .try_get_matches_from(["cockpit", "run", "--help"])
            .unwrap_err();
        assert_eq!(run.kind(), ErrorKind::DisplayHelp);

        let meta = Cli::command()
            .try_get_matches_from(["cockpit", "meta", "--help"])
            .unwrap_err();
        assert_eq!(meta.kind(), ErrorKind::DisplayHelp);
    }

    #[test]
    fn fetch_models_positional_provider_parses() {
        let cli = Cli::try_parse_from(["cockpit", "fetch-models", "codex-oauth"]).unwrap();
        match cli.command {
            Some(Command::FetchModels(args)) => {
                assert_eq!(args.provider_arg.as_deref(), Some("codex-oauth"));
                assert!(args.provider.is_none());
            }
            other => panic!("expected fetch-models command, got {other:?}"),
        }
    }

    #[test]
    fn fetch_models_help_names_provider_catalogs() {
        let help = Cli::command()
            .try_get_matches_from(["cockpit", "fetch-models", "--help"])
            .unwrap_err()
            .to_string();

        assert!(help.contains("provider"), "{help}");
        assert!(help.contains("Provider id"), "{help}");
    }

    #[test]
    fn daemon_stop_grace_parses_zero() {
        let cli = Cli::try_parse_from(["cockpit", "daemon", "stop", "--grace", "0"]).unwrap();
        match cli.command {
            Some(Command::Daemon(DaemonCommand::Stop { grace })) => {
                assert_eq!(grace, Some(0));
            }
            other => panic!("expected daemon stop command, got {other:?}"),
        }
    }

    #[test]
    fn daemon_restart_flags_parse() {
        let cli = Cli::try_parse_from([
            "cockpit",
            "daemon",
            "restart",
            "--grace",
            "0",
            "--no-resume",
            "--no-sandbox",
        ])
        .unwrap();
        match cli.command {
            Some(Command::Daemon(DaemonCommand::Restart {
                grace,
                no_resume,
                no_sandbox,
            })) => {
                assert_eq!(grace, Some(0));
                assert!(no_resume);
                assert!(no_sandbox);
            }
            other => panic!("expected daemon restart command, got {other:?}"),
        }
    }

    #[test]
    fn daemon_restart_help_documents_sandbox_parity_note() {
        let mut cmd = Cli::command();
        let help = cmd
            .find_subcommand_mut("daemon")
            .unwrap()
            .find_subcommand_mut("restart")
            .unwrap()
            .render_long_help()
            .to_string();
        assert!(help.contains("There is no --sandbox flag"), "{help}");
        assert!(help.contains("--no-resume"), "{help}");
        assert!(help.contains("--grace"), "{help}");
    }

    #[test]
    fn trust_status_parses_with_optional_path() {
        let cli = Cli::try_parse_from(["cockpit", "trust", "status"]).unwrap();
        match cli.command {
            Some(Command::Trust(TrustCommand::Status(args))) => assert!(args.path.is_none()),
            other => panic!("expected trust status command, got {other:?}"),
        }

        let cli = Cli::try_parse_from(["cockpit", "trust", "status", "/tmp/example"]).unwrap();
        match cli.command {
            Some(Command::Trust(TrustCommand::Status(args))) => {
                assert_eq!(args.path, Some(PathBuf::from("/tmp/example")));
            }
            other => panic!("expected trust status command, got {other:?}"),
        }
    }

    #[test]
    fn trust_set_parses_all_modes() {
        for (value, expected) in [
            ("trust", TrustModeArg::Trust),
            ("ignore-config", TrustModeArg::IgnoreConfig),
            ("untrusted", TrustModeArg::Untrusted),
        ] {
            let cli =
                Cli::try_parse_from(["cockpit", "trust", "set", "/tmp/example", "--mode", value])
                    .unwrap();
            match cli.command {
                Some(Command::Trust(TrustCommand::Set(args))) => {
                    assert_eq!(args.path, Some(PathBuf::from("/tmp/example")));
                    assert_eq!(args.mode, expected);
                }
                other => panic!("expected trust set command, got {other:?}"),
            }
        }
    }

    #[test]
    fn invalid_run_and_meta_invocations_return_clap_errors() {
        let run = Cli::try_parse_from(["cockpit", "run", "--definitely-not-a-flag"]).unwrap_err();
        assert_eq!(run.kind(), ErrorKind::UnknownArgument);

        let meta = Cli::try_parse_from(["cockpit", "meta", "--definitely-not-a-flag"]).unwrap_err();
        assert_eq!(meta.kind(), ErrorKind::UnknownArgument);
    }

    fn parse_run(args: &[&str]) -> RunArgs {
        match Cli::try_parse_from(args).unwrap().command {
            Some(Command::Run(args)) => args,
            other => panic!("expected run command, got {other:?}"),
        }
    }

    #[test]
    fn run_json_alias_sets_json_output() {
        let args = parse_run(&["cockpit", "run", "hi", "--json"]);
        assert_eq!(args.message, ["hi"]);
        assert_eq!(args.output_format(), OutputFormat::Json);
    }

    #[test]
    fn run_prompt_file_json_parses() {
        let args = parse_run(&["cockpit", "run", "--prompt-file", "/tmp/p.md", "--json"]);
        assert_eq!(args.prompt_file, Some(PathBuf::from("/tmp/p.md")));
        assert_eq!(args.output_format(), OutputFormat::Json);
    }

    #[test]
    fn run_session_message_json_parses() {
        let id = uuid::Uuid::new_v4().to_string();
        let args = parse_run(&["cockpit", "run", "--session", &id, "follow up", "--json"]);
        assert_eq!(args.session.as_deref(), Some(id.as_str()));
        assert_eq!(args.message, ["follow up"]);
        assert_eq!(args.output_format(), OutputFormat::Json);
    }

    #[test]
    fn run_session_follow_json_parses() {
        let id = uuid::Uuid::new_v4().to_string();
        let args = parse_run(&["cockpit", "run", "--session", &id, "--follow", "--json"]);
        assert_eq!(args.session.as_deref(), Some(id.as_str()));
        assert!(args.follow);
        assert_eq!(args.output_format(), OutputFormat::Json);
    }

    #[test]
    fn run_json_verbose_parses() {
        let args = parse_run(&["cockpit", "run", "hi", "--json", "--verbose"]);
        assert!(args.verbose);
        assert_eq!(args.output_format(), OutputFormat::Json);
    }

    #[test]
    fn run_ndjson_format_aliases_parse() {
        for value in ["json", "ndjson", "jsonl"] {
            let args = parse_run(&["cockpit", "run", "hi", "--format", value]);
            assert_eq!(args.output_format(), OutputFormat::Json);
        }
    }

    fn parse_answer(extra: &[&str]) -> SessionAnswerArgs {
        let session = uuid::Uuid::new_v4().to_string();
        let interrupt = uuid::Uuid::new_v4().to_string();
        let mut args = vec![
            "cockpit",
            "session",
            "answer",
            "--session",
            &session,
            "--interrupt",
            &interrupt,
        ];
        args.extend_from_slice(extra);
        match Cli::try_parse_from(args).unwrap().command {
            Some(Command::Session(SessionCommand::Answer(args))) => args,
            other => panic!("expected session answer command, got {other:?}"),
        }
    }

    #[test]
    fn session_answer_choice_parses() {
        let args = parse_answer(&["--choice", "yes", "--json"]);
        assert_eq!(args.choice.as_deref(), Some("yes"));
        assert!(args.json);
    }

    #[test]
    fn session_show_json_parses() {
        let session = uuid::Uuid::new_v4().to_string();
        match Cli::try_parse_from(["cockpit", "session", "show", &session, "--json"])
            .unwrap()
            .command
        {
            Some(Command::Session(SessionCommand::Show { session_id, json })) => {
                assert_eq!(session_id, session);
                assert!(json);
            }
            other => panic!("expected session show command, got {other:?}"),
        }
    }

    #[test]
    fn daemon_status_json_parses() {
        match Cli::try_parse_from(["cockpit", "daemon", "status", "--json"])
            .unwrap()
            .command
        {
            Some(Command::Daemon(DaemonCommand::Status { json })) => assert!(json),
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn session_answer_multi_text_batch_cancel_and_follow_parse() {
        assert_eq!(
            parse_answer(&["--choices", "a,b"]).choices.as_deref(),
            Some("a,b")
        );
        assert_eq!(
            parse_answer(&["--text", "free"]).text.as_deref(),
            Some("free")
        );
        assert_eq!(
            parse_answer(&["--answers-json", "/tmp/answers.json"])
                .answers_json
                .as_deref(),
            Some("/tmp/answers.json")
        );
        assert!(parse_answer(&["--cancel"]).cancel);
        assert!(parse_answer(&["--choice", "yes", "--follow"]).follow);
    }
}
