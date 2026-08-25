//! Clap definitions for the `cockpit` CLI surface.
//!
//! The shape defines FlyCockpit's command-line surface.

use std::path::PathBuf;

use clap::{ArgAction, Parser, Subcommand, ValueEnum};
use clap_complete::Shell;

#[derive(Debug, Parser)]
#[command(
    name = "cockpit",
    version,
    about = "AI coding harness with an interactive terminal UI",
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

    /// Debugging: write each outbound inference request (system
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

    /// Run a one-shot prompt non-interactively.
    #[command(
        after_long_help = "Exit codes:\n  0  turn succeeded\n  2  usage or configuration error\n  3  workspace trust refused\n  4  daemon, connection, capacity, or unavailable id\n  5  authoritative non-success terminal outcome (timeout, max-turns, failure, not-found)\n  130 interrupted (SIGINT)"
    )]
    Run(RunArgs),

    /// Query or cancel a durable run invocation by client_submission_id.
    #[command(subcommand)]
    Invocation(InvocationCommand),

    /// Manage agents.
    #[command(subcommand)]
    Agent(AgentCommand),

    /// User-facing assistant workflows.
    #[command(subcommand)]
    Assistant(AssistantCommand),

    /// Manage the FlyCockpit account used for SaaS sync and relay access.
    #[cfg(feature = "remote")]
    #[command(subcommand)]
    Account(AccountCommand),

    /// Manage AI providers and credentials.
    #[command(subcommand, name = "provider", alias = "providers", alias = "auth")]
    Provider(ProvidersCommand),

    /// Run an interactive setup wizard.
    Setup(SetupArgs),

    /// List locally configured provider models; does not fetch from the network.
    Models(ModelsArgs),

    /// Show last provider model catalog refresh status; does not fetch from the network.
    #[command(name = "provider-catalog-status")]
    ProviderCatalogStatus(ProviderCatalogStatusArgs),

    /// Refresh model lists from every configured provider's /models endpoint.
    FetchModels(FetchModelsArgs),

    /// Run the bundled jq-compatible JSON query applet.
    #[command(
        trailing_var_arg = true,
        allow_hyphen_values = true,
        disable_help_flag = true,
        disable_version_flag = true
    )]
    Jq(JqArgs),

    /// Manage the background daemon (`start`, `stop`, `status`).
    #[command(subcommand)]
    Daemon(DaemonCommand),

    /// Print read-only diagnostics, including trust/model policy and delegation status.
    Doctor(DoctorArgs),

    /// Manage sessions.
    #[command(subcommand)]
    Session(SessionCommand),

    /// Manage durable daemon scheduler jobs.
    #[command(subcommand)]
    Schedule(ScheduleCommand),

    /// Manage Agent Skills.
    #[command(subcommand)]
    Skill(SkillCommand),

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

    /// Manage MCP servers: add, list, and smoke-test.
    #[command(subcommand)]
    Mcp(McpCommand),

    /// Removed: use `cockpit account login` or `cockpit provider add`.
    #[cfg(feature = "remote")]
    #[command(hide = true)]
    Login(RemovedCommandArgs),

    /// Removed: use `cockpit account logout` or `cockpit provider add`.
    #[cfg(feature = "remote")]
    #[command(hide = true)]
    Logout,

    /// Removed: use `cockpit account whoami` or `cockpit provider add`.
    #[cfg(feature = "remote")]
    #[command(hide = true)]
    Whoami,

    /// Inspect enterprise org-policy synchronization.
    #[cfg(feature = "remote")]
    #[command(subcommand)]
    Sync(SyncCommand),

    /// Toggle outbound relay access for remote control on this instance; requires `cockpit account login`.
    #[cfg(feature = "remote")]
    Connect(ConnectArgs),

    /// Manage the package registry the `docs` agent reads from.
    #[command(
        subcommand,
        alias = "package",
        alias = "dependency",
        alias = "dependencies"
    )]
    Packages(PackagesCommand),

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

#[derive(Debug, clap::Args)]
pub struct JqArgs {
    #[arg(
        value_name = "JQ_ARGS",
        trailing_var_arg = true,
        allow_hyphen_values = true
    )]
    pub args: Vec<std::ffi::OsString>,
}

/// `cockpit bash-hints` subcommands.
#[derive(Debug, Subcommand)]
pub enum BashHintsCommand {
    /// List the built-in `bash` post-result hint rules (id + description).
    List,
}

#[derive(Debug, Subcommand)]
pub enum AssistantCommand {
    /// Create a new persistent assistant.
    New(AssistantNewArgs),
    /// List persistent assistants.
    List,
    /// Show one assistant definition and metadata.
    Show {
        #[arg(value_name = "NAME")]
        name: String,
    },
    /// Delete an assistant registry row without deleting its home directory.
    Delete(AssistantDeleteArgs),
    /// Open or create the assistant's latest session.
    Chat {
        #[arg(value_name = "NAME")]
        name: String,
    },
    /// Turn local paths, URLs, text, or a recent workflow into a reusable skill.
    Learn(LearnArgs),
    /// Inspect or repair durable media accounting.
    Media {
        #[command(subcommand)]
        command: AssistantMediaCommand,
    },
}

#[derive(Debug, Subcommand)]
pub enum AssistantMediaCommand {
    Accounting {
        #[command(subcommand)]
        command: MediaAccountingCommand,
    },
}

#[derive(Debug, Subcommand)]
pub enum MediaAccountingCommand {
    Diagnose {
        #[arg(long, value_parser=["global","project","session"])]
        scope: String,
        #[arg(long)]
        id: String,
        #[arg(long, required = true)]
        json: bool,
    },
    Repair {
        #[arg(long, value_parser=["global","project","session"])]
        scope: String,
        #[arg(long)]
        id: String,
        #[arg(long)]
        expected_block_generation: u64,
        #[arg(long)]
        repair_plan_digest: String,
        #[arg(long)]
        idempotency_key: String,
    },
}

#[derive(Debug, clap::Args)]
pub struct AssistantNewArgs {
    #[arg(value_name = "NAME")]
    pub name: String,
}

#[derive(Debug, clap::Args)]
pub struct AssistantDeleteArgs {
    #[arg(value_name = "NAME")]
    pub name: String,
    /// Do not prompt for confirmation.
    #[arg(long, short = 'y')]
    pub yes: bool,
}

#[derive(Debug, clap::Args)]
pub struct LearnArgs {
    /// Source request. Multiple words and sources are forwarded together.
    #[arg(required = true, num_args = 1..)]
    pub sources: Vec<String>,
    /// Force a fresh ephemeral daemon instead of attaching to a long-running one.
    #[arg(long)]
    pub ephemeral: bool,
}

#[derive(Debug, Subcommand)]
pub enum TrustCommand {
    /// Show the effective workspace trust root and stored mode.
    Status(TrustStatusArgs),
    /// Store a workspace trust mode for the effective root.
    Set(TrustSetArgs),
}

#[derive(Debug, Subcommand)]
pub enum ScheduleCommand {
    /// Create or replace a durable scheduler job.
    Create(ScheduleCreateArgs),
    /// List durable scheduler jobs.
    List(ScheduleListArgs),
    /// Enable a durable scheduler job.
    Enable {
        #[arg(value_name = "ID")]
        id: String,
    },
    /// Disable a durable scheduler job.
    Disable {
        #[arg(value_name = "ID")]
        id: String,
    },
    /// Fire a durable scheduler job immediately.
    Run {
        #[arg(value_name = "ID")]
        id: String,
    },
}

#[derive(Debug, clap::Args)]
pub struct ScheduleCreateArgs {
    #[arg(value_name = "ID")]
    pub id: String,
    /// Job owner, e.g. assistant:alice or system:dreamer.
    #[arg(long, value_name = "OWNER")]
    pub owner: String,
    /// JSON ScheduledJobSchedule payload, e.g. {"type":"every","seconds":60}.
    #[arg(long, value_name = "JSON")]
    pub schedule_json: String,
    /// JSON ScheduledJobPayload payload.
    #[arg(long, value_name = "JSON")]
    pub payload_json: String,
    /// Create the job disabled.
    #[arg(long)]
    pub disabled: bool,
    /// Missed-run policy.
    #[arg(long, default_value = "skip", value_parser = ["skip", "run_once_on_start"])]
    pub missed_run_policy: String,
}

#[derive(Debug, clap::Args)]
pub struct ScheduleListArgs {
    /// Exact owner filter, e.g. assistant:alice or system:dreamer.
    #[arg(long, value_name = "OWNER")]
    pub owner: Option<String>,
}

#[derive(Debug, Subcommand)]
pub enum SkillCommand {
    /// Inspect and run the skill curator.
    #[command(subcommand)]
    Curator(SkillCuratorCommand),
}

#[derive(Debug, Subcommand)]
pub enum SkillCuratorCommand {
    /// Show skill lifecycle and snapshot state.
    Status,
    /// Run deterministic curation now.
    Run(SkillCuratorRunArgs),
    /// Exempt a skill from curator transitions and tool deletion.
    Pin {
        #[arg(value_name = "NAME")]
        name: String,
    },
    /// Clear a curator pin.
    Unpin {
        #[arg(value_name = "NAME")]
        name: String,
    },
    /// Restore an archived skill by name.
    Restore {
        #[arg(value_name = "NAME")]
        name: String,
    },
    /// Roll back the skill tree to a recorded snapshot.
    Rollback(SkillCuratorRollbackArgs),
}

#[derive(Debug, clap::Args)]
pub struct SkillCuratorRunArgs {
    /// Preview transitions without mutating files or DB state.
    #[arg(long)]
    pub dry_run: bool,
    /// Opt into guarded LLM consolidation planning for this run.
    #[arg(long)]
    pub consolidate: bool,
}

#[derive(Debug, clap::Args)]
pub struct SkillCuratorRollbackArgs {
    /// List available snapshots instead of restoring one.
    #[arg(long, conflicts_with = "id")]
    pub list: bool,
    /// Restore a specific snapshot id. Defaults to the newest prior snapshot.
    #[arg(long, value_name = "ID")]
    pub id: Option<String>,
}

#[derive(Debug, Subcommand)]
pub enum ConfigCommand {
    /// Show or save explicit image-generation spend policy.
    #[command(name = "image-spend")]
    ImageSpend(ImageSpendArgs),
    /// Export portable provider/model policy JSON without credentials.
    #[command(name = "export-policy")]
    ExportPolicy(ConfigExportPolicyArgs),
    /// Import portable provider/model policy JSON without credentials.
    #[command(name = "import-policy")]
    ImportPolicy(ConfigImportPolicyArgs),
}

#[derive(Debug, clap::Args)]
pub struct ImageSpendArgs {
    /// Save the reviewed JSON policy from this file.
    #[arg(long, value_name = "FILE")]
    pub save: Option<std::path::PathBuf>,
    /// Stable project ledger key required when saving.
    #[arg(long)]
    pub project_key: Option<String>,
}

#[derive(Debug, Subcommand)]
pub enum AccountCommand {
    /// Sign in to a FlyCockpit account using browser device authorization.
    Login(LoginArgs),
    /// Sign out of the active FlyCockpit account on this machine.
    Logout,
    /// Show the active FlyCockpit account and instance.
    Whoami,
}

#[derive(Debug, clap::Args)]
pub struct RemovedCommandArgs {
    /// Ignored old arguments. The command always prints the split-command pointer.
    #[arg(hide = true, trailing_var_arg = true, allow_hyphen_values = true)]
    pub rest: Vec<String>,
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
#[command(
    after_help = "Exit codes:\n  0  no failing checks\n  1  one or more doctor checks failed\n\nNetwork provider checks run by default; use --offline to skip DNS and HTTP."
)]
pub struct DoctorArgs {
    /// Directory to inspect (defaults to the current directory).
    pub path: Option<PathBuf>,

    /// Skip provider network checks. Static config, credential, git, and container checks still run.
    #[arg(long)]
    pub offline: bool,

    /// Emit the versioned, secret-safe dependency snapshot as JSON.
    #[arg(long)]
    pub dependencies_json: bool,
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

/// Invocation-scoped permission mode for `cockpit run` only.
/// Does not mutate session approval state.
#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
pub enum PermissionModeArg {
    /// Ask for every grant-or-ask surface (session default when omitted).
    Manual,
    /// Utility-model safety gate first; fail closed without a guard model.
    Auto,
    /// Fully unattended for grant-or-ask surfaces; hard gates still apply.
    Yolo,
}

impl From<PermissionModeArg> for crate::daemon::proto::ApprovalMode {
    fn from(value: PermissionModeArg) -> Self {
        match value {
            PermissionModeArg::Manual => crate::daemon::proto::ApprovalMode::Manual,
            PermissionModeArg::Auto => crate::daemon::proto::ApprovalMode::Auto,
            PermissionModeArg::Yolo => crate::daemon::proto::ApprovalMode::Yolo,
        }
    }
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

    /// Cockpit-specific: load an agent definition from an arbitrary file
    /// path. The file does not need to live in a standard configuration directory.
    #[arg(long, value_name = "PATH")]
    pub agent_file: Option<PathBuf>,

    /// Override the model: `provider/model-id`.
    #[arg(
        short,
        long,
        conflicts_with_all = ["continue_session", "session"]
    )]
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
    /// Repeatable; valid classes: command, path, mcp_tool, harness. Grants are never persisted.
    #[arg(long, value_name = "CLASS")]
    pub approve: Vec<crate::approval::store::GrantKind>,

    /// Fork instead of continuing in place.
    #[arg(long)]
    pub fork: bool,

    /// Output format.
    #[arg(long, value_enum, default_value_t = OutputFormat::Default)]
    pub format: OutputFormat,

    /// Emit newline-delimited JSON events. Hidden alias for `--format json`.
    #[arg(long, hide = true)]
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

    /// Maximum provider-dispatch reservations for this run (1..=10000).
    /// Omitted means unbounded. Zero is a usage error, never unbounded.
    #[arg(long, value_name = "TURNS", value_parser = parse_max_turns)]
    pub max_turns: Option<u32>,

    /// Wall-clock timeout in whole seconds from durable acceptance
    /// (1..=604800 = seven days). Converted to milliseconds for the daemon.
    /// Omitted means unbounded. Zero is a usage error, never unbounded.
    #[arg(long, value_name = "SECONDS", value_parser = parse_timeout_secs)]
    pub timeout: Option<u64>,

    /// Invocation-scoped permission mode for this run only
    /// (`manual` | `auto` | `yolo`). Omitted uses the session/default mode.
    /// Never mutates session approval state; concurrent runs may differ.
    #[arg(long = "permission-mode", value_enum, value_name = "MODE")]
    pub permission_mode: Option<PermissionModeArg>,
}

impl RunArgs {
    pub fn output_format(&self) -> OutputFormat {
        if self.json {
            OutputFormat::Json
        } else {
            self.format
        }
    }

    /// Immutable run bounds for `SendUserMessage`. Always `Some` for `cockpit run`.
    pub fn run_invocation_options(&self) -> crate::daemon::proto::RunInvocationOptions {
        crate::daemon::proto::RunInvocationOptions {
            max_turns: self.max_turns,
            timeout_ms: self.timeout.map(|secs| secs.saturating_mul(1000)),
            approval_mode: self.permission_mode.map(|m| m.into()),
        }
    }
}

fn parse_max_turns(raw: &str) -> Result<u32, String> {
    if raw.is_empty()
        || raw.contains(['+', '-', '.', 'e', 'E'])
        || !raw.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(
            "--max-turns must be a decimal integer in 1..=10000 (no signs, fractions, or suffixes)"
                .into(),
        );
    }
    let value: u32 = raw
        .parse()
        .map_err(|_| "--max-turns must be a decimal integer in 1..=10000".to_string())?;
    if !(1..=10_000).contains(&value) {
        return Err("--max-turns must be a decimal integer in 1..=10000".into());
    }
    Ok(value)
}

fn parse_timeout_secs(raw: &str) -> Result<u64, String> {
    if raw.is_empty()
        || raw.contains(['+', '-', '.', 'e', 'E'])
        || !raw.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(
            "--timeout must be a decimal integer number of seconds in 1..=604800 (no signs, fractions, or suffixes)"
                .into(),
        );
    }
    let value: u64 = raw.parse().map_err(|_| {
        "--timeout must be a decimal integer number of seconds in 1..=604800".to_string()
    })?;
    if !(1..=604_800).contains(&value) {
        return Err("--timeout must be a decimal integer number of seconds in 1..=604800".into());
    }
    // Checked millisecond conversion (must not overflow u64).
    value
        .checked_mul(1000)
        .ok_or_else(|| "--timeout millisecond conversion overflow".to_string())?;
    Ok(value)
}

// ---- invocation subcommands ----

#[derive(Debug, Subcommand)]
pub enum InvocationCommand {
    /// Print durable status for a run invocation.
    #[command(
        after_long_help = "Exit codes:\n  0  found active or terminal status\n  2  usage error\n  4  transport/protocol/auth/busy\n  5  authoritative InvocationNotFound"
    )]
    Status(InvocationStatusArgs),
    /// Request cancellation of a run invocation (idempotent).
    #[command(
        after_long_help = "Exit codes:\n  0  cancel result recorded\n  2  usage error\n  4  transport/protocol/auth/busy\n  5  authoritative InvocationNotFound"
    )]
    Cancel(InvocationCancelArgs),
}

#[derive(Debug, Clone, clap::Args)]
pub struct InvocationStatusArgs {
    /// Canonical lowercase hyphenated UUIDv4 client_submission_id.
    pub client_submission_id: String,

    /// Output format. There is no `--json` alias.
    #[arg(long, value_enum, default_value_t = OutputFormat::Default)]
    pub format: OutputFormat,
}

#[derive(Debug, Clone, clap::Args)]
pub struct InvocationCancelArgs {
    /// Canonical lowercase hyphenated UUIDv4 client_submission_id.
    pub client_submission_id: String,

    /// Output format. There is no `--json` alias.
    #[arg(long, value_enum, default_value_t = OutputFormat::Default)]
    pub format: OutputFormat,
}

// ---- agent subcommands ----

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum AgentScopeArg {
    Global,
    #[value(name = "workspace-private")]
    WorkspacePrivate,
    #[value(name = "workspace")]
    Workspace,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum AgentExecutionKindArg {
    Assistant,
    Coding,
    Computer,
}

impl From<AgentExecutionKindArg> for cockpit_proto::AgentInstallationExecutionKindV1 {
    fn from(value: AgentExecutionKindArg) -> Self {
        match value {
            AgentExecutionKindArg::Assistant => Self::Assistant,
            AgentExecutionKindArg::Coding => Self::Coding,
            AgentExecutionKindArg::Computer => Self::Computer,
        }
    }
}

#[derive(Debug, Subcommand)]
#[command(
    after_help = "Agent operation exit codes:\n  3  daemon choice required\n  4  acknowledgement required\n  5  primary slot unusable\n  6  optional slot unbound\n  7  rebind required\n  8  conflict"
)]
pub enum AgentCommand {
    /// Install a versioned agent definition through the daemon.
    Install {
        #[arg(value_name = "OWNER/REPO[@REV]:PATH")]
        source: String,
        /// Target scope. When omitted on an interactive terminal, Cockpit asks
        /// before contacting the daemon; non-interactive callers must supply it.
        #[arg(long, value_enum)]
        scope: Option<AgentScopeArg>,
        #[arg(long, value_name = "PATH")]
        workspace: Option<PathBuf>,
        /// Reuse this opaque operation key to replay an interrupted request.
        #[arg(long, value_name = "KEY")]
        operation_key: Option<String>,
        /// Bind only the first exact author-suggested compatible model.
        #[arg(long)]
        yes: bool,
    },
    /// Update an installed agent definition through the daemon.
    Update {
        #[arg(value_name = "INSTALLATION_ID")]
        installation_id: String,
        #[arg(long, value_name = "OWNER/REPO[@REV]:PATH")]
        source: String,
        #[arg(long, required = true)]
        replace: bool,
        #[arg(long, value_enum)]
        scope: Option<AgentScopeArg>,
        #[arg(long, value_name = "PATH")]
        workspace: Option<PathBuf>,
        #[arg(long, value_name = "KEY")]
        operation_key: Option<String>,
        /// Bind only the first exact author-suggested compatible model.
        #[arg(long)]
        yes: bool,
    },
    /// Bind a daemon-resolved installed agent slot.
    Bind {
        #[arg(value_name = "INSTALLATION_ID")]
        installation_id: String,
        #[arg(long, default_value = "primary")]
        slot: String,
        #[arg(long, value_enum)]
        scope: Option<AgentScopeArg>,
        #[arg(long, value_name = "PATH")]
        workspace: Option<PathBuf>,
        #[arg(long, value_name = "KEY")]
        operation_key: Option<String>,
        /// Bind only the first exact author-suggested compatible model.
        #[arg(long, conflicts_with_all = ["defer", "provider_profile", "model"])]
        yes: bool,
        /// Displayed daemon choice provider selector; never an opaque route handle.
        #[arg(
            long,
            value_name = "PROFILE",
            requires = "model",
            conflicts_with = "defer"
        )]
        provider_profile: Option<String>,
        /// Displayed daemon choice model selector; never a credential or route handle.
        #[arg(
            long,
            value_name = "MODEL",
            requires = "provider_profile",
            conflicts_with = "defer"
        )]
        model: Option<String>,
        /// Leave the requested slot unbound through the daemon continuation.
        #[arg(long, conflicts_with_all = ["yes", "provider_profile", "model"])]
        defer: bool,
    },
    /// Submit one daemon-issued agent binding choice.
    SubmitChoice {
        #[arg(value_name = "CONTINUATION_TOKEN")]
        continuation_token: String,
        #[arg(value_name = "CHOICE_ID", required_unless_present = "defer")]
        choice_id: Option<String>,
        /// Leave the selected slot unbound without exposing a provider route.
        #[arg(long, conflicts_with = "choice_id")]
        defer: bool,
    },
    /// Inspect one daemon-owned installed agent record.
    Inspect {
        #[arg(value_name = "INSTALLATION_ID")]
        installation_id: String,
        #[arg(long, value_enum)]
        scope: Option<AgentScopeArg>,
        #[arg(long, value_name = "PATH")]
        workspace: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// Create a new agent file.
    Create {
        #[arg(value_name = "NAME")]
        name: String,
        #[arg(long, value_enum, required = true)]
        scope: Option<AgentScopeArg>,
        #[arg(long, value_enum)]
        execution_kind: AgentExecutionKindArg,
        #[arg(long, default_value = "primary")]
        primary_slot: String,
        #[arg(long, value_name = "PATH")]
        workspace: Option<PathBuf>,
        #[arg(long, value_name = "KEY")]
        operation_key: Option<String>,
    },
    /// List all available agents (project + global + extended `agent_dirs`).
    List {
        #[arg(long, value_enum)]
        scope: Option<AgentScopeArg>,
        #[arg(long, value_name = "PATH")]
        workspace: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
}

// ---- providers / models ----

#[derive(Debug, Subcommand)]
pub enum ProvidersCommand {
    #[command(alias = "ls")]
    List,
    /// Add a provider using the terminal setup wizard.
    Add(ProviderAddArgs),
    /// Sign out of an OAuth-backed provider without deleting its config entry.
    Logout(ProviderLogoutArgs),
    /// Show vendor plan limits and quota for configured providers.
    Usage(ProvidersUsageArgs),
}

#[derive(Debug, clap::Args)]
pub struct ProviderAddArgs {
    /// Optional built-in provider template id to preselect.
    #[arg(value_name = "TEMPLATE")]
    pub template: Option<String>,
}

#[derive(Debug, clap::Args)]
pub struct ProviderLogoutArgs {
    /// Provider id to sign out.
    #[arg(value_name = "ID")]
    pub provider: String,
}

#[derive(Debug, clap::Args)]
pub struct ProvidersUsageArgs {
    /// Provider id to probe. Omit to probe every configured provider.
    #[arg(long, value_name = "ID")]
    pub provider: Option<String>,
}

#[derive(Debug, clap::Args)]
pub struct SetupArgs {
    /// Wizard id to run. Omit to choose from the registered wizard menu.
    #[arg(value_name = "WIZARD")]
    pub wizard: Option<String>,
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
    /// Internal one-shot diagnostics worker. It deliberately does not boot the
    /// normal daemon server, so it can report a database bootstrap failure.
    #[command(hide = true)]
    DiagnosticSnapshot {
        #[arg(long)]
        path: Option<std::path::PathBuf>,
        /// Explicit offline SQLite copy to inspect. Hidden worker use only.
        #[arg(long, hide = true)]
        database_snapshot: Option<std::path::PathBuf>,
        #[arg(long)]
        offline: bool,
        #[arg(long)]
        no_sandbox: bool,
    },
}

#[derive(Debug, clap::Args)]
#[command(after_help = "Exit codes:
  0   login completed
  1   network/auth/server failure, denied approval, or expired device code
  64  invalid command usage")]
pub struct LoginArgs {
    /// FlyCockpit server origin. HTTPS is required except for localhost development.
    #[arg(long, default_value = "https://app.flycockpit.dev", value_name = "URL")]
    pub server: String,

    /// Display name for this machine in FlyCockpit. Defaults to the hostname.
    #[arg(long, value_name = "DISPLAY_NAME")]
    pub name: Option<String>,

    /// Replace the currently logged-in FlyCockpit account without prompting.
    #[arg(long)]
    pub force: bool,

    /// Enable outbound remote access for this instance without prompting.
    #[arg(long, action = ArgAction::SetTrue, conflicts_with = "no_remote")]
    pub remote: bool,

    /// Disable outbound remote access for this instance without prompting.
    #[arg(long = "no-remote", action = ArgAction::SetTrue)]
    pub no_remote: bool,
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

    /// Send explicit live probes to learn endpoint and context-window metadata.
    #[arg(long)]
    pub deep: bool,

    /// Skip the deep-fetch money/cost confirmation prompt. Required for
    /// non-interactive deep fetches.
    #[arg(long)]
    pub yes: bool,

    /// Limit --deep to one model id within the selected provider set.
    #[arg(long, value_name = "MODEL_ID", requires = "deep")]
    pub model: Option<String>,
}

// ---- sessions ----

#[derive(Debug, Subcommand)]
pub enum SessionCommand {
    List(SessionListArgs),
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
        /// Confirm irreversible deletion. Required outside an interactive terminal.
        #[arg(long)]
        yes: bool,
    },
    /// Permanently delete ended sessions before an absolute date or relative duration such as 30d.
    Purge {
        /// Absolute YYYY-MM-DD date or relative duration such as 30d.
        #[arg(long, value_name = "WHEN")]
        before: String,
        /// Report matching sessions without deleting them.
        #[arg(long)]
        dry_run: bool,
        /// Confirm irreversible deletion. Required outside an interactive terminal.
        #[arg(long)]
        yes: bool,
    },
    /// Answer a pending question or approval interrupt.
    Answer(SessionAnswerArgs),
}

#[derive(Debug, Clone, clap::Args)]
pub struct SessionListArgs {
    /// Only list sessions owned by this assistant.
    #[arg(long, value_name = "NAME")]
    pub assistant: Option<String>,
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

    /// EXPLICIT LOCAL RAW EXPORT. Write the archive WITHOUT redaction — it will
    /// contain raw secrets (API keys, tokens, credentials, SSH material). This
    /// is the single unredacted export path and is local + CLI-only: the daemon
    /// RPC and the TUI export stay invariantly redacted. A stderr warning is
    /// printed on every use and `manifest.json` records `"redacted": false`.
    #[arg(long)]
    pub include_sensitive: bool,
}

#[derive(Debug, clap::Args)]
pub struct ImportArgs {
    pub file: PathBuf,
}

/// Scope toggle for `cockpit stats`.
#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
pub enum StatsProjectScope {
    /// The project rooted at the current working directory (default).
    Current,
    /// Every project recorded on this machine.
    All,
}

/// Range toggle for `cockpit stats`.
#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
pub enum StatsRangeArg {
    /// The last 7 days (default).
    #[value(name = "7d")]
    SevenDays,
    /// All recorded history.
    All,
}

/// Output format for `cockpit stats`.
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
    /// Print the bounded, redacted fresh-session system and project-guidance context.
    Context,
    /// Cockpit-specific: list recent tool calls that hard-failed
    /// (and optionally those that fired any recovery).
    FailedCalls(FailedCallsArgs),
}

#[derive(Debug, clap::Args)]
pub struct FailedCallsArgs {
    /// Only failures within the last N days. Default: 7.
    #[arg(long, default_value_t = 7)]
    pub days: u32,
    /// Only this tool name (e.g. `edit`, `bash`).
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

// ---- connect / init ----

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
    /// Import one package directory. This is equivalent to `--package <DIR>`.
    #[arg(
        value_name = "DIR",
        conflicts_with = "dir",
        conflicts_with = "package_path"
    )]
    pub package: Option<PathBuf>,
    /// Scan immediate child directories and import each package.
    #[arg(long, value_name = "DIR", conflicts_with = "package")]
    pub dir: Option<PathBuf>,
    /// Import one package directory.
    #[arg(
        long = "package",
        value_name = "DIR",
        conflicts_with = "dir",
        conflicts_with = "package"
    )]
    pub package_path: Option<PathBuf>,
    /// Override the derived identifier for single-package import.
    #[arg(long, value_name = "IDENTIFIER", conflicts_with = "dir")]
    pub id: Option<String>,
    /// Register exact local paths instead of Git-managed Cockpit clones.
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

// ---- MCP ----

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
    use std::collections::BTreeSet;

    const README: &str = include_str!("../README.md");

    fn assert_no_internal_jargon(label: &str, text: &str) {
        for needle in ["GOALS", "§", "design notes", "repair catalog", "ralph"] {
            assert!(
                !text.contains(needle),
                "{label} contains internal jargon `{needle}`:\n{text}"
            );
        }
    }

    fn collect_visible_help(mut command: clap::Command, path: Vec<String>, out: &mut Vec<String>) {
        out.push(format!(
            "{}\n{}",
            path.join(" "),
            command.render_long_help()
        ));

        let subcommands: Vec<String> = command
            .get_subcommands()
            .filter(|subcommand| !subcommand.is_hide_set())
            .map(|subcommand| subcommand.get_name().to_string())
            .collect();

        for name in subcommands {
            let Some(subcommand) = command.find_subcommand_mut(&name) else {
                continue;
            };
            let mut subpath = path.clone();
            subpath.push(name);
            collect_visible_help(subcommand.clone(), subpath, out);
        }
    }

    fn markdown_section<'a>(source: &'a str, heading: &str, next_heading: &str) -> &'a str {
        let start = source
            .find(heading)
            .unwrap_or_else(|| panic!("missing {heading}"));
        let rest = &source[start..];
        let end = rest
            .find(next_heading)
            .unwrap_or_else(|| panic!("missing {next_heading} after {heading}"));
        &rest[..end]
    }

    fn common_command_cells() -> BTreeSet<String> {
        markdown_section(README, "## Common Commands", "## Configuration")
            .lines()
            .filter_map(|line| {
                let trimmed = line.trim();
                if !trimmed.starts_with("| `") {
                    return None;
                }
                let rest = trimmed.trim_start_matches("| `");
                let end = rest.find('`')?;
                Some(rest[..end].to_string())
            })
            .collect()
    }

    fn quickstart_shell_commands() -> Vec<Vec<&'static str>> {
        let quickstart = markdown_section(README, "## Quick Start", "## Common Commands");
        let mut in_shell = false;
        let mut commands = Vec::new();
        for line in quickstart.lines() {
            let trimmed = line.trim();
            if trimmed == "```sh" {
                in_shell = true;
                continue;
            }
            if trimmed == "```" {
                in_shell = false;
                continue;
            }
            if in_shell && trimmed.starts_with("cockpit") {
                commands.push(trimmed.split_whitespace().collect());
            }
        }
        commands
    }

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
    fn export_include_generated_flag_parses() {
        let cli =
            Cli::try_parse_from(["cockpit", "export", "abc123", "--include-generated"]).unwrap();
        match cli.command {
            Some(Command::Export(args)) => {
                assert_eq!(args.session_id.as_deref(), Some("abc123"));
                assert!(args.include_generated);
            }
            other => panic!("expected export command, got {other:?}"),
        }
    }

    #[test]
    fn export_include_sensitive_flag_parses() {
        // `--include-sensitive` is the explicit LOCAL raw-export opt-in: it
        // parses on `cockpit export` and sets the typed flag; a default export
        // leaves it false.
        let cli =
            Cli::try_parse_from(["cockpit", "export", "abc123", "--include-sensitive"]).unwrap();
        match cli.command {
            Some(Command::Export(args)) => {
                assert_eq!(args.session_id.as_deref(), Some("abc123"));
                assert!(
                    args.include_sensitive,
                    "--include-sensitive must set the flag"
                );
            }
            other => panic!("expected export command, got {other:?}"),
        }

        // Absent by default: the non-bypassable redacted path.
        let cli = Cli::try_parse_from(["cockpit", "export", "abc123"]).unwrap();
        match cli.command {
            Some(Command::Export(args)) => assert!(
                !args.include_sensitive,
                "the default export must leave include_sensitive false"
            ),
            other => panic!("expected export command, got {other:?}"),
        }

        // No other subcommand accepts the raw opt-in — it is export-local.
        assert!(
            Cli::try_parse_from(["cockpit", "import", "some.zip", "--include-sensitive"]).is_err(),
            "`--include-sensitive` must be rejected outside `cockpit export`"
        );
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
                assert_eq!(args.path, Some(PathBuf::from("/tmp/example")));
                assert!(!args.offline);
            }
            other => panic!("expected doctor command, got {other:?}"),
        }

        let cli = Cli::try_parse_from(["cockpit", "doctor", "--offline"]).unwrap();
        match cli.command {
            Some(Command::Doctor(args)) => {
                assert!(args.path.is_none());
                assert!(args.offline);
            }
            other => panic!("expected doctor command, got {other:?}"),
        }
    }

    #[test]
    fn provider_add_command_parses_optional_template() {
        let cli = Cli::try_parse_from(["cockpit", "provider", "add", "openai"]).unwrap();
        match cli.command {
            Some(Command::Provider(ProvidersCommand::Add(args))) => {
                assert_eq!(args.template.as_deref(), Some("openai"));
            }
            other => panic!("expected providers add command, got {other:?}"),
        }
    }

    #[test]
    fn provider_logout_command_parses_provider_id() {
        let cli = Cli::try_parse_from(["cockpit", "provider", "logout", "grok-oauth"]).unwrap();
        match cli.command {
            Some(Command::Provider(ProvidersCommand::Logout(args))) => {
                assert_eq!(args.provider, "grok-oauth");
            }
            other => panic!("expected provider logout command, got {other:?}"),
        }
    }

    #[cfg(feature = "remote")]
    #[test]
    fn account_tree_parses() {
        let cli = Cli::try_parse_from([
            "cockpit",
            "account",
            "login",
            "--server",
            "https://app.flycockpit.dev",
            "--force",
            "--no-remote",
        ])
        .unwrap();
        match cli.command {
            Some(Command::Account(AccountCommand::Login(args))) => {
                assert_eq!(args.server, "https://app.flycockpit.dev");
                assert!(args.force);
                assert!(args.no_remote);
                assert!(!args.remote);
            }
            other => panic!("expected account login command, got {other:?}"),
        }

        let cli = Cli::try_parse_from(["cockpit", "account", "logout"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Command::Account(AccountCommand::Logout))
        ));

        let cli = Cli::try_parse_from(["cockpit", "account", "whoami"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Command::Account(AccountCommand::Whoami))
        ));
    }

    #[cfg(not(feature = "remote"))]
    #[test]
    fn local_release_rejects_remote_command_surface() {
        for command in ["account", "sync", "connect", "login", "logout", "whoami"] {
            assert!(
                Cli::try_parse_from(["cockpit", command]).is_err(),
                "local release unexpectedly exposed `{command}`"
            );
        }
    }

    #[cfg(feature = "remote")]
    #[test]
    fn provider_aliases_parse() {
        for root in ["provider", "providers", "auth"] {
            let cli = Cli::try_parse_from(["cockpit", root, "list"]).unwrap();
            assert!(matches!(
                cli.command,
                Some(Command::Provider(ProvidersCommand::List))
            ));

            let cli =
                Cli::try_parse_from(["cockpit", root, "usage", "--provider", "openai"]).unwrap();
            match cli.command {
                Some(Command::Provider(ProvidersCommand::Usage(args))) => {
                    assert_eq!(args.provider.as_deref(), Some("openai"));
                }
                other => panic!("expected provider usage command, got {other:?}"),
            }

            let cli = Cli::try_parse_from(["cockpit", root, "logout", "codex-oauth"]).unwrap();
            match cli.command {
                Some(Command::Provider(ProvidersCommand::Logout(args))) => {
                    assert_eq!(args.provider, "codex-oauth");
                }
                other => panic!("expected provider logout command, got {other:?}"),
            }
        }
    }

    #[test]
    fn removed_login_stub_parses_but_is_hidden_from_help() {
        let cli = Cli::try_parse_from(["cockpit", "login", "--force"]).unwrap();
        assert!(matches!(cli.command, Some(Command::Login(_))));

        let help = Cli::command().render_help().to_string();
        // The account surface is remote-only: the local artifact must not
        // advertise it, and the remote build must.
        #[cfg(feature = "remote")]
        assert!(help.contains("account"), "{help}");
        #[cfg(not(feature = "remote"))]
        assert!(!help.contains("account"), "{help}");
        assert!(help.contains("provider"), "{help}");
        assert!(!help.contains("  login"), "{help}");
        assert!(!help.contains("  logout"), "{help}");
        assert!(!help.contains("  whoami"), "{help}");
    }

    #[test]
    fn help_output_has_no_literal_markdown() {
        let mut help_pages = Vec::new();
        collect_visible_help(Cli::command(), vec!["cockpit".to_string()], &mut help_pages);
        for page in help_pages {
            for marker in ["**", "`*", "*`"] {
                assert!(
                    !page.contains(marker),
                    "clap help contains literal Markdown emphasis marker `{marker}`:\n{page}"
                );
            }
        }
    }

    #[test]
    fn help_copy_no_internal_jargon() {
        let mut help_pages = Vec::new();
        collect_visible_help(Cli::command(), vec!["cockpit".to_string()], &mut help_pages);
        for page in help_pages {
            assert_no_internal_jargon("clap help", &page);
        }

        for template in crate::providers::TEMPLATES {
            if let Some(hint) = template.hint {
                assert_no_internal_jargon(template.id, hint);
            }
        }

        assert_no_internal_jargon("README", README);
        assert_no_internal_jargon("providers doc", include_str!("../docs/providers.md"));
    }

    /// AC6. Checked docs search: every cited surface must say that trusted
    /// inference may be raw, untrusted inference is redacted, exports and
    /// client display stay redacted regardless of trust, and neither harness
    /// mode nor locality implies trust.
    #[test]
    fn trust_and_mode_docs_are_orthogonal() {
        const PROVIDERS_DOC: &str = include_str!("../docs/providers.md");
        const SCRUB_SITES: &str = include_str!("../docs/redaction-scrub-sites.md");

        for (label, text) in [("README", README), ("providers doc", PROVIDERS_DOC)] {
            let lowered = text.to_ascii_lowercase();
            assert!(
                lowered.contains("inference requests to a trusted model may be sent raw")
                    || lowered.contains("inference requests to a `trusted` model may be sent raw"),
                "{label} must say trusted inference may be raw"
            );
            assert!(
                lowered.contains("secrets and environment values"),
                "{label} must name what a trusted provider receives"
            );
            assert!(
                lowered.contains("stay redacted regardless of trust"),
                "{label} must keep the export/display boundary explicit"
            );
            assert!(
                lowered.contains("locality is descriptive and never implies trust"),
                "{label} must state that locality never implies trust"
            );
            assert!(
                lowered.contains("never changes provider eligibility, data custody"),
                "{label} must deny mode-implies-custody"
            );

            // Negative half: no surface may claim the inverse implication.
            // These are the concrete "X implies trust" shapes the copy must
            // never contain, checked without a tautological `|| contains(..)`.
            for forbidden in [
                "local models are trusted",
                "local providers are trusted",
                "a local model is trusted",
                "local endpoints are trusted",
                "self-hosted models are trusted",
                "frontier models are trusted",
                "frontier implies trust",
                "local implies trust",
                "locality implies trust",
                "mode implies trust",
                "defensive models are untrusted",
            ] {
                assert!(
                    !lowered.contains(forbidden),
                    "{label} must not claim `{forbidden}`"
                );
            }
            // And trust must not be described as a blanket redaction switch:
            // it governs inference custody, not the export/display boundary.
            assert!(
                !lowered.contains("trusted models disable outbound redaction"),
                "{label} must not describe trust as a blanket redaction switch"
            );
        }

        // The all-export boundary stays documented and unqualified by trust.
        assert!(
            SCRUB_SITES.contains(
                "export payloads scrub session/config/MCP/file content regardless of model trust"
            ),
            "the all-export scrub boundary must stay documented"
        );
    }

    #[test]
    fn help_copy_readme_covers_top_level_commands() {
        let cells = common_command_cells();
        let mut missing = Vec::new();
        for subcommand in Cli::command()
            .get_subcommands()
            .filter(|subcommand| !subcommand.is_hide_set())
        {
            let name = subcommand.get_name();
            if !cells.iter().any(|cell| {
                cell == &format!("cockpit {name}") || cell.starts_with(&format!("cockpit {name} "))
            }) {
                missing.push(name.to_string());
            }
        }

        assert!(missing.is_empty(), "README table missing: {missing:?}");
    }

    #[test]
    fn help_copy_quickstart_matches_onboarding_commands() {
        let quickstart = markdown_section(README, "## Quick Start", "## Common Commands");
        let ordered = [
            "Install Cockpit",
            "cockpit",
            "workspace trust",
            "provider wizard",
            "model wizard",
            "first message",
        ];
        let mut cursor = 0;
        for needle in ordered {
            let Some(found) = quickstart[cursor..].find(needle) else {
                panic!("quickstart missing ordered step `{needle}`:\n{quickstart}");
            };
            cursor += found + needle.len();
        }

        assert!(quickstart.contains("cockpit account"), "{quickstart}");
        assert!(quickstart.contains("cockpit provider"), "{quickstart}");

        let commands = quickstart_shell_commands();
        assert!(!commands.is_empty(), "quickstart has cockpit commands");
        for command in commands {
            Cli::try_parse_from(command.clone()).unwrap_or_else(|err| {
                panic!("quickstart command does not parse: {command:?}\n{err}")
            });
        }
    }

    #[test]
    fn run_help_returns_clap_help() {
        let run = Cli::command()
            .try_get_matches_from(["cockpit", "run", "--help"])
            .unwrap_err();
        assert_eq!(run.kind(), ErrorKind::DisplayHelp);
    }

    #[test]
    fn fetch_models_positional_provider_parses() {
        let cli = Cli::try_parse_from(["cockpit", "fetch-models", "codex-oauth"]).unwrap();
        match cli.command {
            Some(Command::FetchModels(args)) => {
                assert_eq!(args.provider_arg.as_deref(), Some("codex-oauth"));
                assert!(args.provider.is_none());
                assert!(!args.deep);
                assert!(!args.yes);
                assert!(args.model.is_none());
            }
            other => panic!("expected fetch-models command, got {other:?}"),
        }
    }

    #[test]
    fn plain_fetch_never_probes() {
        let cli = Cli::try_parse_from(["cockpit", "fetch-models", "openai"]).unwrap();
        match cli.command {
            Some(Command::FetchModels(args)) => {
                assert!(!args.deep);
                assert!(!args.yes);
                assert!(args.model.is_none());
            }
            other => panic!("expected fetch-models command, got {other:?}"),
        }
    }

    #[test]
    fn deepfetch_cli_requires_explicit_flag() {
        let cli = Cli::try_parse_from([
            "cockpit",
            "fetch-models",
            "--deep",
            "--yes",
            "openai",
            "--model",
            "gpt-5-mini",
        ])
        .unwrap();
        match cli.command {
            Some(Command::FetchModels(args)) => {
                assert!(args.deep);
                assert!(args.yes);
                assert_eq!(args.provider_arg.as_deref(), Some("openai"));
                assert_eq!(args.model.as_deref(), Some("gpt-5-mini"));
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
    fn invalid_run_invocation_returns_clap_error() {
        let run = Cli::try_parse_from(["cockpit", "run", "--definitely-not-a-flag"]).unwrap_err();
        assert_eq!(run.kind(), ErrorKind::UnknownArgument);
    }

    fn parse_run(args: &[&str]) -> RunArgs {
        match Cli::try_parse_from(args).unwrap().command {
            Some(Command::Run(args)) => args,
            other => panic!("expected run command, got {other:?}"),
        }
    }

    #[test]
    fn run_json_flag_reconciled() {
        let args = parse_run(&["cockpit", "run", "hi", "--format", "json"]);
        assert_eq!(args.message, ["hi"]);
        assert_eq!(args.output_format(), OutputFormat::Json);

        let args = parse_run(&["cockpit", "run", "hi", "--json"]);
        assert_eq!(args.message, ["hi"]);
        assert_eq!(args.output_format(), OutputFormat::Json);

        let mut cmd = Cli::command();
        let help = cmd
            .find_subcommand_mut("run")
            .unwrap()
            .render_long_help()
            .to_string();
        assert!(help.contains("--format"), "{help}");
        assert!(!help.contains("--json"), "{help}");
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
    fn run_model_conflicts_with_session_resume_flags() {
        let session = uuid::Uuid::new_v4().to_string();
        for args in [
            vec![
                "cockpit",
                "run",
                "hi",
                "--model",
                "p/m",
                "--continue-session",
            ],
            vec![
                "cockpit",
                "run",
                "hi",
                "--model",
                "p/m",
                "--session",
                session.as_str(),
            ],
        ] {
            let error = Cli::try_parse_from(args).unwrap_err();
            assert_eq!(error.kind(), ErrorKind::ArgumentConflict);
        }
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
