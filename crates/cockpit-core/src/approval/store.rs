//! Approval-decision store (sandboxing part 1, §2).
//!
//! Records grants so a future access skips the prompt. Grant kinds cover
//! command-shape key (normalized argv[0], subcommand, and option names), path (an absolute path or
//! prefix, for part 2's native confinement), and external MCP tool keys
//! (`server/tool`) across four
//! scopes:
//!
//! - [`Once`](Scope::Once) — never stored.
//! - [`Session`](Scope::Session) — session DB (`approval_grants`,
//!   migration 0011); survives for the session's lifetime.
//! - [`Project`](Scope::Project) — machine-local hashed-cwd config dir, in
//!   `approvals.json`; survives daemon restarts; applies to any session
//!   whose cwd resolves into the same project root.
//! - [`Global`](Scope::Global) — user-level cockpit config dir, in
//!   `approvals.json`; survives restarts; applies everywhere.
//!
//! Persistence honors cockpit's existing config discovery
//! ([`crate::config::dirs`], [`crate::git::find_worktree_root`]) — no new
//! location scheme. Project/Global are plain JSON files written atomically
//! (a fresh owner-only exclusive temp + fsync + an identity-verified
//! rename + directory fsync) under a cross-process lock bound to one
//! verified lock object; Session lives in SQLite. A corrupt or unreadable
//! `approvals.json` fails closed (issue #297): the corrupt bytes are
//! quarantined for diagnosis — copied aside to a fresh owner-only file,
//! never deleted, never overwriting, never touching the live path — and
//! every read fails closed with a repair-oriented error. That covers the
//! decision-boundary health gate and every grant/reject lookup alike, so
//! corruption observed at any point in a decision refuses it, rather than
//! silently dropping every standing allow/reject entry. A quarantine copy
//! from an earlier detection keeps every read failed closed until the
//! store is repaired — a live path that is missing, and an approvals
//! directory whose residue status cannot be established, are both read
//! as "unrepaired", never as "no approval state" — quarantine always
//! preserves exactly the bytes that failed validation (copied aside to a
//! fresh owner-only file, never deleted, never overwriting, never
//! touching the live path), and every successful read enforces the
//! owner-only posture on the store it consumed: a store whose
//! permissions cannot be inspected or tightened to owner-only is
//! refused, never consumed. Every pathname effect on store state is
//! identity-guarded through a held handle and proof-bound at the moment
//! it takes effect: the staged temp is renamed into place only while
//! its name still refers to the object this process wrote and synced —
//! and the publish is reported successful only when the installed live
//! entry is then proven, through the held handle, to be that exact
//! object, so a staged-name substitution installs nothing silently; the
//! lock is acquired and proven at the publication boundary (both sides
//! of the rename) only while its name still refers to the object this
//! process locked; and a failed write's partial copy is removed only
//! while its name still refers to the object this process created, with
//! the removal itself proven after the act through the held handle — so
//! a replacement object at a known pathname is never consumed,
//! installed, or silently destroyed.
//!
//! ## Wrappers are never persisted (priority #1)
//!
//! A wrapper/eval command (§1) carries dynamic behavior the classifier
//! can't bound, so [`record_command`] **rejects** any attempt to store
//! one at a non-`Once` scope with [`StoreError::WrapperNotPersistable`].
//! Wrappers re-prompt every run.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{Context, Result};
use rusqlite::OptionalExtension;
use serde::{Deserialize, Serialize, Serializer};

use crate::approval::classify::{ApprovalKey, RiskTier};
use crate::config::extended::{ApprovalPolicyConfig, ApprovalPolicyScope};
use crate::daemon::session_worker::SessionConfigHandle;
use crate::db::Db;
use crate::tools::shell_sandbox::SandboxPathAccess;

pub use cockpit_db::wire::GrantKind;

/// The four approval scopes the user chose. Ordered narrowest→widest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// This invocation only; never stored.
    Once,
    /// All invocations in the current session (session DB).
    Session,
    /// All sessions whose cwd resolves into this project (machine-local
    /// hashed-cwd config dir).
    Project,
    /// All sessions in all projects (user-level config dir).
    Global,
}

/// Bounded, reusable image-generation approval capability. It deliberately
/// excludes prompt and output-stem identity: a new request may reuse a grant
/// only when it is no broader than every stored authority bound.
#[derive(Debug, Clone, Copy)]
pub struct ImageGenerationGrantBounds<'a> {
    pub destination_binding_digest: &'a str,
    pub output_path_authority: &'a str,
    pub reference_egress: bool,
    pub fanout: u32,
    pub total_outputs: u32,
    pub cost_maximum: Option<u64>,
}

impl Scope {
    /// Lowercase wire/export label for this scope. Used by the `bash`
    /// tool_call event's `sandbox.approval_scope_recorded` field.
    pub fn as_str(self) -> &'static str {
        match self {
            Scope::Once => "once",
            Scope::Session => "session",
            Scope::Project => "project",
            Scope::Global => "global",
        }
    }

    pub fn rank(self) -> u8 {
        match self {
            Scope::Once => 0,
            Scope::Session => 1,
            Scope::Project => 2,
            Scope::Global => 3,
        }
    }

    pub fn within(self, max: Scope) -> bool {
        self.rank() <= max.rank()
    }
}

impl From<ApprovalPolicyScope> for Scope {
    fn from(value: ApprovalPolicyScope) -> Self {
        match value {
            ApprovalPolicyScope::Once => Scope::Once,
            ApprovalPolicyScope::Session => Scope::Session,
            ApprovalPolicyScope::Project => Scope::Project,
            ApprovalPolicyScope::Global => Scope::Global,
        }
    }
}

/// A persisted loop-guard verdict for an exact call signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoopVerdict {
    /// Always run the repeat without prompting.
    Accept,
    /// Always block the repeat (guidance error) without prompting.
    Reject,
}

impl LoopVerdict {
    fn as_str(self) -> &'static str {
        match self {
            LoopVerdict::Accept => "accept",
            LoopVerdict::Reject => "reject",
        }
    }
}

/// The polarity of a command/path grant: an **allow** (the original
/// "remembered" grant — skip the prompt and run) or a **reject** (the
/// mirror — auto-deny the future attempt without prompting). Persisted in
/// the session DB's `approval_grants.verdict` column and as the
/// `commands`/`paths` vs `commands_reject`/`paths_reject` JSON sets. A key
/// is never both: the recorder clears the opposite polarity across every
/// reachable scope before writing (mutual exclusivity, enforced at record
/// time so query time needs no precedence rule).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    Allow,
    Reject,
}

impl Verdict {
    fn as_str(self) -> &'static str {
        match self {
            Verdict::Allow => "allow",
            Verdict::Reject => "reject",
        }
    }

    /// The opposite polarity — the one a record clears before writing.
    fn opposite(self) -> Verdict {
        match self {
            Verdict::Allow => Verdict::Reject,
            Verdict::Reject => Verdict::Allow,
        }
    }
}

/// Errors the store surfaces to callers.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// Attempted to persist a wrapper/eval command at a non-`Once` scope.
    /// Wrappers can only ever be approved `Once` (§2, priority #1).
    #[error("wrapper command `{0}` cannot be remembered; only one-time approval is allowed")]
    WrapperNotPersistable(String),
    /// `Scope::Once` was passed to a record call. `Once` is never stored;
    /// the caller should simply not record it.
    #[error("`Once` scope is never persisted")]
    OnceNotPersistable,
    /// Harness grants are session-only; persistent allow is stored on the
    /// harness config itself as `always_allow`.
    #[error("harness grants can only be stored at session scope")]
    HarnessSessionScopeOnly,
    /// Image-generation grants are once/session/project only — global scope
    /// is unrepresentable in the schema and rejected by the API.
    #[error("image-generation grants cannot be stored at global scope")]
    ImageGenerationNoGlobalScope,
    /// No project root could be resolved for a `Project`-scope grant
    /// (the cwd isn't inside a git worktree).
    #[error("no project root for the current directory; cannot store a project grant")]
    NoProjectRoot,
    /// An I/O / serialization failure while reading or writing a grant.
    #[error(transparent)]
    Io(#[from] anyhow::Error),
}

/// On-disk command allow record. The key stays coarse (`program` + first
/// subcommand) because per-flag keys would turn every flag combination into a
/// separate prompt. Instead, the grant records the tier shown to the user and
/// later checks recompute the invocation tier against it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CommandGrantRecord {
    #[serde(rename = "riskTier")]
    risk_tier: String,
}

impl CommandGrantRecord {
    fn new(tier: RiskTier) -> Self {
        Self {
            risk_tier: tier.as_str().to_string(),
        }
    }

    fn tier(&self) -> Option<RiskTier> {
        RiskTier::from_policy_key(&self.risk_tier)
    }
}

/// On-disk shape of a project/global `approvals.json`. Sorted maps/sets keep
/// the file stable (no spurious diffs) and dedup automatically.
#[derive(Debug, Default, Serialize, Deserialize)]
struct ApprovalsFile {
    /// Command-key allow grants, as storage strings (`"gh pr"`, `"ls"`)
    /// mapped to the tier shown when the grant was issued.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    commands: BTreeMap<String, CommandGrantRecord>,
    /// Path allow grants, as absolute path / prefix strings mapped to access mode.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    paths: BTreeMap<String, SandboxPathAccess>,
    /// External MCP tool allow grants, keyed by escaped `server/tool`.
    #[serde(
        rename = "mcpTools",
        default,
        skip_serializing_if = "BTreeSet::is_empty"
    )]
    mcp_tools: BTreeSet<String>,
    /// Command-key **reject** grants — the allow set's mirror. A key here
    /// auto-denies a future attempt without re-prompting. Mutually exclusive
    /// with `commands` for the same key (the recorder clears the other
    /// polarity first), so a key is never in both.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    commands_reject: BTreeSet<String>,
    /// Path **reject** grants — the `paths` map's mirror. A path here
    /// auto-denies out-of-cwd access without re-prompting. The access value
    /// is retained for the unified persisted shape; reject matching ignores it.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    paths_reject: BTreeMap<String, SandboxPathAccess>,
    /// External MCP tool **reject** grants — the allow set's mirror.
    #[serde(
        rename = "mcpToolsReject",
        default,
        skip_serializing_if = "BTreeSet::is_empty"
    )]
    mcp_tools_reject: BTreeSet<String>,
    /// Loop-guard always-accept rules, keyed by call signature (a hash of
    /// tool name + canonical `wire_input`; see [`GrantStore::loop_signature`]).
    /// A signature here auto-accepts a back-to-back repeat of that exact
    /// call without re-prompting.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    loop_accept: BTreeSet<String>,
    /// Loop-guard always-reject rules, keyed by the same call signature.
    /// A signature here auto-rejects the repeat with the guidance error.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    loop_reject: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectivePathGrant {
    pub path: PathBuf,
    pub access: SandboxPathAccess,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommandGrant {
    pub scope: Scope,
    pub granted_tier: RiskTier,
}

/// The grant store. Holds the session DB handle (for Session scope) and
/// the resolved cwd + project root + global config dir (for Project /
/// Global scope). Cheap to build per query; the DB handle is an `Arc`
/// clone.
pub struct GrantStore {
    db: Db,
    session_id: uuid::Uuid,
    /// Session/project cwd used as the explicit base for relative path
    /// grants. This must not fall back to the daemon process cwd.
    cwd: PathBuf,
    /// Resolved project root for the session cwd, if any. Project-scope
    /// usability is still gated by workspace trust against
    /// `<root>/.cockpit`; the approvals file itself lives outside the repo.
    project_root: Option<PathBuf>,
    /// Machine-local approvals dir for the resolved project root.
    project_approvals_dir: Option<PathBuf>,
    /// User-level cockpit config dir for `Global`-scope grants. Resolved
    /// once; `None` only if no home/data dir can be located.
    global_dir: Option<PathBuf>,
    /// The session's held config, read live for the approval policy. This is
    /// the session-scoped [`SessionConfigHandle`] seam — the policy is read
    /// from it per call (in-memory, no disk) so a policy change on a live
    /// session takes effect without rebuilding the store, and resolution is
    /// trust-aware (the handle is fed by the daemon's `ConfigSource`, not a
    /// bare per-cwd disk load).
    config: SessionConfigHandle,
    /// The last approval policy that passed validation. A malformed policy on
    /// re-read is rejected and this value is returned instead, so an
    /// unreadable/invalid policy can never fall open to a more permissive
    /// outcome than the last known good one (security requirement).
    last_good_policy: Mutex<ApprovalPolicyConfig>,
}

/// Whether an approval policy is well-formed enough to adopt. Scope *values*
/// are already enum-validated at parse time; the only closed-domain **keys**
/// are the risk-tier caps (`riskMaxScope`). An unrecognized risk key silently
/// drops the cap the user intended, which would *widen* the allowed scope — a
/// fall-open. A policy carrying one is therefore treated as malformed so the
/// last good policy is kept instead. Dangerous-flag rules are also fail-closed:
/// their target tier must parse through the same closed tier parser and their
/// flag list must be non-empty. Program/command keys are an open domain (any
/// command name) and are not validated.
fn approval_policy_is_valid(policy: &ApprovalPolicyConfig) -> bool {
    policy
        .risk_max_scope
        .keys()
        .all(|key| RiskTier::from_policy_key(key).is_some())
        && policy
            .dangerous_flags
            .values()
            .all(|rule| !rule.flags.is_empty() && RiskTier::from_policy_key(&rule.tier).is_some())
}

impl GrantStore {
    /// Build a store for a session at `cwd`. Resolves the project root
    /// (via [`crate::git::find_worktree_root`], the same resolution the
    /// rest of the app uses) and the global config dir up front. The cwd is
    /// retained as the explicit base for any relative path grant key.
    /// `config` is the session's held [`SessionConfigHandle`]: the store reads
    /// the approval policy from it live (no per-call disk read) instead of
    /// snapshotting it at construction. Session-scoped construction passes the
    /// worker's live handle; turn-time tool contexts pass `ToolCtx.config`. A
    /// standalone/no-session caller must pass an explicitly-resolved handle
    /// (e.g. [`SessionConfigHandle::detached`]) — there is no implicit,
    /// silently-permissive default policy source.
    pub fn new(db: Db, session_id: uuid::Uuid, cwd: PathBuf, config: SessionConfigHandle) -> Self {
        let project_root = crate::git::find_worktree_root(&cwd)
            .filter(|root| crate::config::trust::project_config_allowed(&root.join(".cockpit")));
        let project_approvals_dir = project_root.as_deref().and_then(project_approvals_dir);
        let global_dir = global_approvals_dir();
        // Seed the last-good policy from the handle's current (already
        // trust-aware, in-memory) policy if it is well-formed; otherwise the
        // built-in default baseline. There is no prior "good" value to keep at
        // construction, so this never reads disk and never falls open beyond
        // the built-in defaults.
        let initial = config.extended().approval_policy;
        let last_good_policy = Mutex::new(if approval_policy_is_valid(&initial) {
            initial
        } else {
            ApprovalPolicyConfig::default()
        });
        Self {
            db,
            session_id,
            cwd,
            project_root,
            project_approvals_dir,
            global_dir,
            config,
            last_good_policy,
        }
    }

    /// Session cwd used as the explicit base for relative path grants.
    pub fn cwd(&self) -> &Path {
        &self.cwd
    }

    /// The effective approval policy, read **live** from the session's held
    /// config on every call (in-memory — no disk read). A policy change made
    /// during the session is therefore observed without rebuilding the store.
    ///
    /// If the live policy is malformed (see [`approval_policy_is_valid`]) the
    /// last good policy is returned and retained instead — an invalid policy
    /// never falls open to a more permissive outcome (security requirement).
    /// A single approval decision reads this once at the start, so a change
    /// landing mid-decision never re-evaluates an in-flight prompt.
    pub fn configs(
        &self,
    ) -> (
        crate::config::extended::ExtendedConfig,
        crate::config::providers::ProvidersConfig,
    ) {
        self.config.configs()
    }

    pub fn approval_policy(&self) -> ApprovalPolicyConfig {
        let candidate = self.config.extended().approval_policy;
        let mut last_good = self
            .last_good_policy
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if approval_policy_is_valid(&candidate) {
            *last_good = candidate.clone();
            candidate
        } else {
            tracing::warn!(
                session_id = %self.session_id,
                "approval policy is malformed on re-read; keeping the last good policy (not falling open)"
            );
            last_good.clone()
        }
    }

    /// Durable scopes where a path grant can actually be recorded for this
    /// store. `Once` is intentionally absent: path grants are durable policy.
    pub fn recordable_path_scopes(&self) -> Vec<Scope> {
        let mut scopes = vec![Scope::Session];
        if self.project_root.is_some() && self.project_approvals_dir.is_some() {
            scopes.push(Scope::Project);
        }
        if self.global_dir.is_some() {
            scopes.push(Scope::Global);
        }
        scopes
    }

    /// Fail-closed health gate over the approvals files (issue #297),
    /// checked at approval-decision boundaries before any grant/reject
    /// lookup. A missing store file with no quarantine residue is the
    /// normal first-run state (healthy). A corrupt or unreadable file is
    /// quarantined by the load and fails closed with a repair-oriented
    /// error — a corrupt `approvals.json` can never silently drop standing
    /// rejects and proceed as if nothing were saved. The gate also refuses
    /// while a quarantine copy from an earlier detection is still present
    /// (the store has not been repaired yet), including one left by
    /// another process.
    ///
    /// Every lookup below this gate consumes the same fail-closed load, so
    /// corruption that lands between the gate and a decision's lookup —
    /// or a quarantine that happened before this gate ran — still refuses
    /// that decision: no read of the store ever resolves to empty approval
    /// state while the store is corrupt or unrepaired.
    pub fn approvals_store_health(&self) -> Result<()> {
        for dir in [
            self.project_approvals_dir.as_deref(),
            self.global_dir.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            if let Err(error) = load_approvals(dir) {
                return Err(approvals_load_refusal_error(error));
            }
        }
        Ok(())
    }

    /// Whether a command key is already **allowed** at *any* scope that
    /// applies to this session (Session, Project, or Global). `Once`
    /// grants are never stored, so they never show up here.
    #[cfg(test)]
    pub async fn is_command_granted(&self, key: &ApprovalKey) -> bool {
        self.command_grant(key)
            .await
            .expect("approvals store must be healthy in tests")
            .is_some()
    }

    /// Fail closed on a corrupt/unreadable approvals store (issue #297):
    /// a load error is the decision's refusal, never a silent "no grants".
    pub async fn command_grant(&self, key: &ApprovalKey) -> Result<Option<CommandGrant>> {
        // The durable files load first so a corrupt/unreadable store fails
        // this decision closed even when a session grant would have matched:
        // the lookup and the health check are one fail-closed operation,
        // never a split "check health, then read as empty".
        let project = self.project_file()?;
        let global = self.global_file()?;
        let s = key.as_storage_str();
        if let Some(granted_tier) = self.session_command_grant_tier(&s).await {
            return Ok(Some(CommandGrant {
                scope: Scope::Session,
                granted_tier,
            }));
        }
        if let Some(granted_tier) =
            project.and_then(|f| f.commands.get(&s).and_then(CommandGrantRecord::tier))
        {
            return Ok(Some(CommandGrant {
                scope: Scope::Project,
                granted_tier,
            }));
        }
        if let Some(granted_tier) =
            global.and_then(|f| f.commands.get(&s).and_then(CommandGrantRecord::tier))
        {
            return Ok(Some(CommandGrant {
                scope: Scope::Global,
                granted_tier,
            }));
        }
        Ok(None)
    }

    /// Whether a command key is **rejected** at any applicable scope — the
    /// allow query's mirror. A standing reject auto-denies the command
    /// without prompting (`DecisionSource::StandingReject`).
    #[cfg(test)]
    pub async fn is_command_rejected(&self, key: &ApprovalKey) -> bool {
        self.command_reject_scope(key)
            .await
            .expect("approvals store must be healthy in tests")
            .is_some()
    }

    /// Fail closed on a corrupt/unreadable approvals store (issue #297):
    /// a corrupt file can never read as "no standing rejects".
    pub async fn command_reject_scope(&self, key: &ApprovalKey) -> Result<Option<Scope>> {
        let project = self.project_file()?;
        let global = self.global_file()?;
        let s = key.as_storage_str();
        if self
            .session_has(GrantKind::Command, &s, Verdict::Reject)
            .await
        {
            return Ok(Some(Scope::Session));
        }
        if project.is_some_and(|f| f.commands_reject.contains(&s)) {
            return Ok(Some(Scope::Project));
        }
        if global.is_some_and(|f| f.commands_reject.contains(&s)) {
            return Ok(Some(Scope::Global));
        }
        Ok(None)
    }

    pub async fn mcp_tool_grant_scope(&self, server: &str, tool: &str) -> Result<Option<Scope>> {
        self.mcp_tool_grant_scope_for_key(&mcp_tool_key(server, tool))
            .await
    }

    pub async fn mcp_tool_grant_scope_for_key(&self, key: &str) -> Result<Option<Scope>> {
        let project = self.project_file()?;
        let global = self.global_file()?;
        if self
            .session_has(GrantKind::McpTool, &key, Verdict::Allow)
            .await
        {
            return Ok(Some(Scope::Session));
        }
        if project.is_some_and(|f| f.mcp_tools.contains(key)) {
            return Ok(Some(Scope::Project));
        }
        if global.is_some_and(|f| f.mcp_tools.contains(key)) {
            return Ok(Some(Scope::Global));
        }
        Ok(None)
    }

    pub async fn mcp_tool_reject_scope(&self, server: &str, tool: &str) -> Result<Option<Scope>> {
        self.mcp_tool_reject_scope_for_key(&mcp_tool_key(server, tool))
            .await
    }

    pub async fn mcp_tool_reject_scope_for_key(&self, key: &str) -> Result<Option<Scope>> {
        let project = self.project_file()?;
        let global = self.global_file()?;
        if self
            .session_has(GrantKind::McpTool, &key, Verdict::Reject)
            .await
        {
            return Ok(Some(Scope::Session));
        }
        if project.is_some_and(|f| f.mcp_tools_reject.contains(key)) {
            return Ok(Some(Scope::Project));
        }
        if global.is_some_and(|f| f.mcp_tools_reject.contains(key)) {
            return Ok(Some(Scope::Global));
        }
        Ok(None)
    }

    /// Scope of the persisted connection grant for one exact server identity.
    /// This is distinct from ordinary MCP tool lookup because the second key
    /// component is namespaced and is derived only from the transport identity.
    pub async fn mcp_server_connect_grant_scope(
        &self,
        server: &str,
        identity: &str,
    ) -> Result<Option<Scope>> {
        let project = self.project_file()?;
        let global = self.global_file()?;
        let key = mcp_server_connect_key(server, identity);
        if self
            .session_has(GrantKind::McpTool, &key, Verdict::Allow)
            .await
        {
            return Ok(Some(Scope::Session));
        }
        if project.is_some_and(|file| file.mcp_tools.contains(&key)) {
            return Ok(Some(Scope::Project));
        }
        if global.is_some_and(|file| file.mcp_tools.contains(&key)) {
            return Ok(Some(Scope::Global));
        }
        Ok(None)
    }

    pub async fn mcp_server_connect_reject_scope(
        &self,
        server: &str,
        identity: &str,
    ) -> Result<Option<Scope>> {
        let project = self.project_file()?;
        let global = self.global_file()?;
        let key = mcp_server_connect_key(server, identity);
        if self
            .session_has(GrantKind::McpTool, &key, Verdict::Reject)
            .await
        {
            return Ok(Some(Scope::Session));
        }
        if project.is_some_and(|file| file.mcp_tools_reject.contains(&key)) {
            return Ok(Some(Scope::Project));
        }
        if global.is_some_and(|file| file.mcp_tools_reject.contains(&key)) {
            return Ok(Some(Scope::Global));
        }
        Ok(None)
    }

    pub async fn record_mcp_server_connect(
        &self,
        server: &str,
        identity: &str,
        scope: Scope,
    ) -> Result<(), StoreError> {
        if scope == Scope::Once {
            return Err(StoreError::OnceNotPersistable);
        }
        self.record(
            GrantKind::McpTool,
            &mcp_server_connect_key(server, identity),
            scope,
            Verdict::Allow,
            None,
            None,
        )
        .await
    }

    pub async fn record_mcp_server_connect_key(
        &self,
        key: &str,
        scope: Scope,
    ) -> Result<(), StoreError> {
        self.record_mcp_key(key, scope, Verdict::Allow).await
    }

    pub async fn record_mcp_server_connect_reject(
        &self,
        server: &str,
        identity: &str,
        scope: Scope,
    ) -> Result<(), StoreError> {
        if scope == Scope::Once {
            return Err(StoreError::OnceNotPersistable);
        }
        self.record(
            GrantKind::McpTool,
            &mcp_server_connect_key(server, identity),
            scope,
            Verdict::Reject,
            None,
            None,
        )
        .await
    }

    pub async fn record_mcp_server_connect_reject_key(
        &self,
        key: &str,
        scope: Scope,
    ) -> Result<(), StoreError> {
        self.record_mcp_key(key, scope, Verdict::Reject).await
    }

    pub async fn is_harness_granted(&self, harness: &str) -> bool {
        self.session_has(GrantKind::Harness, harness, Verdict::Allow)
            .await
    }

    #[cfg(test)]
    async fn is_path_granted(&self, path: &Path) -> bool {
        self.is_path_granted_for(path, SandboxPathAccess::Read)
            .await
            .expect("approvals store must be healthy in tests")
    }

    /// Fail closed on a corrupt/unreadable approvals store (issue #297):
    /// a load error is the decision's refusal, never a silent "not granted".
    pub async fn is_path_granted_for(
        &self,
        path: &Path,
        required: SandboxPathAccess,
    ) -> Result<bool> {
        Ok(self
            .effective_path_grant_access(path)
            .await?
            .is_some_and(|access| access >= required))
    }

    pub async fn effective_path_grant_access(
        &self,
        path: &Path,
    ) -> Result<Option<SandboxPathAccess>> {
        let candidate = normalize_path(path, &self.cwd);
        let matches = |stored: &str| path_covers(stored, &candidate);
        if self.path_reject_matches(matches).await? {
            return Ok(None);
        }
        let mut access: Option<SandboxPathAccess> = None;
        for (key, grant_access) in self.path_allow_entries().await? {
            if path_covers(&key, &candidate) {
                access = Some(access.map_or(grant_access, |current| current.max(grant_access)));
            }
        }
        Ok(access)
    }

    pub async fn effective_path_grants(&self) -> Result<Vec<EffectivePathGrant>> {
        let rejects = self.path_reject_entries().await?;
        let mut by_path: BTreeMap<String, SandboxPathAccess> = BTreeMap::new();
        for (key, access) in self.path_allow_entries().await? {
            if rejects
                .iter()
                .any(|(reject, _)| paths_overlap(reject, &key))
            {
                continue;
            }
            by_path
                .entry(key)
                .and_modify(|current| *current = (*current).max(access))
                .or_insert(access);
        }

        let entries = by_path.into_iter().collect::<Vec<_>>();
        let mut grants = Vec::new();
        'outer: for (key, access) in &entries {
            for (other_key, other_access) in &entries {
                if other_key == key {
                    continue;
                }
                if *other_access >= *access && path_covers(other_key, key) {
                    continue 'outer;
                }
            }
            grants.push(EffectivePathGrant {
                path: PathBuf::from(key),
                access: *access,
            });
        }
        Ok(grants)
    }

    /// Whether a path is **rejected** at any applicable scope — the allow
    /// path query's mirror (same prefix-match semantics). A standing path
    /// reject auto-denies the out-of-cwd access without prompting. Fail
    /// closed on a corrupt/unreadable approvals store (issue #297).
    pub async fn is_path_rejected(&self, path: &Path) -> Result<bool> {
        let candidate = normalize_path(path, &self.cwd);
        let matches = |stored: &str| path_covers(stored, &candidate);
        Ok(self.path_reject_matches(matches).await?)
    }

    /// Record a command-shape **allow** grant at `scope`. Rejects wrappers and
    /// execution-bearing option values at
    /// any non-`Once` scope (priority #1). `Once` is a no-op error — the
    /// caller shouldn't record it, but rejecting loudly catches misuse.
    /// Clears any standing **reject** for this key across every reachable
    /// scope first (mutual exclusivity), then writes the allow.
    pub async fn record_command(
        &self,
        info: &crate::approval::classify::SimpleCommandInfo,
        tier: RiskTier,
        scope: Scope,
    ) -> Result<(), StoreError> {
        if scope == Scope::Once {
            return Err(StoreError::OnceNotPersistable);
        }
        if info.wrapper || info.execution_bearing_option {
            return Err(StoreError::WrapperNotPersistable(info.key.as_storage_str()));
        }
        self.record(
            GrantKind::Command,
            &info.key.as_storage_str(),
            scope,
            Verdict::Allow,
            None,
            Some(tier),
        )
        .await
    }

    /// Record a command-shape **reject** grant at `scope` — the allow
    /// recorder's mirror. Same `Once`/non-persistable rules. Clears any standing **allow** for
    /// this key across every reachable scope first, then writes the reject.
    pub async fn record_command_reject(
        &self,
        info: &crate::approval::classify::SimpleCommandInfo,
        scope: Scope,
    ) -> Result<(), StoreError> {
        if scope == Scope::Once {
            return Err(StoreError::OnceNotPersistable);
        }
        if info.wrapper || info.execution_bearing_option {
            return Err(StoreError::WrapperNotPersistable(info.key.as_storage_str()));
        }
        self.record(
            GrantKind::Command,
            &info.key.as_storage_str(),
            scope,
            Verdict::Reject,
            None,
            None,
        )
        .await
    }

    /// Record a path **allow** grant at `scope`. Paths are never wrappers,
    /// so the only rejection is `Once`. The path is normalized (absolutized
    /// against this store's session cwd) before storage so later prefix
    /// checks are stable.
    /// Clears any standing **reject** for this key across reachable scopes
    /// first.
    pub async fn record_path(
        &self,
        path: &Path,
        scope: Scope,
        access: SandboxPathAccess,
    ) -> Result<(), StoreError> {
        if scope == Scope::Once {
            return Err(StoreError::OnceNotPersistable);
        }
        self.record(
            GrantKind::Path,
            &normalize_path(path, &self.cwd),
            scope,
            Verdict::Allow,
            Some(access),
            None,
        )
        .await
    }

    /// Record a path **reject** grant at `scope` — the allow recorder's
    /// mirror. Clears any standing **allow** for this key across reachable
    /// scopes first, then writes the reject.
    pub async fn record_path_reject(&self, path: &Path, scope: Scope) -> Result<(), StoreError> {
        if scope == Scope::Once {
            return Err(StoreError::OnceNotPersistable);
        }
        self.record(
            GrantKind::Path,
            &normalize_path(path, &self.cwd),
            scope,
            Verdict::Reject,
            Some(SandboxPathAccess::ReadWrite),
            None,
        )
        .await
    }

    /// Record an external MCP tool **allow** grant at `scope`. The key is
    /// exact `(server, tool)`: arguments are intentionally not part of the
    /// grant, so repeated calls to the same external tool do not prompt per
    /// argument set. `Once` is applied by the caller and never persisted.
    pub async fn record_mcp_tool(
        &self,
        server: &str,
        tool: &str,
        scope: Scope,
    ) -> Result<(), StoreError> {
        if scope == Scope::Once {
            return Err(StoreError::OnceNotPersistable);
        }
        self.record(
            GrantKind::McpTool,
            &mcp_tool_key(server, tool),
            scope,
            Verdict::Allow,
            None,
            None,
        )
        .await
    }

    pub async fn record_mcp_tool_key(&self, key: &str, scope: Scope) -> Result<(), StoreError> {
        self.record_mcp_key(key, scope, Verdict::Allow).await
    }

    /// Record an external MCP tool **reject** grant at `scope` — the allow
    /// recorder's mirror. Clears any standing allow for the same exact
    /// `(server, tool)` before writing.
    pub async fn record_mcp_tool_reject(
        &self,
        server: &str,
        tool: &str,
        scope: Scope,
    ) -> Result<(), StoreError> {
        if scope == Scope::Once {
            return Err(StoreError::OnceNotPersistable);
        }
        self.record(
            GrantKind::McpTool,
            &mcp_tool_key(server, tool),
            scope,
            Verdict::Reject,
            None,
            None,
        )
        .await
    }

    pub async fn record_mcp_tool_reject_key(
        &self,
        key: &str,
        scope: Scope,
    ) -> Result<(), StoreError> {
        self.record_mcp_key(key, scope, Verdict::Reject).await
    }

    async fn record_mcp_key(
        &self,
        key: &str,
        scope: Scope,
        verdict: Verdict,
    ) -> Result<(), StoreError> {
        if scope == Scope::Once {
            return Err(StoreError::OnceNotPersistable);
        }
        self.record(GrantKind::McpTool, key, scope, verdict, None, None)
            .await
    }

    /// Record a configured external harness allow grant for this session.
    /// Durable always-allow is a field on the harness config, not an
    /// `approvals.json` entry, so non-session scopes are rejected.
    pub async fn record_harness(&self, harness: &str, scope: Scope) -> Result<(), StoreError> {
        match scope {
            Scope::Once => Err(StoreError::OnceNotPersistable),
            Scope::Session => {
                self.record(
                    GrantKind::Harness,
                    harness,
                    Scope::Session,
                    Verdict::Allow,
                    None,
                    None,
                )
                .await
            }
            Scope::Project | Scope::Global => Err(StoreError::HarnessSessionScopeOnly),
        }
    }

    // ---- image-generation grants -----------------------------------------

    /// Dominance lookup for reusable image-generation grants. Session grants
    /// take precedence; project grants additionally prove that the attached
    /// session still belongs to the same machine-local project. Unknown cost
    /// needs an explicit unknown-cost grant; a known cost may use only a
    /// stored known ceiling at least as large as the new request.
    pub async fn image_generation_grant_scope_bounded(
        &self,
        project_id: &str,
        bounds: ImageGenerationGrantBounds<'_>,
    ) -> Option<Scope> {
        let project_id = project_id.to_owned();
        let destination_binding_digest = bounds.destination_binding_digest.to_owned();
        let output_path_authority = bounds.output_path_authority.to_owned();
        let reference_egress = i64::from(bounds.reference_egress);
        let fanout = i64::from(bounds.fanout);
        let total_outputs = i64::from(bounds.total_outputs);
        let cost = bounds.cost_maximum.map(i64::try_from).transpose().ok()?;
        let session_id = self.session_id.to_string();
        self.db.read(move |conn| {
            let matches = |scope: &str, project_membership: bool| -> rusqlite::Result<bool> {
                let session_fence = if scope == "session" {
                    " AND session_id = ?8"
                } else if project_membership {
                    " AND EXISTS (SELECT 1 FROM sessions s WHERE s.session_id = ?8 AND s.project_id = ?2)"
                } else {
                    ""
                };
                let sql = format!(
                    "SELECT EXISTS(SELECT 1 FROM image_generation_grants WHERE scope = ?1 AND project_id = ?2 AND destination_binding_digest = ?3 AND output_path_authority = ?4 AND reference_egress >= ?5 AND maximum_fanout >= ?6 AND maximum_total_outputs >= ?7 AND ((?9 IS NULL AND unknown_cost_allowed = 1) OR (?9 IS NOT NULL AND maximum_known_cost_usd_micros >= ?9)) AND verdict = 'allow' AND revoked_at_unix_ms IS NULL{session_fence})"
                );
                conn.query_row(
                    &sql,
                    rusqlite::params![scope, project_id, destination_binding_digest, output_path_authority, reference_egress, fanout, total_outputs, session_id, cost],
                    |row| row.get(0),
                )
            };
            if matches("session", false)? {
                return Ok(Some(Scope::Session));
            }
            Ok(matches("project", true)?.then_some(Scope::Project))
        }).await.ok().flatten()
    }

    #[cfg(test)]
    pub(super) async fn record_image_generation_grant_bounded(
        &self,
        scope: Scope,
        project_id: &str,
        bounds: ImageGenerationGrantBounds<'_>,
    ) -> Result<(), StoreError> {
        let (Scope::Session | Scope::Project) = scope else {
            return Err(if scope == Scope::Once {
                StoreError::OnceNotPersistable
            } else {
                StoreError::ImageGenerationNoGlobalScope
            });
        };
        let session_id = (scope == Scope::Session).then(|| self.session_id.to_string());
        let project_id = project_id.to_owned();
        let binding = bounds.destination_binding_digest.to_owned();
        let authority = bounds.output_path_authority.to_owned();
        let known_cost = bounds
            .cost_maximum
            .map(i64::try_from)
            .transpose()
            .map_err(anyhow::Error::from)?;
        self.db.write(move |conn| {
            conn.execute(
                "INSERT OR REPLACE INTO image_generation_grants (grant_id,scope,session_id,project_id,destination_binding_digest,output_path_authority,reference_egress,maximum_fanout,maximum_total_outputs,maximum_known_cost_usd_micros,unknown_cost_allowed,verdict,granted_at_unix_ms,revoked_at_unix_ms) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,'allow',?12,NULL)",
                rusqlite::params![uuid::Uuid::now_v7().to_string(), scope.as_str(), session_id, project_id, binding, authority, i64::from(bounds.reference_egress), i64::from(bounds.fanout), i64::from(bounds.total_outputs), known_cost, i64::from(bounds.cost_maximum.is_none()), now_epoch_seconds() * 1000],
            )?;
            Ok(())
        }).await.map_err(StoreError::Io)
    }

    /// Revoke every live grant at one exact scope/project/destination/output
    /// binding. Broader dominance bounds are deliberately ignored: revocation
    /// names the capability identity, and all envelopes for that identity are
    /// withdrawn so a smaller stored envelope cannot remain reusable.
    pub async fn revoke_image_generation_grants_bounded(
        &self,
        scope: Scope,
        project_id: &str,
        bounds: ImageGenerationGrantBounds<'_>,
    ) -> Result<usize, StoreError> {
        if !matches!(scope, Scope::Session | Scope::Project) {
            return Err(if scope == Scope::Once {
                StoreError::OnceNotPersistable
            } else {
                StoreError::ImageGenerationNoGlobalScope
            });
        }
        let session_id = (scope == Scope::Session).then(|| self.session_id.to_string());
        let project_id = project_id.to_owned();
        let binding = bounds.destination_binding_digest.to_owned();
        let authority = bounds.output_path_authority.to_owned();
        self.db.write(move |conn| Ok(conn.execute(
            "UPDATE image_generation_grants SET revoked_at_unix_ms=?1 WHERE scope=?2 AND ifnull(session_id,'')=ifnull(?3,'') AND project_id=?4 AND destination_binding_digest=?5 AND output_path_authority=?6 AND revoked_at_unix_ms IS NULL",
            rusqlite::params![now_epoch_seconds() * 1000, scope.as_str(), session_id, project_id, binding, authority],
        )?)).await.map_err(StoreError::Io)
    }

    // ---- loop-guard rules -------------------------------------------------

    /// Stable signature for a loop-guard rule: a hash of the tool name and
    /// the call's canonical `wire_input`. Two calls share a signature iff
    /// the tool name and the (serialized) wire input are byte-identical —
    /// the exact-match semantics the loop guard requires. Hashing bounds
    /// the storage key regardless of input size.
    ///
    /// The `wire_input` is serialized with [`canonical_json`] so that
    /// object key ordering can't make two semantically-identical inputs
    /// hash differently (serde_json preserves insertion order; the model
    /// may emit keys in any order).
    pub fn loop_signature(tool: &str, wire_input: &serde_json::Value) -> String {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(tool.as_bytes());
        h.update([0u8]); // separator so `tool` + `input` can't collide across a boundary
        h.update(canonical_json(wire_input).as_bytes());
        let out = h.finalize();
        let mut hex = String::with_capacity(64);
        for byte in out.iter() {
            hex.push_str(&format!("{byte:02x}"));
        }
        hex
    }

    /// The recorded verdict for `signature`, or `None` if no rule applies.
    ///
    /// ## Precedence (session wins over project/global)
    ///
    /// A signature can carry rules at more than one scope (e.g. the user
    /// chose "always accept for this project" in an earlier session, then
    /// "always reject for this session" now). The **session** rule wins:
    /// it is the most recent, most specific expression of intent and is
    /// the only one the user can have set *in the current session*, so it
    /// must be able to override a standing project/global rule for the
    /// life of the session. Project and global are both persistent; among
    /// them, a project rule (nearer the work) wins over a global one.
    ///
    /// Order checked: session → project → global. Within a scope a
    /// `reject` and an `accept` cannot coexist (recording one clears the
    /// other), so the first scope with *any* rule decides. Fail closed on
    /// a corrupt/unreadable approvals store (issue #297): a corrupt
    /// persisted loop reject can never read as "no rule" (which would let
    /// yolo mode auto-accept the repeat).
    pub async fn loop_rule(&self, signature: &str) -> Result<Option<LoopVerdict>> {
        let project = self.project_file()?;
        let global = self.global_file()?;
        if let Some(v) = self.session_loop_rule(signature).await {
            return Ok(Some(v));
        }
        Ok(project
            .and_then(|f| file_loop_rule(&f, signature))
            .or_else(|| global.and_then(|f| file_loop_rule(&f, signature))))
    }

    /// Record a loop-guard rule for `signature` at `scope`. Recording one
    /// verdict at a scope clears the opposite verdict at the same scope so
    /// a signature never carries contradictory rules within one scope.
    /// `Once` is rejected (it is never persisted — the caller acts on a
    /// one-off decision directly).
    pub async fn record_loop_rule(
        &self,
        signature: &str,
        verdict: LoopVerdict,
        scope: Scope,
    ) -> Result<(), StoreError> {
        match scope {
            Scope::Once => Err(StoreError::OnceNotPersistable),
            Scope::Session => self
                .session_record_loop_rule(signature, verdict)
                .await
                .map_err(StoreError::Io),
            Scope::Project => {
                if self.project_root.is_none() {
                    return Err(StoreError::NoProjectRoot);
                }
                let dir = self
                    .project_approvals_dir
                    .as_ref()
                    .context("no machine-local project approvals dir available")
                    .map_err(StoreError::Io)?;
                self.file_record_loop_rule(dir, signature, verdict)
                    .map_err(StoreError::Io)
            }
            Scope::Global => {
                let dir = self
                    .global_dir
                    .clone()
                    .context("no global config dir available")
                    .map_err(StoreError::Io)?;
                self.file_record_loop_rule(&dir, signature, verdict)
                    .map_err(StoreError::Io)
            }
        }
    }

    async fn session_loop_rule(&self, signature: &str) -> Option<LoopVerdict> {
        let session_id = self.session_id;
        let signature = signature.to_owned();
        self.db
            .read(move |conn| {
                let verdict: Option<String> = conn
                    .query_row(
                        "SELECT rule_verdict FROM loop_guard_rules \
                         WHERE session_id = ?1 AND signature = ?2",
                        rusqlite::params![session_id.to_string(), signature],
                        |row| row.get(0),
                    )
                    .optional()?;
                Ok(verdict)
            })
            .await
            .ok()
            .flatten()
            .and_then(|s| parse_verdict(&s))
    }

    async fn session_record_loop_rule(&self, signature: &str, verdict: LoopVerdict) -> Result<()> {
        let session_id = self.session_id;
        let signature = signature.to_owned();
        self.db
            .write(move |conn| {
                // `INSERT OR REPLACE` on the (session_id, signature) primary
                // key flips an existing opposite verdict in place — no
                // contradictory pair can persist.
                conn.execute(
                    "INSERT OR REPLACE INTO loop_guard_rules \
                 (session_id, signature, rule_verdict, recorded_at) \
                 VALUES (?1, ?2, ?3, ?4)",
                    rusqlite::params![
                        session_id.to_string(),
                        signature,
                        verdict.as_str(),
                        now_epoch_seconds()
                    ],
                )
                .context("inserting loop_guard_rule")?;
                Ok(())
            })
            .await
    }

    fn file_record_loop_rule(
        &self,
        dir: &Path,
        signature: &str,
        verdict: LoopVerdict,
    ) -> Result<()> {
        mutate_approvals(dir, |file| {
            // Clear the opposite verdict so the file never carries a
            // contradictory pair for one signature.
            match verdict {
                LoopVerdict::Accept => {
                    file.loop_reject.remove(signature);
                    file.loop_accept.insert(signature.to_string());
                }
                LoopVerdict::Reject => {
                    file.loop_accept.remove(signature);
                    file.loop_reject.insert(signature.to_string());
                }
            }
            (true, ())
        })
    }

    // ---- internals --------------------------------------------------------

    async fn record(
        &self,
        kind: GrantKind,
        key: &str,
        scope: Scope,
        verdict: Verdict,
        access: Option<SandboxPathAccess>,
        risk_tier: Option<RiskTier>,
    ) -> Result<(), StoreError> {
        if scope == Scope::Once {
            return Err(StoreError::OnceNotPersistable);
        }
        // Mutual exclusivity (enforced at record time so query time needs no
        // precedence rule): a key is either allowed or rejected, never both.
        // Before writing the new polarity, drop the opposite polarity for this
        // exact key at EVERY reachable scope — session, project (if a root
        // resolves), and global (if a global dir resolves). Unresolved scopes
        // are skipped. This is the documented side effect: a session-scoped
        // reject of a key allowed at project/global rewrites those files to
        // drop that key's allow (only ever the same key).
        self.clear_key_everywhere(kind, key, verdict.opposite())
            .await
            .map_err(StoreError::Io)?;
        match scope {
            Scope::Once => Err(StoreError::OnceNotPersistable),
            Scope::Session => self
                .session_insert(kind, key, verdict, access, risk_tier)
                .await
                .map_err(StoreError::Io),
            Scope::Project => {
                if self.project_root.is_none() {
                    return Err(StoreError::NoProjectRoot);
                }
                let dir = self
                    .project_approvals_dir
                    .as_ref()
                    .context("no machine-local project approvals dir available")
                    .map_err(StoreError::Io)?;
                self.file_insert(dir, kind, key, verdict, access, risk_tier)
                    .map_err(StoreError::Io)
            }
            Scope::Global => {
                let dir = self
                    .global_dir
                    .clone()
                    .context("no global config dir available")
                    .map_err(StoreError::Io)?;
                self.file_insert(&dir, kind, key, verdict, access, risk_tier)
                    .map_err(StoreError::Io)
            }
        }
    }

    /// Remove a `kind` grant for `key` at `verdict` polarity from EVERY
    /// reachable scope (session DB + project file + global file). Used by
    /// [`Self::record`] to clear the opposite polarity before writing, so a
    /// key never coexists as both an allow and a reject. Scopes that don't
    /// resolve (no project root / no global dir) are skipped, never an error.
    /// Each removal is exact-key (commands) or exact-string (paths) — never a
    /// prefix sweep — so it only ever touches the one key being re-recorded.
    async fn clear_key_everywhere(
        &self,
        kind: GrantKind,
        key: &str,
        verdict: Verdict,
    ) -> Result<()> {
        // Session (always reachable).
        self.session_remove(kind, key, verdict).await?;
        // Project (only if a root resolves).
        if let Some(dir) = self.project_approvals_dir.as_ref() {
            self.file_remove(dir, kind, key, verdict)?;
        }
        // Global (only if a global dir resolves).
        if let Some(dir) = self.global_dir.clone() {
            self.file_remove(&dir, kind, key, verdict)?;
        }
        Ok(())
    }

    // ---- session scope (SQLite) ------------------------------------------

    async fn session_command_grant_tier(&self, key: &str) -> Option<RiskTier> {
        let session_id = self.session_id;
        let key = key.to_owned();
        self.db
            .read(move |conn| {
                Ok(conn
                    .query_row(
                        "SELECT risk_tier FROM approval_grants \
                     WHERE session_id = ?1 AND grant_kind = 'command' AND grant_key = ?2 \
                       AND verdict = 'allow'",
                        rusqlite::params![session_id.to_string(), key],
                        |row| row.get::<_, String>(0),
                    )
                    .optional()?)
            })
            .await
            .ok()
            .flatten()
            .and_then(|tier| RiskTier::from_policy_key(&tier))
    }

    async fn session_has(&self, kind: GrantKind, key: &str, verdict: Verdict) -> bool {
        let session_id = self.session_id;
        let key = key.to_owned();
        self.db
            .read(move |conn| {
                let n: i64 = conn.query_row(
                    "SELECT COUNT(*) FROM approval_grants \
                     WHERE session_id = ?1 AND grant_kind = ?2 AND grant_key = ?3 \
                       AND verdict = ?4",
                    rusqlite::params![session_id.to_string(), kind.as_str(), key, verdict.as_str()],
                    |row| row.get(0),
                )?;
                Ok(n > 0)
            })
            .await
            .unwrap_or(false)
    }

    async fn session_path_entries(&self, verdict: Verdict) -> Vec<(String, SandboxPathAccess)> {
        let session_id = self.session_id;
        self.db
            .read(move |conn| {
                let mut stmt = conn.prepare(
                    "SELECT grant_key, access FROM approval_grants \
                     WHERE session_id = ?1 AND grant_kind = 'path' AND verdict = ?2 \
                     ORDER BY grant_key",
                )?;
                let rows = stmt.query_map(
                    rusqlite::params![session_id.to_string(), verdict.as_str()],
                    |row| {
                        let key: String = row.get(0)?;
                        let access: Option<String> = row.get(1)?;
                        Ok((key, path_access_from_storage(access.as_deref())))
                    },
                )?;
                let mut out = Vec::new();
                for row in rows {
                    out.push(row?);
                }
                Ok(out)
            })
            .await
            .unwrap_or_default()
    }

    async fn path_allow_entries(&self) -> Result<Vec<(String, SandboxPathAccess)>> {
        let project = self.project_file()?;
        let global = self.global_file()?;
        let mut entries = self.session_path_entries(Verdict::Allow).await;
        if let Some(file) = project {
            entries.extend(file.paths);
        }
        if let Some(file) = global {
            entries.extend(file.paths);
        }
        Ok(entries)
    }

    async fn path_reject_entries(&self) -> Result<Vec<(String, SandboxPathAccess)>> {
        let project = self.project_file()?;
        let global = self.global_file()?;
        let mut entries = self.session_path_entries(Verdict::Reject).await;
        if let Some(file) = project {
            entries.extend(file.paths_reject);
        }
        if let Some(file) = global {
            entries.extend(file.paths_reject);
        }
        Ok(entries)
    }

    async fn path_reject_matches<F>(&self, matches: F) -> Result<bool>
    where
        F: Fn(&str) -> bool,
    {
        Ok(self
            .path_reject_entries()
            .await?
            .iter()
            .any(|(key, _)| matches(key)))
    }

    async fn session_insert(
        &self,
        kind: GrantKind,
        key: &str,
        verdict: Verdict,
        access: Option<SandboxPathAccess>,
        risk_tier: Option<RiskTier>,
    ) -> Result<()> {
        let session_id = self.session_id;
        let key = key.to_owned();
        let access = access.map(SandboxPathAccess::storage_str);
        let risk_tier = risk_tier.map(RiskTier::as_str);
        self.db
            .write(move |conn| {
                // `INSERT OR REPLACE` on the (session_id, grant_kind, grant_key)
                // primary key flips an existing opposite verdict in place — a key
                // can never carry both polarities at session scope.
                conn.execute(
                    "INSERT OR REPLACE INTO approval_grants \
                 (session_id, grant_kind, grant_key, granted_at, verdict, access, risk_tier) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    rusqlite::params![
                        session_id.to_string(),
                        kind.as_str(),
                        key,
                        now_epoch_seconds(),
                        verdict.as_str(),
                        access,
                        risk_tier
                    ],
                )
                .context("inserting session approval grant")?;
                Ok(())
            })
            .await
    }

    /// Remove a session-scope grant of `verdict` polarity for an exact
    /// `(kind, key)`. Used to clear the opposite polarity before writing.
    async fn session_remove(&self, kind: GrantKind, key: &str, verdict: Verdict) -> Result<()> {
        let session_id = self.session_id;
        let key = key.to_owned();
        self.db
            .write(move |conn| {
                conn.execute(
                    "DELETE FROM approval_grants \
                 WHERE session_id = ?1 AND grant_kind = ?2 AND grant_key = ?3 \
                   AND verdict = ?4",
                    rusqlite::params![session_id.to_string(), kind.as_str(), key, verdict.as_str()],
                )
                .context("removing session approval grant")?;
                Ok(())
            })
            .await
    }

    // ---- project / global scope (JSON files) ------------------------------

    /// Load the project `approvals.json`, failing closed (issue #297): a
    /// corrupt/unreadable store — or a not-yet-repaired quarantine residue
    /// from an earlier detection — is an error carrying the repair-oriented
    /// refusal (the load already quarantined the corrupt bytes) — never a
    /// silent `None` that would drop every standing entry for this
    /// decision. The decision-boundary health gate and every lookup
    /// consume the same fail-closed load.
    fn project_file(&self) -> Result<Option<ApprovalsFile>> {
        scoped_approvals_file(self.project_approvals_dir.as_deref())
    }

    /// Load the global `approvals.json`, mirroring [`Self::project_file`].
    fn global_file(&self) -> Result<Option<ApprovalsFile>> {
        scoped_approvals_file(self.global_dir.as_deref())
    }

    /// Insert a grant into the `approvals.json` in `dir` via one locked
    /// read-modify-write cycle. A corrupt store fails closed — the corrupt
    /// bytes were already quarantined by the load and this refuses instead
    /// of recreating a fresh store that silently drops every standing
    /// entry.
    fn file_insert(
        &self,
        dir: &Path,
        kind: GrantKind,
        key: &str,
        verdict: Verdict,
        access: Option<SandboxPathAccess>,
        risk_tier: Option<RiskTier>,
    ) -> Result<()> {
        mutate_approvals(dir, |file| {
            // Clear the opposite polarity within this same file too, so one
            // `approvals.json` never lists a key in both an allow and a reject
            // set (belt-and-braces with `clear_key_everywhere`, which already
            // visited this scope — but this keeps `file_insert`
            // self-consistent).
            verdict_remove(file, kind, verdict.opposite(), key);
            verdict_insert(file, kind, verdict, key, access, risk_tier);
            (true, ())
        })
    }

    /// Remove a grant of `verdict` polarity for an exact `key` from the
    /// `approvals.json` in `dir`. A missing file / missing key is a no-op
    /// (no write). A corrupt store fails closed with the quarantine
    /// refusal instead of being silently treated as empty. Used to clear
    /// the opposite polarity before writing.
    fn file_remove(&self, dir: &Path, kind: GrantKind, key: &str, verdict: Verdict) -> Result<()> {
        mutate_approvals(dir, |file| (verdict_remove(file, kind, verdict, key), ()))
    }
}

fn verdict_insert(
    file: &mut ApprovalsFile,
    kind: GrantKind,
    verdict: Verdict,
    key: &str,
    access: Option<SandboxPathAccess>,
    risk_tier: Option<RiskTier>,
) {
    match (kind, verdict) {
        (GrantKind::Command, Verdict::Allow) => {
            if let Some(tier) = risk_tier {
                file.commands
                    .insert(key.to_string(), CommandGrantRecord::new(tier));
            }
        }
        (GrantKind::Command, Verdict::Reject) => {
            file.commands_reject.insert(key.to_string());
        }
        (GrantKind::Path, Verdict::Allow) => {
            file.paths.insert(
                key.to_string(),
                access.unwrap_or(SandboxPathAccess::ReadWrite),
            );
        }
        (GrantKind::Path, Verdict::Reject) => {
            file.paths_reject.insert(
                key.to_string(),
                access.unwrap_or(SandboxPathAccess::ReadWrite),
            );
        }
        (GrantKind::McpTool, Verdict::Allow) => {
            file.mcp_tools.insert(key.to_string());
        }
        (GrantKind::McpTool, Verdict::Reject) => {
            file.mcp_tools_reject.insert(key.to_string());
        }
        // Harness grants are session-only; the durable equivalent is the
        // `harnesses.<name>.always_allow` field in config.json.
        (GrantKind::Harness, Verdict::Allow | Verdict::Reject) => {}
    }
}

fn verdict_remove(file: &mut ApprovalsFile, kind: GrantKind, verdict: Verdict, key: &str) -> bool {
    match (kind, verdict) {
        (GrantKind::Command, Verdict::Allow) => file.commands.remove(key).is_some(),
        (GrantKind::Command, Verdict::Reject) => file.commands_reject.remove(key),
        (GrantKind::Path, Verdict::Allow) => file.paths.remove(key).is_some(),
        (GrantKind::Path, Verdict::Reject) => file.paths_reject.remove(key).is_some(),
        (GrantKind::McpTool, Verdict::Allow) => file.mcp_tools.remove(key),
        (GrantKind::McpTool, Verdict::Reject) => file.mcp_tools_reject.remove(key),
        // Harness grants are session-only and never stored in approvals.json.
        (GrantKind::Harness, Verdict::Allow | Verdict::Reject) => false,
    }
}

fn path_access_from_storage(value: Option<&str>) -> SandboxPathAccess {
    match value {
        Some("read") => SandboxPathAccess::Read,
        Some("read-write") => SandboxPathAccess::ReadWrite,
        _ => SandboxPathAccess::ReadWrite,
    }
}

pub fn mcp_server_connect_key(server: &str, identity: &str) -> String {
    mcp_server_connect_key_for(None, crate::mcp::config::DEFAULT_PROFILE, server, identity)
}

pub fn mcp_server_connect_key_for(
    agent: Option<&str>,
    profile: &str,
    server: &str,
    identity: &str,
) -> String {
    mcp_tool_key_for(agent, profile, server, &format!("\u{0}connect:{identity}"))
}

pub fn mcp_tool_key(server: &str, tool: &str) -> String {
    mcp_tool_key_for(None, crate::mcp::config::DEFAULT_PROFILE, server, tool)
}

/// Grant key for an MCP tool. Agent-bound servers include the requesting
/// agent so a grant for agent A never satisfies agent B. Scope-level
/// servers keep the historical `server/tool` key.
pub fn mcp_tool_key_for(agent: Option<&str>, profile: &str, server: &str, tool: &str) -> String {
    let base = format!(
        "{}/{}",
        escape_mcp_tool_key_part(server),
        escape_mcp_tool_key_part(tool)
    );
    let profiled = format!("profile:{}/{}", escape_mcp_tool_key_part(profile), base);
    match agent {
        Some(agent) if !agent.is_empty() => {
            format!("agent:{}/{}", escape_mcp_tool_key_part(agent), profiled)
        }
        _ => profiled,
    }
}

fn escape_mcp_tool_key_part(part: &str) -> String {
    part.replace('%', "%25").replace('/', "%2F")
}

fn paths_overlap(a: &str, b: &str) -> bool {
    path_covers(a, b) || path_covers(b, a)
}

/// `<global config dir>` for approvals. This is the same platform-default
/// user-level config root used by layered discovery.
pub fn global_approvals_dir() -> Option<PathBuf> {
    crate::config::dirs::global_config_dir().ok()
}

/// Machine-local approvals dir for a project root. This is keyed through
/// the same hashed-cwd config directory used by the config layer, so the
/// persisted user decision never lives inside the repository.
pub fn project_approvals_dir(root: &Path) -> Option<PathBuf> {
    crate::config::dirs::local_config_dir_for(root).ok()
}

/// A management-UI grant kind: the entry buckets a project/global
/// `approvals.json` carries. Unlike [`GrantKind`] (which only spans the
/// command/path grants the approval flow records), this also names the
/// two loop-guard buckets so the `/permissions` UI can list and delete
/// every persisted entry — not just commands and paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagedGrantKind {
    /// A command-shape grant (`commands` set).
    Command,
    /// A path grant (`paths` set).
    Path,
    /// An external MCP tool grant (`mcpTools` set).
    McpTool,
    /// A loop-guard always-accept rule (`loop_accept` set).
    LoopAccept,
    /// A loop-guard always-reject rule (`loop_reject` set).
    LoopReject,
}

impl ManagedGrantKind {
    /// Stable, human-facing label for the kind (used as the section
    /// heading in the `/permissions` pane).
    pub fn label(self) -> &'static str {
        match self {
            ManagedGrantKind::Command => "Commands",
            ManagedGrantKind::Path => "Paths",
            ManagedGrantKind::McpTool => "External MCP tools",
            ManagedGrantKind::LoopAccept => "Loop always-accept",
            ManagedGrantKind::LoopReject => "Loop always-reject",
        }
    }
}

#[derive(Deserialize)]
struct StoredCommandShape {
    program: String,
    subcommand: Option<String>,
    options: BTreeSet<String>,
}

/// Convert a versioned command storage key into the non-secret shape the user
/// approved. Legacy keys remain readable so they can be removed, but never
/// match at authorization time.
fn command_shape_display(storage: &str) -> String {
    let Some(json) = storage.strip_prefix("v2:") else {
        return storage.to_string();
    };
    let Ok(shape) = serde_json::from_str::<StoredCommandShape>(json) else {
        return storage.to_string();
    };
    let mut display = match shape.subcommand {
        Some(subcommand) => format!("{} {}", shape.program, subcommand),
        None => shape.program,
    };
    if !shape.options.is_empty() {
        display.push(' ');
        display.push_str(&shape.options.into_iter().collect::<Vec<_>>().join(" "));
    }
    display
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ManagedCommandGrant {
    pub key: String,
    #[serde(rename = "riskTier", serialize_with = "serialize_risk_tier")]
    pub risk_tier: RiskTier,
}

fn serialize_risk_tier<S>(tier: &RiskTier, serializer: S) -> std::result::Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(tier.as_str())
}

/// A persisted path grant exposed to the `/permissions` management UI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ManagedPathGrant {
    pub key: String,
    pub access: SandboxPathAccess,
}

impl ManagedPathGrant {
    pub fn access_label(&self) -> &'static str {
        self.access.storage_str()
    }
}

/// The ordered grant buckets of one scope's `approvals.json`, each a
/// sorted list of entries. Produced by [`list_managed_grants`] for the
/// `/permissions` management UI; the order (commands, paths, MCP tools, accept,
/// reject) is the order the UI renders sections in.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ManagedGrants {
    pub commands: Vec<ManagedCommandGrant>,
    pub paths: Vec<ManagedPathGrant>,
    pub mcp_tools: Vec<String>,
    pub loop_accept: Vec<String>,
    pub loop_reject: Vec<String>,
}

impl ManagedGrants {
    /// Whether the scope has no persisted grants of any kind — drives the
    /// pane's explicit empty-state per scope.
    pub fn is_empty(&self) -> bool {
        self.commands.is_empty()
            && self.paths.is_empty()
            && self.mcp_tools.is_empty()
            && self.loop_accept.is_empty()
            && self.loop_reject.is_empty()
    }

    pub fn entry_count(&self, kind: ManagedGrantKind) -> usize {
        match kind {
            ManagedGrantKind::Command => self.commands.len(),
            ManagedGrantKind::Path => self.paths.len(),
            ManagedGrantKind::McpTool => self.mcp_tools.len(),
            ManagedGrantKind::LoopAccept => self.loop_accept.len(),
            ManagedGrantKind::LoopReject => self.loop_reject.len(),
        }
    }
}

/// Read every persisted grant from the `approvals.json` in `dir` (the
/// machine-local project approvals dir or the global config dir). A missing
/// file reads as no grants — the management UI shows an empty scope, never an
/// error. A corrupt file is quarantined (copied aside to a fresh owner-only
/// file, never deleted) and
/// reads as no grants here, as does a store with an unrepaired quarantine
/// residue; the approval-decision health gate refuses approval-dependent
/// actions while the quarantine copy exists, so the corruption surfaces there
/// with a repair-oriented error. Entries come out
/// sorted by the on-disk `BTreeMap` / `BTreeSet` ordering, so the listing is
/// stable.
pub fn list_managed_grants(dir: &Path) -> ManagedGrants {
    let file = match load_approvals(dir) {
        Ok(file) => file.unwrap_or_default(),
        Err(error) => {
            tracing::error!(
                refusal = %error.refusal_message(),
                "approvals store failed the load closed; listing as empty on this informational surface"
            );
            ApprovalsFile::default()
        }
    };
    ManagedGrants {
        commands: file
            .commands
            .into_iter()
            .filter_map(|(key, record)| {
                record.tier().map(|risk_tier| ManagedCommandGrant {
                    key: command_shape_display(&key),
                    risk_tier,
                })
            })
            .collect(),
        paths: file
            .paths
            .into_iter()
            .map(|(key, access)| ManagedPathGrant { key, access })
            .collect(),
        mcp_tools: file.mcp_tools.into_iter().collect(),
        loop_accept: file.loop_accept.into_iter().collect(),
        loop_reject: file.loop_reject.into_iter().collect(),
    }
}

/// Remove a single grant `key` of `kind` from the `approvals.json` in
/// `dir`, rewriting the file via the same locked load→mutate→atomic-store
/// path the approval store uses to *record* grants. Holding the approvals
/// lock across the whole cycle means a concurrent edit to a different
/// entry is preserved (we only drop the one key, never clobber the whole
/// file from a stale snapshot). A corrupt store fails closed with the
/// quarantine refusal — it is never silently treated as empty and
/// rewritten. Returns `true` if the key was present and removed; `false`
/// (no write) if it wasn't — so a double-delete or a vanished entry is a
/// harmless no-op. The change takes effect on the next approval check,
/// which re-reads the file.
pub fn delete_managed_grant(dir: &Path, kind: ManagedGrantKind, key: &str) -> Result<bool> {
    mutate_approvals(dir, |file| {
        let removed = match kind {
            ManagedGrantKind::Command => {
                if file.commands.remove(key).is_some() {
                    true
                } else {
                    let stored = file
                        .commands
                        .keys()
                        .find(|stored| command_shape_display(stored) == key)
                        .cloned();
                    stored.is_some_and(|stored| file.commands.remove(&stored).is_some())
                }
            }
            ManagedGrantKind::Path => file.paths.remove(key).is_some(),
            ManagedGrantKind::McpTool => file.mcp_tools.remove(key),
            ManagedGrantKind::LoopAccept => file.loop_accept.remove(key),
            ManagedGrantKind::LoopReject => file.loop_reject.remove(key),
        };
        (removed, removed)
    })
}

/// File name for the per-scope approvals store inside an approvals dir.
const APPROVALS_FILE: &str = "approvals.json";

/// Cross-process advisory lock guarding every `approvals.json`
/// read-modify-write cycle (issue #297). The lock file itself never holds
/// store data, is never truncated, and every acquirer verifies the
/// pathname still refers to the object it locked — so all cycles for a
/// directory serialize on one shared lock object, never on two
/// replacement inodes.
const APPROVALS_LOCK_FILE: &str = "approvals.json.lock";

/// Name prefix of the quarantine copies a corrupt approvals file is renamed
/// aside to — `approvals.json.corrupt-<unix_ms>[-<n>]` — so the original
/// bytes survive for diagnosis. Never deleted.
const APPROVALS_QUARANTINE_PREFIX: &str = "approvals.json.corrupt";

/// A corrupt/unreadable approvals store detected at load time (issue #297).
/// The store fails closed around one of these: the corrupt bytes are
/// preserved for diagnosis by copying them aside to a fresh owner-only
/// file — never deleted or overwritten, and never touching the live path —
/// and approval-dependent decisions are refused with a repair-oriented
/// error instead of silently dropping every standing allow/reject entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorruptApprovalsStore {
    /// The store file that failed to load.
    pub path: PathBuf,
    /// Where the corrupt bytes were preserved (copied aside to a fresh
    /// owner-only file; the live path is never vacated, renamed, or
    /// deleted by quarantine). `None` when nothing was quarantined: an
    /// unreadable file, the cross-process lock could not be taken to
    /// re-read under, or every preservation candidate failed. The
    /// original file is then left in place, still never deleted.
    pub preserved: Option<PathBuf>,
    /// Why the load failed (read or JSON parse error).
    pub error: String,
}

impl CorruptApprovalsStore {
    /// Repair-oriented refusal: what was found, where the original bytes
    /// are preserved, and how to recover. Surfaced verbatim to the user
    /// at the approval-decision boundary.
    pub fn refusal_message(&self) -> String {
        match &self.preserved {
            Some(preserved) => format!(
                "approval store `{}` is corrupt ({}) and its original bytes are preserved \
                 for diagnosis at `{}`; nothing was deleted or overwritten. This action \
                 is refused rather than silently dropping saved allow/reject decisions. \
                 Restore `{}` from the preserved copy as valid JSON and remove the `{}` \
                 copy, then re-run the action.",
                self.path.display(),
                self.error,
                preserved.display(),
                self.path.display(),
                preserved.display(),
            ),
            None => format!(
                "approval store `{}` could not be read ({}) and its contents are \
                 untrustworthy. This action is refused rather than silently dropping \
                 saved allow/reject decisions. Repair the file to valid JSON, then \
                 re-run the action.",
                self.path.display(),
                self.error,
            ),
        }
    }
}

/// Why an approvals-file load failed closed (issue #297). Every read of the
/// store — the decision-boundary health gate, every grant/reject lookup,
/// and every locked read-modify-write cycle — resolves to `Ok` only on a
/// healthy, fully repaired store; corruption and unrepaired quarantine
/// residue alike surface as one of these refusals instead of empty
/// approval state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApprovalsLoadError {
    /// The live `approvals.json` itself failed to load. A parse failure
    /// quarantined the corrupt bytes (copied aside to a fresh owner-only
    /// file, never deleted); `preserved` is `None` when nothing was
    /// quarantined (an unreadable file, the cross-process lock could not
    /// be taken, or every preservation candidate failed).
    Corrupt(CorruptApprovalsStore),
    /// A quarantine copy from an earlier detection is still present: the
    /// store has not been repaired yet. Reads fail closed with the
    /// repair-oriented refusal instead of treating a missing (or
    /// restored-but-unverified) live file as the whole story.
    QuarantineResidue(PathBuf),
    /// The approvals directory could not be inspected for preserved
    /// quarantine copies, so a clear quarantine fence could not be
    /// established. The read fails closed instead of treating "residue
    /// status unknown" as "no residue" (issue #297): a preserved copy
    /// from an earlier detection may be hiding behind the enumeration
    /// failure.
    ResidueUnknown { dir: PathBuf, error: String },
    /// The store's contents parsed, but its owner-only posture could not
    /// be established: permissions could not be inspected through the
    /// open handle, or could not be tightened to owner-only. The parsed
    /// policy is refused rather than consumed while the file may stay
    /// readable beyond its owner (issue #297: the approval file must not
    /// be world-readable).
    NotOwnerOnly { path: PathBuf, error: String },
}

impl ApprovalsLoadError {
    /// Repair-oriented refusal, surfaced verbatim to the user at the
    /// approval-decision boundary.
    pub fn refusal_message(&self) -> String {
        match self {
            Self::Corrupt(corrupt) => corrupt.refusal_message(),
            Self::QuarantineResidue(residue) => quarantine_residue_refusal(residue),
            Self::ResidueUnknown { dir, error } => format!(
                "earlier quarantined approvals copies could not be ruled out: `{}` \
                 could not be searched ({}). This action is refused rather than assume \
                 the store was repaired. Restore read access to the directory and \
                 remove any preserved `{}-*` copy it contains, then re-run the action.",
                dir.display(),
                error,
                APPROVALS_QUARANTINE_PREFIX,
            ),
            Self::NotOwnerOnly { path, error } => format!(
                "approval store `{}` may be readable beyond its owner and could not \
                 be tightened to owner-only ({}). This action is refused rather than \
                 expose saved allow/reject decisions. Repair the file to owner-only \
                 (chmod 600) and re-run the action.",
                path.display(),
                error,
            ),
        }
    }
}

/// Load the `approvals.json` in `dir` (issue #297 fail-closed contract):
///
/// - a missing live file with no quarantine residue is `Ok(None)` — the
///   normal first-run state;
/// - a corrupt/unreadable file fails closed: the corrupt bytes are
///   quarantined for diagnosis — copied aside to a fresh owner-only file,
///   never deleted, never overwriting — and the error carries the
///   repair-oriented refusal; never a silent `Ok(None)` that drops every
///   standing entry;
/// - a quarantine copy from an earlier detection keeps the read failed
///   closed until the store is repaired — including one left by another
///   process, and including a directory whose residue status cannot be
///   established;
/// - a parsed store whose owner-only posture cannot be inspected or
///   enforced through the read handle is refused, never consumed.
///
/// The healthy path is a pure read: no lock, no side effects beyond
/// enforcing the owner-only posture on the file it read. Any failure
/// escalates under the same cross-process lock the read-modify-write
/// writers hold, so quarantine is serialized against concurrent store
/// replacement and always preserves exactly the bytes that failed
/// validation (see [`quarantine_corrupt_approvals`]).
fn load_approvals(dir: &Path) -> std::result::Result<Option<ApprovalsFile>, ApprovalsLoadError> {
    match probe_approvals(dir) {
        Ok(file) => Ok(file),
        Err(probe_error) => {
            // Re-read under the cross-process lock before preserving a
            // diagnosis: the object the probe read may have been replaced
            // by a writer or an external repair since, and what is
            // preserved must be diagnosed under the same ordering the
            // writers hold — never a stale snapshot of an object that no
            // longer occupies the live path.
            match lock_approvals(dir) {
                Ok(_lock) => load_approvals_locked(dir),
                Err(lock_error) => {
                    tracing::error!(
                        dir = %dir.display(),
                        error = %lock_error,
                        "cannot acquire the approvals lock to quarantine a failing store; failing the read closed without quarantining"
                    );
                    Err(probe_error)
                }
            }
        }
    }
}

/// Lock-free probe of the live `approvals.json`. Deliberately **does not
/// quarantine**: a failure here is escalated by [`load_approvals`] to a
/// locked re-read, so what is preserved is diagnosed under the same
/// ordering the writers hold — quarantining the probe's bytes without
/// the lock could preserve a stale diagnosis of an object a writer has
/// since replaced (issue #297).
fn probe_approvals(dir: &Path) -> std::result::Result<Option<ApprovalsFile>, ApprovalsLoadError> {
    let path = dir.join(APPROVALS_FILE);
    let Some(live) = read_live_approvals_bytes(&path)? else {
        // A missing live file is healthy only when no quarantine residue
        // lingers: a live file removed during repair — with a preserved
        // copy still present — means "unrepaired", not "no approval
        // state" (issue #297). A directory that cannot be inspected has
        // not established absence either, so the fence fails the read
        // closed.
        ensure_no_quarantine_residue(dir)?;
        return Ok(None);
    };
    match serde_json::from_slice(&live.bytes) {
        Ok(file) => {
            ensure_no_quarantine_residue(dir)?;
            enforce_owner_only(&live.file, &path)?;
            Ok(Some(file))
        }
        Err(error) => Err(ApprovalsLoadError::Corrupt(CorruptApprovalsStore {
            path,
            preserved: None,
            error: error.to_string(),
        })),
    }
}

/// The live approvals bytes plus the open handle they were read through.
struct LiveApprovalsBytes {
    file: std::fs::File,
    bytes: Vec<u8>,
}

/// Read the live `approvals.json` through an open handle so the bytes
/// validated, the owner-only enforcement, and any quarantine preservation
/// all bind the same file object (issue #297) — never whatever a
/// concurrent replacement leaves at the path. `Ok(None)` for a missing
/// live path (the healthy first-run state); open/read failures fail the
/// load closed as corrupt.
fn read_live_approvals_bytes(
    path: &Path,
) -> std::result::Result<Option<LiveApprovalsBytes>, ApprovalsLoadError> {
    let mut file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(ApprovalsLoadError::Corrupt(CorruptApprovalsStore {
                path: path.to_path_buf(),
                preserved: None,
                error: error.to_string(),
            }));
        }
    };
    let mut bytes = Vec::new();
    let read = {
        use std::io::Read as _;
        file.read_to_end(&mut bytes)
    };
    if let Err(error) = read {
        return Err(ApprovalsLoadError::Corrupt(CorruptApprovalsStore {
            path: path.to_path_buf(),
            preserved: None,
            error: error.to_string(),
        }));
    }
    Ok(Some(LiveApprovalsBytes { file, bytes }))
}

/// Locked half of [`load_approvals`]: assumes the caller holds the
/// cross-process approvals lock, so the bytes validated, the bytes
/// preserved, and any concurrent writer's replacement are strictly
/// ordered. Quarantine here is copy-aside preservation — the failing
/// bytes are written to a fresh owner-only copy through the same handle
/// they were read from, never a path-based rename, which cannot be
/// proven to act on the inspected object at the moment it takes effect
/// (issue #297).
fn load_approvals_locked(
    dir: &Path,
) -> std::result::Result<Option<ApprovalsFile>, ApprovalsLoadError> {
    // A residue from an earlier detection means "unrepaired": refuse
    // before even reading the live path, so a fresh corruption never piles
    // up additional quarantine copies and the standing-refusal semantics
    // hold. A directory that cannot be inspected is refused the same way
    // — absence of residue must be established, not assumed.
    ensure_no_quarantine_residue(dir)?;
    let path = dir.join(APPROVALS_FILE);
    let Some(live) = read_live_approvals_bytes(&path)? else {
        return Ok(None);
    };
    match serde_json::from_slice(&live.bytes) {
        Ok(parsed) => {
            enforce_owner_only(&live.file, &path)?;
            Ok(Some(parsed))
        }
        Err(error) => {
            let preserved = quarantine_corrupt_approvals(&path, &live.file, &live.bytes);
            Err(ApprovalsLoadError::Corrupt(CorruptApprovalsStore {
                path,
                preserved,
                error: error.to_string(),
            }))
        }
    }
}

/// Load the scoped `approvals.json` for one approvals dir, mapping any
/// fail-closed load refusal into the store-wide error type. A `None` dir
/// is `Ok(None)` — the scope is not reachable for this session.
fn scoped_approvals_file(dir: Option<&Path>) -> Result<Option<ApprovalsFile>> {
    let Some(dir) = dir else {
        return Ok(None);
    };
    match load_approvals(dir) {
        Ok(file) => Ok(file),
        Err(error) => Err(approvals_load_refusal_error(error)),
    }
}

/// Log and convert a fail-closed approvals load (issue #297) into the
/// decision refusal. The single logging point for every approvals-file
/// load failure: the decision-boundary health gate and every query-time
/// load route through here, so a corrupt or unrepaired store surfaces as
/// a visible, repair-oriented refusal wherever it is first read — never
/// as empty approval state.
fn approvals_load_refusal_error(error: ApprovalsLoadError) -> anyhow::Error {
    match &error {
        ApprovalsLoadError::Corrupt(corrupt) => tracing::error!(
            path = %corrupt.path.display(),
            preserved = ?corrupt.preserved,
            error = %corrupt.error,
            "corrupt approvals store detected; failing the approval decision closed"
        ),
        ApprovalsLoadError::QuarantineResidue(residue) => tracing::error!(
            residue = %residue.display(),
            "unrepaired approvals quarantine residue; failing the approval decision closed"
        ),
        ApprovalsLoadError::ResidueUnknown { dir, error } => tracing::error!(
            dir = %dir.display(),
            error = %error,
            "could not inspect the approvals directory for quarantine residue; failing the approval decision closed"
        ),
        ApprovalsLoadError::NotOwnerOnly { path, error } => tracing::error!(
            path = %path.display(),
            error = %error,
            "approvals store could not be enforced owner-only; failing the approval decision closed"
        ),
    }
    anyhow::Error::msg(error.refusal_message())
}

/// Preserve the corrupt approvals bytes for diagnosis and leave the live
/// path untouched (issue #297). The `bytes` are the exact bytes read from
/// the open `inspected` handle whose contents failed validation, so
/// preservation never depends on pathname identity: a rename or unlink
/// by path cannot be proven to act on the inspected object at the moment
/// it takes effect, so quarantine performs none. Instead the diagnosed
/// bytes are written to a fresh owner-only quarantine copy via
/// [`write_private_file`] (`create_new`, so an existing artifact is never
/// overwritten), and the live path is left exactly as found for the owner
/// to repair — including when a concurrent replacement now occupies it,
/// since those contents were never diagnosed.
///
/// The live object's owner-only posture is tightened best-effort through
/// the inspected handle: nothing is consumed from it either way (the
/// caller fails the read closed), so a tightening failure is logged, not
/// propagated. Collision-tolerant and best-effort overall: on failure the
/// original is left in place (the caller still fails closed) and `None`
/// is returned.
fn quarantine_corrupt_approvals(
    path: &Path,
    inspected: &std::fs::File,
    bytes: &[u8],
) -> Option<PathBuf> {
    let dir = path.parent()?;
    let stem = path.file_name()?.to_str()?.to_string();
    let millis = chrono::Utc::now().timestamp_millis();
    tighten_owner_only_best_effort(inspected, path);
    for attempt in 0..16u32 {
        let candidate = if attempt == 0 {
            dir.join(format!("{stem}.corrupt-{millis}"))
        } else {
            dir.join(format!("{stem}.corrupt-{millis}-{attempt}"))
        };
        match write_private_file(&candidate, bytes) {
            Ok(()) => return Some(candidate),
            Err(error) => {
                tracing::warn!(
                    path = %candidate.display(),
                    error = %error,
                    attempt,
                    "quarantine copy-aside attempt failed"
                );
            }
        }
    }
    tracing::error!(
        path = %path.display(),
        "quarantining the corrupt approvals store failed; refusing without preserving a copy"
    );
    None
}

/// Whether `path`'s directory entry still refers to the same filesystem
/// object as the open `file` handle (issue #297). Every destructive or
/// publishing effect on a pathname in this module — partial-copy cleanup,
/// the store's staged-temp rename, the lock stability fences — must be
/// able to prove it acts on the object this process created or holds, and
/// this is that proof: identity probed through the held handle (`fstat`)
/// and through the entry itself (`lstat`, never a follow — a symlink at
/// the name has its own identity, and a rename or unlink acts on the
/// entry). A missing entry is `Ok(false)`: the name no longer refers to
/// the held object.
///
/// Non-unix exemption: stable std exposes no object-identity comparison
/// primitive on those targets (`windows_by_handle`'s `file_index` /
/// `volume_serial_number` are still unstable), so a mismatch cannot be
/// proven there and the probe reports `Ok(true)`, preserving the
/// platform's existing behavior instead of stubbing a false refusal —
/// the same platform-honesty matrix `cockpit_host::private_fs` reports
/// through `PRIVATE_FS_POLICY`. The races this probe guards against are
/// pathname unlink-and-replace races; on Windows a name whose object is
/// held open through a std handle cannot be replaced underneath it (no
/// `FILE_SHARE_DELETE`), so the exposure is unix-shaped.
#[cfg(unix)]
fn same_object_at_path(file: &std::fs::File, path: &Path) -> std::io::Result<bool> {
    use std::os::unix::fs::MetadataExt as _;
    let held = file.metadata()?;
    match std::fs::symlink_metadata(path) {
        Ok(named) => Ok(held.dev() == named.dev() && held.ino() == named.ino()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

/// See the unix arm; the non-unix platform cannot prove a mismatch, so
/// the probe passes and the caller keeps its existing behavior.
#[cfg(not(unix))]
fn same_object_at_path(_file: &std::fs::File, _path: &Path) -> std::io::Result<bool> {
    Ok(true)
}

/// The held handle's current link count — the pre/post-act proof input
/// for [`discard_partial_private_candidate`]'s identity-guarded removal.
#[cfg(unix)]
fn held_link_count(file: &std::fs::File) -> std::io::Result<u64> {
    use std::os::unix::fs::MetadataExt as _;
    Ok(file.metadata()?.nlink())
}

/// Remove a failed private-file attempt's partial copy, identity-guarded
/// and proof-bound (issue #297): the removal happens only while the
/// candidate pathname still refers to the object this process created
/// and opened, proven through the held handle — never the pathname
/// alone — and its completion is proven, not assumed, after the act
/// through the same held handle. The handle stays open across the
/// removal precisely so that proof is possible; the previous
/// probe-then-drop-then-remove shape could neither bound the window nor
/// verify the outcome. Between the exclusive `create_new` and this
/// cleanup, a non-cooperating writer can unlink the partial candidate
/// and install a different object at the same name; a blind
/// `remove_file(path)` would then destroy that replacement — including
/// a preserved diagnostic artifact fencing the store.
///
/// Unix proof pair: immediately before the removal, the held object's
/// link count must be exactly 1 — the candidate entry is the only link
/// to the object this process created, and any other count (a link
/// added by another writer; the candidate's link already removed and
/// the name re-populated) is a substituted state in which nothing is
/// removed. The removal is then proven by the held object's link count
/// dropping to 0 exactly at it: the removed directory entry was the
/// object this process created. A removal whose post-act count still
/// shows a live link proves the removed entry was a substitution
/// (this process's object was renamed aside), and the tampering is
/// reported loudly instead of the cleanup silently completing or
/// silently destroying evidence. A mismatch on any probe is left
/// exactly as found (the caller still fails closed), and identity that
/// cannot be proven is never guessed: nothing is removed on a probe
/// failure. The name is only ever removed by this failure path — a
/// successful private file is the caller's to publish or keep.
///
/// Irreducible platform boundary: Unix has no delete-by-descriptor
/// primitive (Windows has `FileDispositionInfo`), so an entry unlinked
/// and replaced in the instant between the pre-removal proofs and the
/// `remove_file` below can still be removed by this failure path — the
/// same boundary
/// `cockpit_host::private_fs::held_directory`'s unlink accepts (it
/// proves the identical way, after the act) and the TUI clipboard's
/// `remove_verified` documents. The pre-removal probe plus link-count
/// guard make that instant as small as the platform admits and catch
/// every deterministically checkable substitution; the post-removal
/// proof converts each detectable one into a reported tamper, so
/// cleanup completion is only ever claimed for the object this process
/// created. A non-unix target keeps the documented platform-honesty
/// exemption of [`same_object_at_path`] (no stable link-count or
/// object-identity probe there): the pre-removal probe stands alone.
fn discard_partial_private_candidate(out: std::fs::File, path: &Path) {
    #[cfg(unix)]
    {
        // Pre-act link-count guard, taken first so the identity probe can
        // sit immediately adjacent to the removal: the held object must
        // be linked exactly once — by the candidate entry this process
        // created. Any other count (a link added by another writer; the
        // candidate's link already removed) is a substituted state in
        // which nothing is removed.
        match held_link_count(&out) {
            Ok(1) => {}
            Ok(links) => {
                tracing::warn!(
                    path = %path.display(),
                    links,
                    "a failed private-file candidate's link state is not exactly the \
                     one entry this process created; leaving its name untouched"
                );
                return;
            }
            Err(error) => {
                tracing::warn!(
                    path = %path.display(),
                    error = %error,
                    "cannot prove the link state of a failed private-file candidate; \
                     leaving its name untouched"
                );
                return;
            }
        }
    }
    // Pre-act identity probe, immediately adjacent to the removal: the
    // candidate pathname must still refer to the object this process
    // created and opened, proven through the held handle — never the
    // pathname alone.
    match same_object_at_path(&out, path) {
        Ok(true) => {}
        Ok(false) => {
            tracing::warn!(
                path = %path.display(),
                "a failed private-file candidate's name no longer refers to the object \
                 this process created; leaving whatever occupies it untouched"
            );
            return;
        }
        Err(error) => {
            tracing::warn!(
                path = %path.display(),
                error = %error,
                "cannot prove the identity of a failed private-file candidate; leaving \
                 its name untouched"
            );
            return;
        }
    }
    let removal = std::fs::remove_file(path);
    #[cfg(unix)]
    {
        // Post-act proof: the held object must have lost its one link
        // exactly at this removal, proving the removed entry was the
        // object this process created. A still-live link proves the
        // removed entry was a substitution — report the tamper; the
        // caller already fails closed either way.
        match (&removal, held_link_count(&out)) {
            (Ok(()), Ok(0)) => {}
            (Err(error), _) if error.kind() == std::io::ErrorKind::NotFound => {}
            (Err(error), _) => {
                tracing::warn!(
                    path = %path.display(),
                    error = %error,
                    "removing a failed private-file candidate failed; leaving any \
                     residue for the next cycle"
                );
            }
            (Ok(()), Ok(links)) => {
                tracing::error!(
                    path = %path.display(),
                    links,
                    "the entry removed from a failed private-file candidate's name \
                     was not the object this process created (its partial still has a \
                     live link — it was renamed aside); the substitution is reported, \
                     never silently cleaned"
                );
            }
            (Ok(()), Err(error)) => {
                tracing::error!(
                    path = %path.display(),
                    error = %error,
                    "the removal of a failed private-file candidate completed but its \
                     outcome could not be proven through the held handle; treating it \
                     as unproven, never as completed cleanup"
                );
            }
        }
    }
    #[cfg(not(unix))]
    {
        if let Err(error) = removal {
            if error.kind() != std::io::ErrorKind::NotFound {
                tracing::warn!(
                    path = %path.display(),
                    error = %error,
                    "removing a failed private-file candidate failed; leaving any \
                     residue for the next cycle"
                );
            }
        }
    }
}

/// Open a fresh exclusive (owner-only on unix) file at `path`
/// (`create_new`): the staging object for quarantine preservation copies
/// and the atomic store's temp. `create_new` never follows a pre-existing
/// symlink and never overwrites an existing artifact — the open fails
/// with `AlreadyExists` instead — and the mode is pinned to exactly
/// `0o600` through the open handle (creation modes are narrowed by
/// umask; a handle chmod is not), cleaning up its own partial copy if the
/// pin fails. The returned handle is the only proof of which object was
/// created; every later effect on `path` is bound to it through
/// [`same_object_at_path`].
#[cfg(unix)]
fn open_new_private_file(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
    let file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)?;
    if let Err(error) = file.set_permissions(std::fs::Permissions::from_mode(0o600)) {
        discard_partial_private_candidate(file, path);
        return Err(error);
    }
    Ok(file)
}

#[cfg(not(unix))]
fn open_new_private_file(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
}

/// Write `bytes` to a fresh owner-only file at `path`: quarantine's
/// preservation mechanism (issue #297). `create_new` means an existing
/// artifact is never overwritten — a colliding name fails with
/// `AlreadyExists` and the caller retries with the next candidate — and
/// the copy is created owner-only and pinned to exactly `0o600` through
/// the open handle (creation modes are narrowed by umask; a handle chmod
/// is not). A failed attempt removes its partial copy — but only while
/// the candidate pathname still refers to the object this process
/// created ([`discard_partial_private_candidate`]), so a replacement
/// artifact at the name is never destroyed — and no bogus quarantine
/// artifact is left fencing the store.
#[cfg(unix)]
fn write_private_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    let mut out = open_new_private_file(path)?;
    if let Err(error) = out.write_all(bytes) {
        discard_partial_private_candidate(out, path);
        return Err(error);
    }
    if let Err(error) = out.sync_all() {
        discard_partial_private_candidate(out, path);
        return Err(error);
    }
    Ok(())
}

#[cfg(not(unix))]
fn write_private_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    let mut out = open_new_private_file(path)?;
    if let Err(error) = out.write_all(bytes) {
        discard_partial_private_candidate(out, path);
        return Err(error);
    }
    if let Err(error) = out.sync_all() {
        discard_partial_private_candidate(out, path);
        return Err(error);
    }
    Ok(())
}

/// Enforce the owner-only posture on the open approvals file (unix)
/// through the read handle (issue #297: the saved approval state must
/// never stay readable beyond the owner). The live `approvals.json` can
/// pre-date the owner-only writer (an older version created it under an
/// ambient umask), so the read path must repair it on sight — and the
/// mode is both inspected and tightened through the handle, so the
/// enforced object is exactly the one whose bytes are being consumed,
/// never a concurrent replacement at the path. Inspection or tightening
/// failure fails the read closed instead of consuming policy that may
/// stay world-readable.
#[cfg(unix)]
fn enforce_owner_only(
    file: &std::fs::File,
    path: &Path,
) -> std::result::Result<(), ApprovalsLoadError> {
    use std::os::unix::fs::PermissionsExt as _;
    let not_owner_only = |error: std::io::Error| ApprovalsLoadError::NotOwnerOnly {
        path: path.to_path_buf(),
        error: error.to_string(),
    };
    let mode = file
        .metadata()
        .map_err(not_owner_only)?
        .permissions()
        .mode()
        & 0o777;
    if mode == 0o600 {
        return Ok(());
    }
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
        .map_err(not_owner_only)
}

/// Off unix there are no owner/group/other mode bits to inspect or
/// tighten (matching [`open_new_private_file`]'s no-mode fallback), so there
/// is no owner-only posture to enforce; the read stays valid.
#[cfg(not(unix))]
fn enforce_owner_only(
    _file: &std::fs::File,
    _path: &Path,
) -> std::result::Result<(), ApprovalsLoadError> {
    Ok(())
}

/// Best-effort owner-only tightening for a file whose contents are never
/// consumed: the corrupt live store during quarantine (the read fails
/// closed regardless, and the preserved copy is owner-only by
/// construction). Inspection or tightening failure is logged, never
/// propagated.
#[cfg(unix)]
fn tighten_owner_only_best_effort(file: &std::fs::File, path: &Path) {
    if let Err(refusal) = enforce_owner_only(file, path) {
        tracing::warn!(
            path = %path.display(),
            error = %refusal.refusal_message(),
            "could not tighten the corrupt approvals store to owner-only; nothing is \
             consumed from it and the read stays failed closed"
        );
    }
}

#[cfg(not(unix))]
fn tighten_owner_only_best_effort(_file: &std::fs::File, _path: &Path) {}

/// Find a preserved quarantine copy in `dir`, if any. Its presence keeps
/// approval-dependent actions refused (the store has not been repaired
/// yet), including a quarantine left by another process.
///
/// Fails closed on enumeration failure (issue #297): an unreadable
/// directory or entry has not established absence of residue, so `Err`
/// lets callers refuse instead of treating an unestablishable fence as a
/// clear one. A missing directory is the healthy first-run state — no
/// residue can exist there.
fn find_quarantine_residue(dir: &Path) -> std::io::Result<Option<PathBuf>> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    for entry in entries {
        // An entry that cannot be read may be the residue itself: fail
        // the scan rather than silently skip it.
        let path = entry?.path();
        let is_residue = path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with(APPROVALS_QUARANTINE_PREFIX));
        if is_residue {
            return Ok(Some(path));
        }
    }
    Ok(None)
}

/// Fail-closed quarantine-fence check: verifies that no preserved
/// quarantine copy lingers in `dir`. `Ok(())` means the fence is
/// established clear; a found residue — or a directory that cannot be
/// inspected to rule one out — fails the load closed (issue #297).
fn ensure_no_quarantine_residue(dir: &Path) -> std::result::Result<(), ApprovalsLoadError> {
    match find_quarantine_residue(dir) {
        Ok(None) => Ok(()),
        Ok(Some(residue)) => Err(ApprovalsLoadError::QuarantineResidue(residue)),
        Err(error) => Err(ApprovalsLoadError::ResidueUnknown {
            dir: dir.to_path_buf(),
            error: error.to_string(),
        }),
    }
}

/// Refusal for a store whose corruption was already quarantined earlier
/// (a live file may parse again — or be missing — but the owner has not
/// resolved the preserved copy yet). Fail closed until the residue is
/// resolved.
fn quarantine_residue_refusal(residue: &Path) -> String {
    format!(
        "a corrupt approvals store was quarantined earlier; its original bytes are \
         preserved at `{}` (never deleted). Approval-dependent actions are refused \
         until the store is repaired: restore or repair `{}` to valid JSON and \
         remove the preserved copy, then re-run the action.",
        residue.display(),
        residue.with_file_name(APPROVALS_FILE).display(),
    )
}

/// Open the `approvals.json.lock` object (creating it if absent), the
/// stable lock object every read-modify-write cycle for a directory must
/// share (issue #297). Never truncates: the lock file holds no data, and
/// a truncating open would destroy whatever a pre-existing symlink at
/// the name points at. Unix opens with `O_NOFOLLOW`, so a planted symlink
/// at the lock path is refused with `ELOOP` — acquisition fails closed —
/// instead of silently locking (and tightening the mode of) the
/// symlink's target. The mode is pinned to exactly `0o600` through the
/// returned handle so a stale or permissive lock file is repaired on
/// sight, and the tightened object is exactly the one this process
/// opened — never a concurrent replacement at the path.
#[cfg(unix)]
fn open_approvals_lock_file(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    Ok(file)
}

/// See the unix arm; neither truncation nor a follow happens here either,
/// and the non-unix platform-honesty exemption for no-follow opens and
/// identity probes is documented on [`same_object_at_path`] — stable std
/// offers neither on this target.
#[cfg(not(unix))]
fn open_approvals_lock_file(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(path)
}

/// Open the cross-process advisory lock guarding `<dir>/approvals.json`
/// and block until it is held exclusively (issue #297: concurrent writers
/// used to be able to clobber the store with a stale read-modify-write
/// snapshot). The lock is released when the returned file is dropped.
///
/// The lock is bound to a stable lock **object**, not merely to the lock
/// pathname: a name unlinked or replaced after one caller's open would
/// leave two callers holding exclusive locks on two different inodes —
/// both "successfully locked", neither serialized, both free to
/// clobber each other with stale snapshots. Acquisition therefore
/// verifies, through the held handle, that the pathname still refers to
/// the object just locked, and re-acquires from scratch (bounded) when
/// it does not, so every acquirer converges on the object the name
/// currently names. A path that keeps being replaced fails the
/// acquisition closed with a visible error — an actively replaced lock
/// path is an attack or a broken repair, never something to proceed
/// through. A holder whose lock object is replaced mid-cycle is fenced
/// at publish time by [`store_approvals`].
fn lock_approvals(dir: &Path) -> Result<std::fs::File> {
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let lock_path = dir.join(APPROVALS_LOCK_FILE);
    const ACQUIRE_ATTEMPTS: u32 = 8;
    for attempt in 0..ACQUIRE_ATTEMPTS {
        let file = open_approvals_lock_file(&lock_path)
            .with_context(|| format!("opening {}", lock_path.display()))?;
        // `File::lock` is the std blocking exclusive advisory lock (flock on
        // unix, LockFileEx on windows): cross-process and cross-thread.
        file.lock()
            .with_context(|| format!("locking {}", lock_path.display()))?;
        // Identity fence: the object just locked must still be the one the
        // lock pathname refers to. A mismatch means the name was replaced
        // between the open and the lock — release this handle and take the
        // current object instead.
        match same_object_at_path(&file, &lock_path) {
            Ok(true) => return Ok(file),
            Ok(false) => {
                tracing::warn!(
                    path = %lock_path.display(),
                    attempt,
                    "the approvals lock path was replaced while the lock was being \
                     acquired; retrying against the current lock object"
                );
                drop(file);
            }
            Err(error) => {
                return Err(anyhow::Error::from(error)).with_context(|| {
                    format!("verifying the lock object at {}", lock_path.display())
                });
            }
        }
    }
    anyhow::bail!(
        "the approvals lock at {} kept being replaced while it was being acquired; \
         refusing to serialize on an unstable lock object",
        lock_path.display()
    );
}

/// Run one read-modify-write cycle on `<dir>/approvals.json` under the
/// cross-process lock (load → mutate → atomic store while holding
/// `approvals.json.lock`), so concurrent writers serialize instead of
/// clobbering each other's entries with stale snapshots. The closure
/// returns `(changed, value)`; the file is rewritten only when `changed`.
/// A corrupt/unreadable store — or one with an unrepaired quarantine
/// residue — fails closed with [`ApprovalsLoadError::refusal_message`]:
/// never a silent `unwrap_or_default()` that would overwrite the corrupt
/// bytes and drop every standing entry. The lock is one verified shared
/// object ([`lock_approvals`]), and the publish proves that object at
/// the publication boundary — both sides of the rename
/// ([`store_approvals`]) — a lock file replaced mid-cycle aborts the
/// write closed instead of racing whatever else now serializes on the
/// replacement.
fn mutate_approvals<R>(
    dir: &Path,
    mutate: impl FnOnce(&mut ApprovalsFile) -> (bool, R),
) -> Result<R> {
    let _lock = lock_approvals(dir)?;
    // The lock is already held here, so the load must take the locked
    // entry point directly (never [`load_approvals`], which would block
    // re-acquiring the lock it already holds).
    let mut file = match load_approvals_locked(dir) {
        Ok(file) => file.unwrap_or_default(),
        Err(error) => return Err(anyhow::Error::msg(error.refusal_message())),
    };
    let (changed, value) = mutate(&mut file);
    if changed {
        store_approvals(dir, &_lock, &file)?;
    }
    Ok(value)
}

/// Durably commit a rename into `dir`: fsync the containing directory so
/// the new directory entry survives a crash (issue #297). The temp file's
/// `sync_all` flushes the contents but not the directory entry — without
/// this, a crash could lose the committed rename, the live approvals
/// store would vanish, and later decisions would mistake the store for
/// a healthy first run (missing live files are healthy by design).
#[cfg(unix)]
fn sync_dir(dir: &Path) -> std::io::Result<()> {
    std::fs::File::open(dir)?.sync_all()
}

/// A directory fsync is not a meaningful operation on non-unix platforms;
/// the atomic write relies on the rename's own ordering guarantees there.
#[cfg(not(unix))]
fn sync_dir(_dir: &Path) -> std::io::Result<()> {
    Ok(())
}

/// Create the staging temp for one atomic store publish: a fresh
/// `create_new` owner-only file under an unpredictable
/// `approvals.json.tmp-<hex>` name in `dir` (issue #297). The
/// unpredictable name plus exclusive creation means no pre-existing
/// artifact — a stale fixed-name temp, or a symlink planted at any
/// guessable staging name — is ever followed, truncated, or
/// overwritten, and a non-cooperating writer can neither pre-plant nor
/// guess which entry the publish will rename. Collisions retry; bounded
/// exhaustion fails the write closed.
fn create_private_store_temp(dir: &Path) -> Result<(std::fs::File, PathBuf)> {
    const ATTEMPTS: u8 = 32;
    for _ in 0..ATTEMPTS {
        let candidate = dir.join(format!("{APPROVALS_FILE}.tmp-{}", random_hex()));
        match open_new_private_file(&candidate) {
            Ok(out) => return Ok((out, candidate)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(anyhow::Error::from(error))
                    .with_context(|| format!("creating {}", candidate.display()));
            }
        }
    }
    anyhow::bail!(
        "could not create a unique private temp file in {}",
        dir.display()
    )
}

/// Sixteen random bytes as lowercase hex: the unpredictable staging-name
/// entropy for [`create_private_store_temp`].
fn random_hex() -> String {
    use rand::Rng as _;
    use std::fmt::Write as _;
    let mut raw = [0_u8; 16];
    rand::rng().fill_bytes(&mut raw);
    let mut out = String::with_capacity(raw.len() * 2);
    for byte in raw {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Deterministic seam for the publish-boundary race tests (issue #297):
/// fires immediately after the staged temp is written and synced, before
/// the pre-act proofs, so a test can substitute the staged entry or
/// replace the lock pathname in the exact window the proofs must catch.
#[cfg(test)]
thread_local! {
    static AFTER_STAGING_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
}

/// Deterministic seam for the publish-boundary race tests (issue #297):
/// fires after the pre-act proofs and immediately before the rename, so
/// a test can land a substitution in the pre-act-proof→rename window
/// that the post-act proofs must detect.
#[cfg(test)]
thread_local! {
    static BEFORE_PUBLISH_RENAME_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn run_after_staging_hook() {
    if let Some(hook) = AFTER_STAGING_HOOK.with(|slot| slot.borrow_mut().take()) {
        hook();
    }
}

#[cfg(not(test))]
fn run_after_staging_hook() {}

#[cfg(test)]
fn run_before_publish_rename_hook() {
    if let Some(hook) = BEFORE_PUBLISH_RENAME_HOOK.with(|slot| slot.borrow_mut().take()) {
        hook();
    }
}

#[cfg(not(test))]
fn run_before_publish_rename_hook() {}

/// Write `file` to `<dir>/approvals.json` atomically (owner-only exclusive
/// temp file + fsync + identity-proof-bound rename + directory fsync) so
/// a crash mid-write can't corrupt the store, a crash after the rename
/// can't lose it, and the file is never world-readable. Called with the
/// approvals lock held; `lock` is that held lock object.
///
/// Two invariants bind the publish (issue #297), each proven at the
/// publication boundary — the pre-act proofs run immediately before
/// the rename and the post-act proofs immediately after it, so success
/// is only ever reported for a rename whose entry effects are proven
/// through the held handles on both sides of the act:
///
/// - **The installed store is the object that was written.** The staged
///   temp is a fresh `create_new` file under an unpredictable name
///   ([`create_private_store_temp`]) — never a guessable fixed `.tmp`
///   whose entry a pre-planted symlink could steer the writer into
///   truncating. Before the rename, the staged entry must still refer
///   to the object this process wrote and synced, proven through the
///   held handle ([`same_object_at_path`]); a replacement at the staged
///   name is left untouched and the publish fails closed. After the
///   rename, the live entry must be proven — through the same held
///   handle — to be that exact written-and-synced object: a
///   substitution landing in the pre-act-proof→rename window (the
///   name is enumerable after creation) makes the rename install the
///   replacement's bytes, and the post-act proof detects it and fails
///   the write closed with a tamper error instead of reporting success —
///   the same detected-not-silent outcome the TUI clipboard
///   `file_publish` publish established for its identical race. Every
///   abort after staging removes this process's own partial through
///   [`discard_partial_private_candidate`] (identity-guarded itself), so
///   a failed publish leaves no temp residue.
/// - **The serialization boundary is valid at publication.** The held
///   lock object must still be the one the lock pathname refers to —
///   proven immediately before the rename and proven again
///   immediately after it: a lock file replaced during this cycle (or
///   in the rename window) means the exclusion this write relies on
///   is gone, so the write fails closed with a visible error instead
///   of silently racing whatever else now serializes on the
///   replacement.
fn store_approvals(dir: &Path, lock: &std::fs::File, file: &ApprovalsFile) -> Result<()> {
    let path = dir.join(APPROVALS_FILE);
    let lock_path = dir.join(APPROVALS_LOCK_FILE);
    let json = serde_json::to_vec_pretty(file).context("serializing approvals")?;
    let (mut out, tmp) = create_private_store_temp(dir)?;
    {
        use std::io::Write as _;
        if let Err(error) = out.write_all(&json).and_then(|()| out.sync_all()) {
            let write_error =
                anyhow::Error::from(error).context(format!("writing {}", tmp.display()));
            discard_partial_private_candidate(out, &tmp);
            return Err(write_error);
        }
    }
    run_after_staging_hook();
    // Publish boundary, pre-act proof 1 — identity-bind the rename to the
    // object that was written: the staged entry must still be the one
    // this process created, wrote, and synced. A replacement at the name
    // is not ours to remove or install — leave it untouched and abort
    // the publish.
    match same_object_at_path(&out, &tmp) {
        Ok(true) => {}
        Ok(false) => anyhow::bail!(
            "aborting the approvals store write: the staged temp at {} was \
             substituted before the rename; the store was left untouched",
            tmp.display()
        ),
        Err(error) => {
            discard_partial_private_candidate(out, &tmp);
            return Err(anyhow::Error::from(error))
                .with_context(|| format!("verifying the staged temp at {}", tmp.display()));
        }
    }
    // Publish boundary, pre-act proof 2 — serialization fence at
    // publication: this publish is valid only while the lock object this
    // cycle holds is still the one the lock pathname names. A replaced
    // lock file means the boundary is gone — remove this process's own
    // staged partial (never the replacement) and fail closed with the
    // store untouched.
    match same_object_at_path(lock, &lock_path) {
        Ok(true) => {}
        Ok(false) => {
            discard_partial_private_candidate(out, &tmp);
            anyhow::bail!(
                "the approvals lock at {} no longer refers to the lock object held \
                 for this write; the store was left untouched",
                lock_path.display()
            );
        }
        Err(error) => {
            discard_partial_private_candidate(out, &tmp);
            return Err(anyhow::Error::from(error))
                .with_context(|| format!("verifying the lock object at {}", lock_path.display()));
        }
    }
    run_before_publish_rename_hook();
    // The publish act.
    if let Err(error) = std::fs::rename(&tmp, &path) {
        let rename_error =
            anyhow::Error::from(error).context(format!("renaming into {}", path.display()));
        // The staged entry is still ours here, so clean it up through the
        // same identity guard (a swap in between leaves the replacement
        // untouched, never destroyed).
        discard_partial_private_candidate(out, &tmp);
        return Err(rename_error);
    }
    // Publish boundary, post-act proof 1 — the installed entry must be
    // the exact object this process wrote and synced, proven through the
    // still-held staged handle. A mismatch means a substitution landed
    // in the pre-act-proof→rename window and the rename installed its
    // entry: report the publish as failed (fail closed with a visible
    // tamper error) — a write never reports success while installing
    // some other object's bytes.
    match same_object_at_path(&out, &path) {
        Ok(true) => {}
        Ok(false) => anyhow::bail!(
            "the approvals store write installed an entry at {} that is not the \
             staged object this process wrote and synced (the staged temp was \
             substituted during the rename); reporting the publish as failed",
            path.display()
        ),
        Err(error) => {
            return Err(anyhow::Error::from(error))
                .with_context(|| format!("verifying the published store at {}", path.display()));
        }
    }
    // Publish boundary, post-act proof 2 — the serialization boundary must
    // have held across the publish: the lock pathname must still refer to
    // the held lock object. A replacement landing in the rename window
    // means another writer may have serialized on the replacement and
    // raced this publish; report the write as failed instead of claiming
    // a serialized success.
    match same_object_at_path(lock, &lock_path) {
        Ok(true) => {}
        Ok(false) => anyhow::bail!(
            "the approvals lock at {} was replaced while the store was being \
             published; the serialization boundary this write relied on is gone, \
             so the write is reported as failed",
            lock_path.display()
        ),
        Err(error) => {
            return Err(anyhow::Error::from(error))
                .with_context(|| format!("verifying the lock object at {}", lock_path.display()));
        }
    }
    sync_dir(dir).with_context(|| format!("syncing {}", dir.display()))?;
    Ok(())
}

fn now_epoch_seconds() -> i64 {
    chrono::Utc::now().timestamp()
}

/// Absolutize + lexically normalize a path to a stable storage string.
/// We don't canonicalize (the path may not exist yet — part 2 grants
/// access before creation), but we do resolve `.`/`..` lexically and
/// join relative paths onto the explicit session/project base so prefix
/// checks are sound and independent of the daemon process cwd.
fn normalize_path(path: &Path, base: &Path) -> String {
    let abs = if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    };
    lexical_normalize(&abs).to_string_lossy().into_owned()
}

/// Resolve `.` and `..` components lexically without touching the
/// filesystem. A leading `..` (path escaping root) is kept as-is.
fn lexical_normalize(path: &Path) -> PathBuf {
    use std::path::Component;
    let mut out = PathBuf::new();
    for comp in path.components() {
        match comp {
            Component::CurDir => {}
            Component::ParentDir => {
                if !out.pop() {
                    out.push("..");
                }
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// Whether a stored path grant `stored` covers `candidate`: equal, or
/// `candidate` is a descendant of `stored` (prefix match on path
/// components, not raw string prefix — so `/a/bc` is not covered by
/// `/a/b`).
fn path_covers(stored: &str, candidate: &str) -> bool {
    let stored = Path::new(stored);
    let candidate = Path::new(candidate);
    candidate == stored || candidate.starts_with(stored)
}

/// Parse a stored verdict string. An unrecognized value (corrupt row /
/// hand-edited file) reads as `None` — no rule applies, so the guard
/// falls back to prompting, the safe default.
fn parse_verdict(s: &str) -> Option<LoopVerdict> {
    match s {
        "accept" => Some(LoopVerdict::Accept),
        "reject" => Some(LoopVerdict::Reject),
        _ => None,
    }
}

/// Loop-guard verdict for `signature` from a loaded approvals file.
/// `reject` is checked first so a hand-edited file that somehow lists a
/// signature in both sets resolves to the safe (blocking) verdict.
fn file_loop_rule(file: &ApprovalsFile, signature: &str) -> Option<LoopVerdict> {
    if file.loop_reject.contains(signature) {
        Some(LoopVerdict::Reject)
    } else if file.loop_accept.contains(signature) {
        Some(LoopVerdict::Accept)
    } else {
        None
    }
}

/// Serialize a JSON value with object keys sorted recursively, so two
/// semantically-identical inputs that differ only in key order produce
/// the same string (and thus the same loop signature).
fn canonical_json(value: &serde_json::Value) -> String {
    use serde_json::Value;
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut out = String::from("{");
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                // The key itself is JSON-escaped via serde so embedded
                // quotes/control chars can't break the framing.
                out.push_str(&Value::String((*k).clone()).to_string());
                out.push(':');
                out.push_str(&canonical_json(&map[*k]));
            }
            out.push('}');
            out
        }
        Value::Array(items) => {
            let mut out = String::from("[");
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&canonical_json(item));
            }
            out.push(']');
            out
        }
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_bound_grant_keys_are_disjoint() {
        let a = mcp_tool_key_for(Some("agent-a"), "default", "svc", "search");
        let b = mcp_tool_key_for(Some("agent-b"), "default", "svc", "search");
        let scope = mcp_tool_key("svc", "search");
        assert_ne!(a, b, "grants for agent A must not satisfy agent B");
        assert_ne!(
            a, scope,
            "agent-bound keys stay disjoint from scope-level keys"
        );
        assert!(a.starts_with("agent:agent-a/"));
        assert_eq!(
            mcp_server_connect_key_for(
                Some("agent-a"),
                "default",
                "svc",
                "stdio command=x args=[]"
            ),
            mcp_tool_key_for(
                Some("agent-a"),
                "default",
                "svc",
                "\u{0}connect:stdio command=x args=[]"
            )
        );
    }
    use crate::approval::classify::SimpleCommandInfo;
    use crate::config::extended::DangerousFlagRule;

    fn cmd_info(program: &str, sub: Option<&str>, wrapper: bool) -> SimpleCommandInfo {
        let key = ApprovalKey {
            program: program.to_string(),
            subcommand: sub.map(str::to_string),
            option_names: std::collections::BTreeSet::new(),
        };
        SimpleCommandInfo {
            program: program.to_string(),
            normalized_program: program.to_string(),
            subcommand: sub.map(str::to_string),
            args: sub.into_iter().map(str::to_string).collect(),
            key,
            wrapper,
            execution_bearing_option: false,
            risk: Default::default(),
            span: None,
        }
    }

    fn test_project_approvals_dir(project: &Path, base: &Path) -> PathBuf {
        let name = project
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("project");
        base.join("project-approvals").join(name)
    }

    fn point_project_scope(store: &mut GrantStore, project: &Path, base: &Path) {
        store.project_root = Some(project.to_path_buf());
        store.project_approvals_dir = Some(test_project_approvals_dir(project, base));
    }

    fn test_project_dir(store: &GrantStore) -> &Path {
        store.project_approvals_dir.as_deref().unwrap()
    }

    /// Build a store backed by an in-memory DB, with project root + file
    /// approval dirs pointed at temp dirs so scopes are exercised hermetically.
    pub(super) fn test_store(project: &Path, global: PathBuf) -> (GrantStore, uuid::Uuid) {
        let (store, sid, _) = test_store_with_project_id(project, global);
        (store, sid)
    }

    /// Like [`test_store`] but also returns the session's machine-local
    /// `project_id` so image-generation grant scopes can be exercised.
    pub(super) fn test_store_with_project_id(
        project: &Path,
        global: PathBuf,
    ) -> (GrantStore, uuid::Uuid, String) {
        let db = Db::open_in_memory().unwrap();
        let session = crate::session::Session::create_for_test(
            db.clone(),
            project.to_path_buf(),
            "builder",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap();
        let sid = session.id;
        let project_id = session.project_id.clone();
        let mut store = GrantStore::new(
            db,
            sid,
            project.to_path_buf(),
            SessionConfigHandle::from_disk_for_tests(project),
        );
        // Force deterministic scopes regardless of the test host's git
        // state: the temp project IS the root, approvals/global are temp dirs.
        point_project_scope(&mut store, project, &global);
        store.global_dir = Some(global);
        (store, sid, project_id)
    }

    #[tokio::test]
    async fn db_async_approval_decision_write_is_visible_to_subsequent_gate_read() {
        let tmp = tempfile::tempdir().unwrap();
        let global = tempfile::tempdir().unwrap();
        let (store, _) = test_store(tmp.path(), global.path().to_path_buf());
        let info = cmd_info("cargo", Some("test"), false);

        store
            .record_command(&info, RiskTier::Mutating, Scope::Project)
            .await
            .unwrap();

        assert!(store.is_command_granted(&info.key).await);
        assert_eq!(
            store.command_grant(&info.key).await.unwrap(),
            Some(CommandGrant {
                scope: Scope::Project,
                granted_tier: RiskTier::Mutating,
            })
        );
    }

    #[tokio::test]
    async fn db_async_approval_cancelled_decision_write_is_all_or_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let global = tempfile::tempdir().unwrap();
        let (store, _) = test_store(tmp.path(), global.path().to_path_buf());
        let info = cmd_info("cargo", Some("build"), false);

        let cancelled = store.record_command(&info, RiskTier::Ordinary, Scope::Session);
        drop(cancelled);

        assert_eq!(store.command_grant(&info.key).await.unwrap(), None);
        assert!(!store.is_command_granted(&info.key).await);

        store
            .record_command(&info, RiskTier::Ordinary, Scope::Session)
            .await
            .unwrap();
        assert!(store.is_command_granted(&info.key).await);
    }

    #[tokio::test]
    async fn db_async_approval_denial_is_never_lost_under_concurrent_reads() {
        let tmp = tempfile::tempdir().unwrap();
        let global = tempfile::tempdir().unwrap();
        let (store, _) = test_store(tmp.path(), global.path().to_path_buf());
        let info = cmd_info("rm", Some("-rf"), false);

        store
            .record_command_reject(&info, Scope::Session)
            .await
            .unwrap();

        let (first, second, third, grant) = tokio::join!(
            store.command_reject_scope(&info.key),
            store.command_reject_scope(&info.key),
            store.is_command_rejected(&info.key),
            store.command_grant(&info.key),
        );

        assert_eq!(first.unwrap(), Some(Scope::Session));
        assert_eq!(second.unwrap(), Some(Scope::Session));
        assert!(third);
        assert_eq!(grant.unwrap(), None);
    }

    fn column_type(conn: &rusqlite::Connection, table: &str, column: &str) -> Result<String> {
        let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(1)?, row.get::<_, String>(2)?))
        })?;
        for row in rows {
            let (name, ty) = row?;
            if name == column {
                return Ok(ty);
            }
        }
        anyhow::bail!("missing column {table}.{column}")
    }

    #[tokio::test]
    async fn session_grant_then_granted() {
        let tmp = tempfile::tempdir().unwrap();
        let global = tempfile::tempdir().unwrap();
        let (store, _) = test_store(tmp.path(), global.path().to_path_buf());
        let info = cmd_info("gh", Some("pr"), false);
        assert!(!store.is_command_granted(&info.key).await);
        store
            .record_command(&info, info.risk.tier, Scope::Session)
            .await
            .unwrap();
        assert!(store.is_command_granted(&info.key).await);
        // A different subcommand still prompts.
        let other = cmd_info("gh", Some("repo"), false);
        assert!(!store.is_command_granted(&other.key).await);
    }

    #[tokio::test]
    async fn command_grant_records_and_returns_issue_tier() {
        let tmp = tempfile::tempdir().unwrap();
        let global = tempfile::tempdir().unwrap();
        let (store, _) = test_store(tmp.path(), global.path().to_path_buf());
        let mut info = cmd_info("git", Some("push"), false);
        info.risk.tier = RiskTier::Destructive;

        store
            .record_command(&info, info.risk.tier, Scope::Session)
            .await
            .unwrap();

        assert_eq!(
            store.command_grant(&info.key).await.unwrap(),
            Some(CommandGrant {
                scope: Scope::Session,
                granted_tier: RiskTier::Destructive,
            })
        );
    }

    #[tokio::test]
    async fn approvals_file_commands_serializes_as_tier_map() {
        let file = ApprovalsFile {
            commands: BTreeMap::from([(
                "git push".to_string(),
                CommandGrantRecord::new(RiskTier::Destructive),
            )]),
            ..ApprovalsFile::default()
        };

        let json = serde_json::to_value(&file).unwrap();
        assert_eq!(
            json["commands"],
            serde_json::json!({
                "git push": {
                    "riskTier": "destructive"
                }
            })
        );
    }

    #[tokio::test]
    async fn unparseable_persisted_tier_is_treated_as_no_grant() {
        let tmp = tempfile::tempdir().unwrap();
        let global = tempfile::tempdir().unwrap();
        let (store, _) = test_store(tmp.path(), global.path().to_path_buf());
        let info = cmd_info("git", Some("push"), false);

        let _lock = lock_approvals(test_project_dir(&store)).unwrap();
        store_approvals(
            test_project_dir(&store),
            &_lock,
            &ApprovalsFile {
                commands: BTreeMap::from([(
                    info.key.as_storage_str(),
                    CommandGrantRecord {
                        risk_tier: "catastrophic".to_string(),
                    },
                )]),
                ..ApprovalsFile::default()
            },
        )
        .unwrap();

        assert_eq!(store.command_grant(&info.key).await.unwrap(), None);
        assert!(!store.is_command_granted(&info.key).await);
    }

    #[tokio::test]
    async fn command_reject_ignores_invocation_tier() {
        let tmp = tempfile::tempdir().unwrap();
        let global = tempfile::tempdir().unwrap();
        let (store, _) = test_store(tmp.path(), global.path().to_path_buf());
        let mut info = cmd_info("git", Some("push"), false);

        store
            .record_command_reject(&info, Scope::Session)
            .await
            .unwrap();
        info.risk.tier = RiskTier::Destructive;

        assert_eq!(
            store.command_reject_scope(&info.key).await.unwrap(),
            Some(Scope::Session)
        );
    }

    #[tokio::test]
    async fn project_grant_covers_subcommand_args_and_persists() {
        let tmp = tempfile::tempdir().unwrap();
        let global = tempfile::tempdir().unwrap();
        let (store, sid) = test_store(tmp.path(), global.path().to_path_buf());
        let info = cmd_info("gh", Some("pr"), false);
        store
            .record_command(&info, info.risk.tier, Scope::Project)
            .await
            .unwrap();

        // `gh pr create ...` derives the same key → granted, no prompt.
        let create = cmd_info("gh", Some("pr"), false);
        assert!(store.is_command_granted(&create.key).await);
        // `gh repo ...` is a different key → still prompts.
        let repo = cmd_info("gh", Some("repo"), false);
        assert!(!store.is_command_granted(&repo.key).await);

        // Survives reload: a fresh store over the same DB + dirs sees it.
        let db2 = store.db.clone();
        let mut reloaded = GrantStore::new(
            db2,
            sid,
            tmp.path().to_path_buf(),
            SessionConfigHandle::from_disk_for_tests(tmp.path()),
        );
        point_project_scope(&mut reloaded, tmp.path(), global.path());
        reloaded.global_dir = Some(global.path().to_path_buf());
        assert!(reloaded.is_command_granted(&info.key).await);
    }

    #[tokio::test]
    async fn project_grant_writes_machine_local_not_repo() {
        let env = tempfile::tempdir().unwrap();
        let _home =
            cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at_async(env.path()).await;
        let project = tempfile::tempdir_in(env.path()).unwrap();
        let status = std::process::Command::new("git")
            .args(["init", "-q"])
            .current_dir(project.path())
            .status()
            .unwrap();
        assert!(status.success());
        let policy = crate::config::trust::WorkspaceTrustPolicy {
            root: crate::config::trust::resolve_trust_root(project.path()).unwrap(),
            mode: crate::db::workspace_trust::WorkspaceTrustMode::Trust,
        };
        crate::config::trust::scope_workspace_trust_policy(policy, async {
            let db = Db::open_in_memory().unwrap();
            let session = crate::session::Session::create_for_test(
                db.clone(),
                project.path().to_path_buf(),
                "builder",
                crate::session::test_redaction_key_resolver(),
            )
            .unwrap();
            let store = GrantStore::new(
                db,
                session.id,
                project.path().to_path_buf(),
                SessionConfigHandle::from_disk_for_tests(project.path()),
            );
            let project_dir = project_approvals_dir(project.path()).unwrap();
            assert_eq!(
                store.project_approvals_dir.as_deref(),
                Some(project_dir.as_path())
            );

            let info = cmd_info("gh", Some("pr"), false);
            store
                .record_command(&info, info.risk.tier, Scope::Project)
                .await
                .unwrap();

            assert!(project_dir.join(APPROVALS_FILE).exists());
            assert!(!project.path().join(".cockpit/approvals.json").exists());
            assert!(!project_dir.starts_with(project.path()));
        })
        .await;
    }

    #[tokio::test]
    async fn repo_side_project_approvals_file_is_ignored_even_when_trusted() {
        let tmp = tempfile::tempdir().unwrap();
        let global = tempfile::tempdir().unwrap();
        let (store, _) = test_store(tmp.path(), global.path().to_path_buf());
        let repo_dir = tmp.path().join(".cockpit");
        let command = cmd_info("cargo", Some("test"), false);
        let granted_dir = tmp.path().join("secrets");
        let _lock = lock_approvals(&repo_dir).unwrap();
        store_approvals(
            &repo_dir,
            &_lock,
            &ApprovalsFile {
                commands: BTreeMap::from([(
                    command.key.as_storage_str(),
                    CommandGrantRecord::new(RiskTier::Ordinary),
                )]),
                paths: BTreeMap::from([(
                    normalize_path(&granted_dir, store.cwd()),
                    SandboxPathAccess::ReadWrite,
                )]),
                ..ApprovalsFile::default()
            },
        )
        .unwrap();

        assert!(!crate::approval::command_grant_allowed_by_policy(&store, &command).await);
        assert!(!store.is_path_granted(&granted_dir.join("token.txt")).await);
        assert!(!test_project_dir(&store).join(APPROVALS_FILE).exists());
    }

    #[tokio::test]
    async fn global_grant_persists_and_applies() {
        let tmp = tempfile::tempdir().unwrap();
        let global = tempfile::tempdir().unwrap();
        let (store, _) = test_store(tmp.path(), global.path().to_path_buf());
        let info = cmd_info("cargo", Some("build"), false);
        store
            .record_command(&info, info.risk.tier, Scope::Global)
            .await
            .unwrap();

        // A *different* project (different root) still sees the global
        // grant, because global applies everywhere.
        let other_project = tempfile::tempdir().unwrap();
        let db2 = store.db.clone();
        let mut elsewhere = GrantStore::new(
            db2,
            store.session_id,
            other_project.path().to_path_buf(),
            SessionConfigHandle::from_disk_for_tests(other_project.path()),
        );
        point_project_scope(&mut elsewhere, other_project.path(), global.path());
        elsewhere.global_dir = Some(global.path().to_path_buf());
        assert!(elsewhere.is_command_granted(&info.key).await);
    }

    #[tokio::test]
    async fn ignore_cfg_blocks_project_approval_file_reads_and_writes() {
        let _env = crate::test_env::lock_async().await;
        let tmp = tempfile::tempdir().unwrap();
        let status = std::process::Command::new("git")
            .args(["init", "-q"])
            .current_dir(tmp.path())
            .status()
            .unwrap();
        assert!(status.success());
        crate::config::trust::clear_runtime_policy_for_tests();
        let root = crate::config::trust::resolve_trust_root(tmp.path()).unwrap();
        crate::config::trust::set_runtime_policy(
            root,
            crate::db::workspace_trust::WorkspaceTrustMode::IgnoreConfig,
        );
        let project_dir = tmp.path().join(".cockpit");
        std::fs::create_dir_all(&project_dir).unwrap();
        let _lock = lock_approvals(&project_dir).unwrap();
        store_approvals(
            &project_dir,
            &_lock,
            &ApprovalsFile {
                commands: BTreeMap::from([(
                    "cargo test".to_string(),
                    CommandGrantRecord::new(RiskTier::Ordinary),
                )]),
                ..ApprovalsFile::default()
            },
        )
        .unwrap();

        let db = Db::open_in_memory().unwrap();
        let session = crate::session::Session::create_for_test(
            db.clone(),
            tmp.path().to_path_buf(),
            "builder",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap();
        let global = tempfile::tempdir().unwrap();
        let mut store = GrantStore::new(
            db,
            session.id,
            tmp.path().to_path_buf(),
            SessionConfigHandle::from_disk_for_tests(tmp.path()),
        );
        store.global_dir = Some(global.path().to_path_buf());
        let info = cmd_info("cargo", Some("test"), false);

        assert!(!store.is_command_granted(&info.key).await);
        assert!(matches!(
            store
                .record_command(&info, info.risk.tier, Scope::Project)
                .await,
            Err(StoreError::NoProjectRoot)
        ));
        store
            .record_command(&info, info.risk.tier, Scope::Session)
            .await
            .unwrap();
        assert!(store.is_command_granted(&info.key).await);
        crate::config::trust::clear_runtime_policy_for_tests();
    }

    #[tokio::test]
    async fn wrapper_rejected_at_every_non_once_scope() {
        let tmp = tempfile::tempdir().unwrap();
        let global = tempfile::tempdir().unwrap();
        let (store, _) = test_store(tmp.path(), global.path().to_path_buf());
        let wrapper = cmd_info("bash", None, true);
        for scope in [Scope::Session, Scope::Project, Scope::Global] {
            let err = store
                .record_command(&wrapper, wrapper.risk.tier, scope)
                .await
                .unwrap_err();
            assert!(
                matches!(err, StoreError::WrapperNotPersistable(_)),
                "scope {scope:?} should reject wrapper, got {err:?}"
            );
        }
        // And nothing was written.
        assert!(!store.is_command_granted(&wrapper.key).await);
    }

    #[tokio::test]
    async fn once_scope_is_never_recorded() {
        let tmp = tempfile::tempdir().unwrap();
        let global = tempfile::tempdir().unwrap();
        let (store, _) = test_store(tmp.path(), global.path().to_path_buf());
        let info = cmd_info("ls", None, false);
        assert!(matches!(
            store
                .record_command(&info, info.risk.tier, Scope::Once)
                .await,
            Err(StoreError::OnceNotPersistable)
        ));
        assert!(!store.is_command_granted(&info.key).await);
    }

    #[tokio::test]
    async fn path_grant_prefix_match() {
        let tmp = tempfile::tempdir().unwrap();
        let global = tempfile::tempdir().unwrap();
        let (store, _) = test_store(tmp.path(), global.path().to_path_buf());
        let dir = tmp.path().join("src");
        store
            .record_path(&dir, Scope::Project, SandboxPathAccess::ReadWrite)
            .await
            .unwrap();
        // A file under the granted dir is covered.
        assert!(store.is_path_granted(&dir.join("main.rs")).await);
        // A sibling that shares a string prefix but not a path prefix is
        // NOT covered.
        let sibling = tmp.path().join("src-gen").join("x.rs");
        assert!(!store.is_path_granted(&sibling).await);
    }

    #[tokio::test]
    async fn path_grant_session_scope() {
        let tmp = tempfile::tempdir().unwrap();
        let global = tempfile::tempdir().unwrap();
        let (store, _) = test_store(tmp.path(), global.path().to_path_buf());
        let file = tmp.path().join("a/b/c.txt");
        assert!(!store.is_path_granted(&file).await);
        store
            .record_path(&file, Scope::Session, SandboxPathAccess::ReadWrite)
            .await
            .unwrap();
        assert!(store.is_path_granted(&file).await);
    }

    #[tokio::test]
    async fn path_grant_modes_round_trip_at_each_scope() {
        for scope in [Scope::Session, Scope::Project, Scope::Global] {
            let tmp = tempfile::tempdir().unwrap();
            let global = tempfile::tempdir().unwrap();
            let (store, _) = test_store(tmp.path(), global.path().to_path_buf());
            let dir = tmp.path().join(format!("mode-{scope:?}"));
            store
                .record_path(&dir, scope, SandboxPathAccess::Read)
                .await
                .unwrap();
            assert!(
                store
                    .is_path_granted_for(&dir.join("file.txt"), SandboxPathAccess::Read)
                    .await
                    .unwrap()
            );
            assert!(
                !store
                    .is_path_granted_for(&dir.join("file.txt"), SandboxPathAccess::ReadWrite)
                    .await
                    .unwrap(),
                "read grant must not satisfy read-write at {scope:?}"
            );

            match scope {
                Scope::Session => {
                    let session_id = store.session_id;
                    let grant_key = normalize_path(&dir, store.cwd());
                    let access: String = store
                        .db
                        .read(move |conn| {
                            Ok(conn.query_row(
                                "SELECT access FROM approval_grants \
                                 WHERE session_id = ?1 AND grant_kind = 'path' AND grant_key = ?2",
                                rusqlite::params![session_id.to_string(), grant_key],
                                |row| row.get(0),
                            )?)
                        })
                        .await
                        .unwrap();
                    assert_eq!(access, "read");
                }
                Scope::Project => {
                    let grants = list_managed_grants(test_project_dir(&store));
                    assert_eq!(grants.paths[0].key, normalize_path(&dir, store.cwd()));
                    assert_eq!(grants.paths[0].access, SandboxPathAccess::Read);
                }
                Scope::Global => {
                    let grants = list_managed_grants(global.path());
                    assert_eq!(grants.paths[0].key, normalize_path(&dir, store.cwd()));
                    assert_eq!(grants.paths[0].access, SandboxPathAccess::Read);
                }
                Scope::Once => unreachable!(),
            }
        }
    }

    #[tokio::test]
    async fn mcp_tool_grant_round_trips_through_session_and_file_scopes() {
        for scope in [Scope::Session, Scope::Project, Scope::Global] {
            let tmp = tempfile::tempdir().unwrap();
            let global = tempfile::tempdir().unwrap();
            let (store, sid) = test_store(tmp.path(), global.path().to_path_buf());

            assert!(
                store
                    .mcp_tool_grant_scope("external", "search/query")
                    .await
                    .unwrap()
                    .is_none()
            );
            store
                .record_mcp_tool("external", "search/query", scope)
                .await
                .unwrap();
            assert_eq!(
                store
                    .mcp_tool_grant_scope("external", "search/query")
                    .await
                    .unwrap(),
                Some(scope),
                "scope {scope:?}"
            );
            assert!(
                store
                    .mcp_tool_grant_scope("external/search", "query")
                    .await
                    .unwrap()
                    .is_none(),
                "escaped key must not collide with a different server/tool split"
            );

            let key = mcp_tool_key("external", "search/query");
            match scope {
                Scope::Session => {
                    let session_id = sid;
                    let key_for_db = key.clone();
                    let (access, risk_tier): (Option<String>, Option<String>) = store
                        .db
                        .read(move |conn| {
                            Ok(conn.query_row(
                                "SELECT access, risk_tier FROM approval_grants \
                                 WHERE session_id = ?1 AND grant_kind = 'mcp_tool' AND grant_key = ?2",
                                rusqlite::params![session_id.to_string(), key_for_db],
                                |row| Ok((row.get(0)?, row.get(1)?)),
                            )?)
                        })
                        .await
                        .unwrap();
                    assert_eq!(access, None);
                    assert_eq!(risk_tier, None);
                }
                Scope::Project => {
                    assert_eq!(
                        list_managed_grants(test_project_dir(&store)).mcp_tools,
                        vec![key]
                    );
                }
                Scope::Global => {
                    assert_eq!(list_managed_grants(global.path()).mcp_tools, vec![key]);
                }
                Scope::Once => unreachable!(),
            }

            let mut reloaded = GrantStore::new(
                store.db.clone(),
                sid,
                tmp.path().to_path_buf(),
                SessionConfigHandle::from_disk_for_tests(tmp.path()),
            );
            point_project_scope(&mut reloaded, tmp.path(), global.path());
            reloaded.global_dir = Some(global.path().to_path_buf());
            assert_eq!(
                reloaded
                    .mcp_tool_grant_scope("external", "search/query")
                    .await
                    .unwrap(),
                Some(scope),
                "reload {scope:?}"
            );
        }
    }

    #[tokio::test]
    async fn effective_path_grants_use_strongest_access_and_filter_rejects() {
        let tmp = tempfile::tempdir().unwrap();
        let global = tempfile::tempdir().unwrap();
        let (store, _) = test_store(tmp.path(), global.path().to_path_buf());
        let read_dir = tmp.path().join("read-only");
        let rw_dir = tmp.path().join("read-write");
        let rejected_dir = tmp.path().join("rejected");

        store
            .record_path(&read_dir, Scope::Session, SandboxPathAccess::Read)
            .await
            .unwrap();
        store
            .record_path(&read_dir, Scope::Project, SandboxPathAccess::ReadWrite)
            .await
            .unwrap();
        store
            .record_path(&rw_dir, Scope::Global, SandboxPathAccess::ReadWrite)
            .await
            .unwrap();
        store
            .record_path(&rejected_dir, Scope::Project, SandboxPathAccess::ReadWrite)
            .await
            .unwrap();
        store
            .record_path_reject(&rejected_dir, Scope::Session)
            .await
            .unwrap();

        let grants = store.effective_path_grants().await.unwrap();
        assert!(grants.iter().any(|grant| {
            grant.path == read_dir && grant.access == SandboxPathAccess::ReadWrite
        }));
        assert!(
            grants
                .iter()
                .any(|grant| grant.path == rw_dir && grant.access == SandboxPathAccess::ReadWrite)
        );
        assert!(
            !grants.iter().any(|grant| grant.path == rejected_dir),
            "standing rejects must not become sandbox allow paths"
        );
    }

    #[tokio::test]
    async fn approval_timestamp_columns_are_integer() {
        let db = Db::open_in_memory().unwrap();
        db.read(|conn| {
            assert_eq!(
                column_type(conn, "approval_grants", "granted_at")?,
                "INTEGER"
            );
            assert_eq!(
                column_type(conn, "loop_guard_rules", "recorded_at")?,
                "INTEGER"
            );
            Ok(())
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn session_approval_records_epoch_integer_timestamp() {
        let tmp = tempfile::tempdir().unwrap();
        let global = tempfile::tempdir().unwrap();
        let (store, _) = test_store(tmp.path(), global.path().to_path_buf());
        let before = now_epoch_seconds();

        store
            .record_command(
                &cmd_info("grep", None, false),
                RiskTier::Ordinary,
                Scope::Session,
            )
            .await
            .unwrap();

        let session_id = store.session_id;
        let grant_key = cmd_info("grep", None, false).key.as_storage_str();
        let (value, sqlite_type): (i64, String) = store
            .db
            .read(move |conn| {
                conn.query_row(
                    "SELECT granted_at, typeof(granted_at) FROM approval_grants \
                     WHERE session_id = ?1 AND grant_kind = 'command' AND grant_key = ?2",
                    rusqlite::params![session_id.to_string(), grant_key],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .map_err(Into::into)
            })
            .await
            .unwrap();
        let after = now_epoch_seconds();

        assert_eq!(sqlite_type, "integer");
        assert!((before..=after).contains(&value));
    }

    #[tokio::test]
    async fn loop_rule_records_epoch_integer_timestamp() {
        let tmp = tempfile::tempdir().unwrap();
        let global = tempfile::tempdir().unwrap();
        let (store, _) = test_store(tmp.path(), global.path().to_path_buf());
        let signature = GrantStore::loop_signature("read", &serde_json::json!({"path": "x"}));
        let before = now_epoch_seconds();

        store
            .record_loop_rule(&signature, LoopVerdict::Accept, Scope::Session)
            .await
            .unwrap();

        let session_id = store.session_id;
        let signature_for_db = signature.clone();
        let (value, sqlite_type): (i64, String) = store
            .db
            .read(move |conn| {
                conn.query_row(
                    "SELECT recorded_at, typeof(recorded_at) FROM loop_guard_rules \
                     WHERE session_id = ?1 AND signature = ?2",
                    rusqlite::params![session_id.to_string(), signature_for_db],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .map_err(Into::into)
            })
            .await
            .unwrap();
        let after = now_epoch_seconds();

        assert_eq!(sqlite_type, "integer");
        assert!((before..=after).contains(&value));
    }

    #[tokio::test]
    async fn relative_path_grants_use_store_cwd_not_process_cwd() {
        let session = tempfile::tempdir().unwrap();
        let global = tempfile::tempdir().unwrap();
        let unrelated_daemon_cwd = tempfile::tempdir().unwrap();
        let (store, _) = test_store(session.path(), global.path().to_path_buf());

        store
            .record_path(
                Path::new("src"),
                Scope::Session,
                SandboxPathAccess::ReadWrite,
            )
            .await
            .unwrap();

        assert!(store.is_path_granted(Path::new("src/main.rs")).await);
        assert!(
            !store
                .is_path_granted(&unrelated_daemon_cwd.path().join("src/main.rs"))
                .await
        );
    }

    #[tokio::test]
    async fn normalize_path_uses_explicit_base_for_relative_paths() {
        let session_cwd = Path::new("/session/project");
        let daemon_cwd = Path::new("/daemon/process");

        assert_eq!(
            normalize_path(Path::new("src/../Cargo.toml"), session_cwd),
            "/session/project/Cargo.toml"
        );
        assert_ne!(
            normalize_path(Path::new("src/../Cargo.toml"), session_cwd),
            daemon_cwd.join("Cargo.toml").to_string_lossy()
        );
    }

    #[tokio::test]
    async fn normalize_path_keeps_absolute_paths_and_lexical_parent_resolution() {
        assert_eq!(
            normalize_path(
                Path::new("/tmp/project/../file.txt"),
                Path::new("/ignored/base")
            ),
            "/tmp/file.txt"
        );
    }

    // ---- reject grants (mirror of the allow grants) ----------------------

    /// A command reject persists and is seen by `is_command_rejected` at each
    /// non-`Once` scope; it survives a reload at the persistent scopes.
    #[tokio::test]
    async fn command_reject_at_each_scope() {
        for scope in [Scope::Session, Scope::Project, Scope::Global] {
            let tmp = tempfile::tempdir().unwrap();
            let global = tempfile::tempdir().unwrap();
            let (store, sid) = test_store(tmp.path(), global.path().to_path_buf());
            let info = cmd_info("gh", Some("pr"), false);
            assert!(!store.is_command_rejected(&info.key).await);
            store.record_command_reject(&info, scope).await.unwrap();
            assert!(
                store.is_command_rejected(&info.key).await,
                "scope {scope:?}"
            );
            // A reject is not an allow.
            assert!(
                !store.is_command_granted(&info.key).await,
                "scope {scope:?}"
            );

            // Reload (fresh store over the same DB + dirs) still sees it.
            let mut reloaded = GrantStore::new(
                store.db.clone(),
                sid,
                tmp.path().to_path_buf(),
                SessionConfigHandle::from_disk_for_tests(tmp.path()),
            );
            point_project_scope(&mut reloaded, tmp.path(), global.path());
            reloaded.global_dir = Some(global.path().to_path_buf());
            assert!(
                reloaded.is_command_rejected(&info.key).await,
                "reload {scope:?}"
            );
        }
    }

    /// A path reject persists and is seen by `is_path_rejected` (prefix
    /// semantics, same as allow) at each non-`Once` scope.
    #[tokio::test]
    async fn path_reject_at_each_scope() {
        for scope in [Scope::Session, Scope::Project, Scope::Global] {
            let tmp = tempfile::tempdir().unwrap();
            let global = tempfile::tempdir().unwrap();
            let (store, _) = test_store(tmp.path(), global.path().to_path_buf());
            let dir = tmp.path().join("secret");
            assert!(!store.is_path_rejected(&dir.join("k.txt")).await.unwrap());
            store.record_path_reject(&dir, scope).await.unwrap();
            // A file under the rejected dir is covered (prefix match).
            assert!(
                store.is_path_rejected(&dir.join("k.txt")).await.unwrap(),
                "scope {scope:?}"
            );
            assert!(
                !store.is_path_granted(&dir.join("k.txt")).await,
                "scope {scope:?}"
            );
        }
    }

    /// Recording a reject for a key first removes any allow grant for that key
    /// at every reachable scope, and vice-versa — a key is never simultaneously
    /// allowed and rejected after any record call (no-coexistence invariant).
    #[tokio::test]
    async fn reject_and_allow_never_coexist_both_directions() {
        let tmp = tempfile::tempdir().unwrap();
        let global = tempfile::tempdir().unwrap();
        let (store, _) = test_store(tmp.path(), global.path().to_path_buf());
        let info = cmd_info("gh", Some("pr"), false);

        // Allow at project + global, then reject at session: the session
        // reject must clear BOTH the project and the global allow.
        store
            .record_command(&info, info.risk.tier, Scope::Project)
            .await
            .unwrap();
        store
            .record_command(&info, info.risk.tier, Scope::Global)
            .await
            .unwrap();
        assert!(store.is_command_granted(&info.key).await);
        store
            .record_command_reject(&info, Scope::Session)
            .await
            .unwrap();
        assert!(store.is_command_rejected(&info.key).await);
        assert!(
            !store.is_command_granted(&info.key).await,
            "reject cleared every reachable allow"
        );

        // Now allow again at project: the allow must clear the session reject.
        store
            .record_command(&info, info.risk.tier, Scope::Project)
            .await
            .unwrap();
        assert!(store.is_command_granted(&info.key).await);
        assert!(
            !store.is_command_rejected(&info.key).await,
            "allow cleared the standing reject"
        );
    }

    /// The same no-coexistence invariant for path grants.
    #[tokio::test]
    async fn path_reject_and_allow_never_coexist() {
        let tmp = tempfile::tempdir().unwrap();
        let global = tempfile::tempdir().unwrap();
        let (store, _) = test_store(tmp.path(), global.path().to_path_buf());
        let dir = tmp.path().join("data");

        store
            .record_path(&dir, Scope::Project, SandboxPathAccess::ReadWrite)
            .await
            .unwrap();
        assert!(store.is_path_granted(&dir.join("x")).await);
        store
            .record_path_reject(&dir, Scope::Session)
            .await
            .unwrap();
        assert!(store.is_path_rejected(&dir.join("x")).await.unwrap());
        assert!(
            !store.is_path_granted(&dir.join("x")).await,
            "reject cleared allow"
        );

        store
            .record_path(&dir, Scope::Global, SandboxPathAccess::ReadWrite)
            .await
            .unwrap();
        assert!(store.is_path_granted(&dir.join("x")).await);
        assert!(
            !store.is_path_rejected(&dir.join("x")).await.unwrap(),
            "allow cleared reject"
        );
    }

    #[tokio::test]
    async fn mcp_tool_reject_blocks_without_prompting() {
        let tmp = tempfile::tempdir().unwrap();
        let global = tempfile::tempdir().unwrap();
        let (store, _) = test_store(tmp.path(), global.path().to_path_buf());

        store
            .record_mcp_tool("external", "search", Scope::Project)
            .await
            .unwrap();
        assert_eq!(
            store
                .mcp_tool_grant_scope("external", "search")
                .await
                .unwrap(),
            Some(Scope::Project)
        );

        store
            .record_mcp_tool_reject("external", "search", Scope::Session)
            .await
            .unwrap();
        assert_eq!(
            store
                .mcp_tool_reject_scope("external", "search")
                .await
                .unwrap(),
            Some(Scope::Session)
        );
        assert!(
            store
                .mcp_tool_grant_scope("external", "search")
                .await
                .unwrap()
                .is_none()
        );

        store
            .record_mcp_tool("external", "search", Scope::Global)
            .await
            .unwrap();
        assert_eq!(
            store
                .mcp_tool_grant_scope("external", "search")
                .await
                .unwrap(),
            Some(Scope::Global)
        );
        assert!(
            store
                .mcp_tool_reject_scope("external", "search")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn harness_grant_is_session_scope_only() {
        let tmp = tempfile::tempdir().unwrap();
        let global = tempfile::tempdir().unwrap();
        let (store, _) = test_store(tmp.path(), global.path().to_path_buf());

        assert_eq!(GrantKind::Harness.as_str(), "harness");
        assert_eq!("harness".parse::<GrantKind>().unwrap(), GrantKind::Harness);
        assert_eq!(
            "unknown"
                .parse::<GrantKind>()
                .expect_err("unknown grant kind is rejected"),
            "unknown approval class `unknown`; expected command, path, mcp_tool, or harness"
        );
        assert!(!store.is_harness_granted("claude").await);
        store
            .record_harness("claude", Scope::Session)
            .await
            .unwrap();
        assert!(store.is_harness_granted("claude").await);

        assert!(matches!(
            store.record_harness("codex", Scope::Once).await,
            Err(StoreError::OnceNotPersistable)
        ));
        assert!(matches!(
            store.record_harness("codex", Scope::Project).await,
            Err(StoreError::HarnessSessionScopeOnly)
        ));
        assert!(matches!(
            store.record_harness("codex", Scope::Global).await,
            Err(StoreError::HarnessSessionScopeOnly)
        ));
        assert!(!test_project_dir(&store).join("approvals.json").exists());
        assert!(!global.path().join("approvals.json").exists());
    }

    /// `Once` is never persisted in either polarity, and a wrapper command can
    /// never be rejected at a persistent scope — identical to the allow rules.
    #[tokio::test]
    async fn reject_once_and_wrapper_rules() {
        let tmp = tempfile::tempdir().unwrap();
        let global = tempfile::tempdir().unwrap();
        let (store, _) = test_store(tmp.path(), global.path().to_path_buf());

        // Once → OnceNotPersistable; nothing recorded.
        let info = cmd_info("ls", None, false);
        assert!(matches!(
            store.record_command_reject(&info, Scope::Once).await,
            Err(StoreError::OnceNotPersistable)
        ));
        assert!(!store.is_command_rejected(&info.key).await);

        // Wrapper → WrapperNotPersistable at every non-Once scope.
        let wrapper = cmd_info("bash", None, true);
        for scope in [Scope::Session, Scope::Project, Scope::Global] {
            assert!(matches!(
                store.record_command_reject(&wrapper, scope).await,
                Err(StoreError::WrapperNotPersistable(_))
            ));
        }
        assert!(!store.is_command_rejected(&wrapper.key).await);

        // Path reject Once is also never persisted.
        let p = tmp.path().join("p");
        assert!(matches!(
            store.record_path_reject(&p, Scope::Once).await,
            Err(StoreError::OnceNotPersistable)
        ));
        assert!(!store.is_path_rejected(&p).await.unwrap());
    }

    #[tokio::test]
    async fn tierless_command_allow_rows_are_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let global = tempfile::tempdir().unwrap();
        let (store, _) = test_store(tmp.path(), global.path().to_path_buf());
        let info = cmd_info("cargo", Some("test"), false);
        let key = info.key.as_storage_str();
        let session_id = store.session_id;
        let inserted = store
            .db
            .write(move |conn| {
                conn.execute(
                    "INSERT INTO approval_grants \
                     (session_id, grant_kind, grant_key, granted_at) \
                     VALUES (?1, 'command', ?2, ?3)",
                    rusqlite::params![session_id.to_string(), key, 1_700_000_000_i64],
                )?;
                Ok(())
            })
            .await;
        assert!(inserted.is_err(), "command allow rows must carry risk_tier");
        assert!(!store.is_command_granted(&info.key).await);
        assert!(!store.is_command_rejected(&info.key).await);
    }

    #[tokio::test]
    async fn unparseable_or_empty_keys_are_just_not_granted() {
        // The store only answers about keys it's given; an empty/garbage
        // command never produces a key, so the classifier returns no
        // simple commands and the store is never asked → not granted.
        // (Classifier-side behavior is tested in classify.rs.) Here we
        // assert the store treats an unknown key as not-granted.
        let tmp = tempfile::tempdir().unwrap();
        let global = tempfile::tempdir().unwrap();
        let (store, _) = test_store(tmp.path(), global.path().to_path_buf());
        let unknown = ApprovalKey {
            program: "nevergranted".into(),
            subcommand: None,
            option_names: std::collections::BTreeSet::new(),
        };
        assert!(!store.is_command_granted(&unknown).await);
    }

    // ---- loop-guard rules ------------------------------------------------

    #[tokio::test]
    async fn loop_signature_keys_on_tool_and_wire_input() {
        use serde_json::json;
        // Same tool + identical input → identical signature.
        let a = GrantStore::loop_signature("read", &json!({"path": "src/main.rs"}));
        let b = GrantStore::loop_signature("read", &json!({"path": "src/main.rs"}));
        assert_eq!(a, b);
        // A different tool with the same input → different signature.
        let c = GrantStore::loop_signature("bash", &json!({"path": "src/main.rs"}));
        assert_ne!(a, c);
        // A different input under the same tool → different signature.
        let d = GrantStore::loop_signature("read", &json!({"path": "src/lib.rs"}));
        assert_ne!(a, d);
    }

    #[tokio::test]
    async fn loop_signature_is_object_key_order_independent() {
        use serde_json::json;
        // The model may emit object keys in any order; semantically
        // identical inputs must share a signature.
        let a = GrantStore::loop_signature("edit", &json!({"path": "a", "old": "x", "new": "y"}));
        let b = GrantStore::loop_signature("edit", &json!({"new": "y", "path": "a", "old": "x"}));
        assert_eq!(a, b);
    }

    #[tokio::test]
    async fn loop_rule_session_record_and_read_round_trip() {
        let tmp = tempfile::tempdir().unwrap();
        let global = tempfile::tempdir().unwrap();
        let (store, _) = test_store(tmp.path(), global.path().to_path_buf());
        let sig = GrantStore::loop_signature("read", &serde_json::json!({"path": "x"}));
        assert!(store.loop_rule(&sig).await.unwrap().is_none());
        store
            .record_loop_rule(&sig, LoopVerdict::Reject, Scope::Session)
            .await
            .unwrap();
        assert_eq!(
            store.loop_rule(&sig).await.unwrap(),
            Some(LoopVerdict::Reject)
        );
        // Recording the opposite verdict at the same scope flips it (no
        // contradictory pair persists).
        store
            .record_loop_rule(&sig, LoopVerdict::Accept, Scope::Session)
            .await
            .unwrap();
        assert_eq!(
            store.loop_rule(&sig).await.unwrap(),
            Some(LoopVerdict::Accept)
        );
    }

    #[tokio::test]
    async fn loop_rule_project_persists_across_sessions() {
        let tmp = tempfile::tempdir().unwrap();
        let global = tempfile::tempdir().unwrap();
        let (store, sid) = test_store(tmp.path(), global.path().to_path_buf());
        let sig = GrantStore::loop_signature("bash", &serde_json::json!({"command": "ls"}));
        store
            .record_loop_rule(&sig, LoopVerdict::Accept, Scope::Project)
            .await
            .unwrap();
        // A fresh store over the same project dir (a later session) reads
        // the persisted project rule back.
        let db2 = store.db.clone();
        let mut reloaded = GrantStore::new(
            db2,
            sid,
            tmp.path().to_path_buf(),
            SessionConfigHandle::from_disk_for_tests(tmp.path()),
        );
        point_project_scope(&mut reloaded, tmp.path(), global.path());
        reloaded.global_dir = Some(global.path().to_path_buf());
        assert_eq!(
            reloaded.loop_rule(&sig).await.unwrap(),
            Some(LoopVerdict::Accept)
        );
    }

    #[tokio::test]
    async fn loop_rule_session_takes_precedence_over_project() {
        // A session rule and a project rule for the SAME signature resolve
        // to the session verdict (documented precedence: session > project
        // > global).
        let tmp = tempfile::tempdir().unwrap();
        let global = tempfile::tempdir().unwrap();
        let (store, _) = test_store(tmp.path(), global.path().to_path_buf());
        let sig = GrantStore::loop_signature("read", &serde_json::json!({"path": "z"}));
        store
            .record_loop_rule(&sig, LoopVerdict::Accept, Scope::Project)
            .await
            .unwrap();
        store
            .record_loop_rule(&sig, LoopVerdict::Reject, Scope::Session)
            .await
            .unwrap();
        // Session (reject) wins over project (accept).
        assert_eq!(
            store.loop_rule(&sig).await.unwrap(),
            Some(LoopVerdict::Reject)
        );
    }

    #[tokio::test]
    async fn loop_rule_project_takes_precedence_over_global() {
        let tmp = tempfile::tempdir().unwrap();
        let global = tempfile::tempdir().unwrap();
        let (store, _) = test_store(tmp.path(), global.path().to_path_buf());
        let sig = GrantStore::loop_signature("read", &serde_json::json!({"path": "q"}));
        store
            .record_loop_rule(&sig, LoopVerdict::Reject, Scope::Global)
            .await
            .unwrap();
        store
            .record_loop_rule(&sig, LoopVerdict::Accept, Scope::Project)
            .await
            .unwrap();
        // Project (accept) wins over global (reject).
        assert_eq!(
            store.loop_rule(&sig).await.unwrap(),
            Some(LoopVerdict::Accept)
        );
    }

    #[tokio::test]
    async fn loop_rule_once_scope_is_never_persisted() {
        let tmp = tempfile::tempdir().unwrap();
        let global = tempfile::tempdir().unwrap();
        let (store, _) = test_store(tmp.path(), global.path().to_path_buf());
        let sig = GrantStore::loop_signature("read", &serde_json::json!({"path": "x"}));
        assert!(matches!(
            store
                .record_loop_rule(&sig, LoopVerdict::Accept, Scope::Once)
                .await,
            Err(StoreError::OnceNotPersistable)
        ));
        assert!(store.loop_rule(&sig).await.unwrap().is_none());
    }

    // ---- management API (`/permissions`) ---------------------------------

    #[tokio::test]
    async fn list_managed_grants_groups_by_kind_and_sorts() {
        let dir = tempfile::tempdir().unwrap();
        // Seed one of each bucket through the normal store write paths so
        // the file shape is exactly what production records.
        let db = Db::open_in_memory().unwrap();
        let session = crate::session::Session::create_for_test(
            db.clone(),
            dir.path().to_path_buf(),
            "builder",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap();
        let mut store = GrantStore::new(
            db,
            session.id,
            dir.path().to_path_buf(),
            SessionConfigHandle::from_disk_for_tests(dir.path()),
        );
        point_project_scope(&mut store, dir.path(), dir.path());
        store
            .record_command(
                &cmd_info("gh", Some("pr"), false),
                RiskTier::Ordinary,
                Scope::Project,
            )
            .await
            .unwrap();
        store
            .record_command(
                &cmd_info("cargo", Some("build"), false),
                RiskTier::Ordinary,
                Scope::Project,
            )
            .await
            .unwrap();
        store
            .record_path(
                &dir.path().join("src"),
                Scope::Project,
                SandboxPathAccess::ReadWrite,
            )
            .await
            .unwrap();
        let sig = GrantStore::loop_signature("read", &serde_json::json!({"path": "x"}));
        store
            .record_loop_rule(&sig, LoopVerdict::Accept, Scope::Project)
            .await
            .unwrap();

        let grants = list_managed_grants(test_project_dir(&store));
        // Commands are sorted; both present.
        assert_eq!(
            grants.commands,
            vec![
                ManagedCommandGrant {
                    key: "cargo build".to_string(),
                    risk_tier: RiskTier::Ordinary,
                },
                ManagedCommandGrant {
                    key: "gh pr".to_string(),
                    risk_tier: RiskTier::Ordinary,
                },
            ]
        );
        assert_eq!(grants.paths.len(), 1);
        assert_eq!(grants.loop_accept, vec![sig]);
        assert!(grants.loop_reject.is_empty());
        assert!(!grants.is_empty());
    }

    #[tokio::test]
    async fn managed_grants_expose_command_tier() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open_in_memory().unwrap();
        let session = crate::session::Session::create_for_test(
            db.clone(),
            dir.path().to_path_buf(),
            "builder",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap();
        let mut store = GrantStore::new(
            db,
            session.id,
            dir.path().to_path_buf(),
            SessionConfigHandle::from_disk_for_tests(dir.path()),
        );
        point_project_scope(&mut store, dir.path(), dir.path());
        let mut info = cmd_info("git", Some("push"), false);
        info.risk.tier = RiskTier::Destructive;
        store
            .record_command(&info, info.risk.tier, Scope::Project)
            .await
            .unwrap();

        let grants = list_managed_grants(test_project_dir(&store));
        assert_eq!(
            grants.commands,
            vec![ManagedCommandGrant {
                key: "git push".to_string(),
                risk_tier: RiskTier::Destructive,
            }]
        );
    }

    #[tokio::test]
    async fn list_managed_grants_missing_file_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let grants = list_managed_grants(dir.path());
        assert!(grants.is_empty(), "no approvals.json → empty, not an error");
    }

    #[tokio::test]
    async fn delete_managed_grant_removes_one_leaves_others() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open_in_memory().unwrap();
        let session = crate::session::Session::create_for_test(
            db.clone(),
            dir.path().to_path_buf(),
            "builder",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap();
        let mut store = GrantStore::new(
            db,
            session.id,
            dir.path().to_path_buf(),
            SessionConfigHandle::from_disk_for_tests(dir.path()),
        );
        point_project_scope(&mut store, dir.path(), dir.path());
        store
            .record_command(
                &cmd_info("gh", Some("pr"), false),
                RiskTier::Ordinary,
                Scope::Project,
            )
            .await
            .unwrap();
        store
            .record_command(
                &cmd_info("cargo", Some("build"), false),
                RiskTier::Ordinary,
                Scope::Project,
            )
            .await
            .unwrap();
        let project_dir = test_project_dir(&store).to_path_buf();

        // Deleting by the readable v2 command label leaves the other intact.
        let gh_key = list_managed_grants(&project_dir)
            .commands
            .into_iter()
            .find(|grant| grant.key == "gh pr")
            .expect("recorded grant")
            .key;
        assert!(delete_managed_grant(&project_dir, ManagedGrantKind::Command, &gh_key).unwrap());
        let grants = list_managed_grants(&project_dir);
        assert_eq!(
            grants.commands,
            vec![ManagedCommandGrant {
                key: "cargo build".to_string(),
                risk_tier: RiskTier::Ordinary,
            }]
        );

        // The removal is durable: a fresh store no longer treats it as granted.
        assert!(
            !store
                .is_command_granted(&ApprovalKey {
                    program: "gh".into(),
                    subcommand: Some("pr".into()),
                    option_names: std::collections::BTreeSet::new(),
                })
                .await
        );
        assert!(
            store
                .is_command_granted(&ApprovalKey {
                    program: "cargo".into(),
                    subcommand: Some("build".into()),
                    option_names: std::collections::BTreeSet::new(),
                })
                .await
        );
    }

    #[tokio::test]
    async fn delete_managed_grant_handles_each_kind() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open_in_memory().unwrap();
        let session = crate::session::Session::create_for_test(
            db.clone(),
            dir.path().to_path_buf(),
            "builder",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap();
        let mut store = GrantStore::new(
            db,
            session.id,
            dir.path().to_path_buf(),
            SessionConfigHandle::from_disk_for_tests(dir.path()),
        );
        point_project_scope(&mut store, dir.path(), dir.path());
        let path = dir.path().join("data");
        store
            .record_path(&path, Scope::Project, SandboxPathAccess::ReadWrite)
            .await
            .unwrap();
        let acc = GrantStore::loop_signature("read", &serde_json::json!({"p": 1}));
        let rej = GrantStore::loop_signature("bash", &serde_json::json!({"c": "x"}));
        store
            .record_loop_rule(&acc, LoopVerdict::Accept, Scope::Project)
            .await
            .unwrap();
        store
            .record_loop_rule(&rej, LoopVerdict::Reject, Scope::Project)
            .await
            .unwrap();

        let project_dir = test_project_dir(&store).to_path_buf();
        let path_key = list_managed_grants(&project_dir).paths[0].key.clone();
        assert!(delete_managed_grant(&project_dir, ManagedGrantKind::Path, &path_key).unwrap());
        assert!(delete_managed_grant(&project_dir, ManagedGrantKind::LoopAccept, &acc).unwrap());
        assert!(delete_managed_grant(&project_dir, ManagedGrantKind::LoopReject, &rej).unwrap());
        assert!(list_managed_grants(&project_dir).is_empty());
    }

    #[tokio::test]
    async fn managed_grants_list_and_revoke_mcp_tools() {
        let tmp = tempfile::tempdir().unwrap();
        let global = tempfile::tempdir().unwrap();
        let (store, _) = test_store(tmp.path(), global.path().to_path_buf());
        store
            .record_mcp_tool("external", "search", Scope::Project)
            .await
            .unwrap();

        let project_dir = test_project_dir(&store).to_path_buf();
        let key = mcp_tool_key("external", "search");
        let grants = list_managed_grants(&project_dir);
        assert_eq!(grants.mcp_tools, vec![key.clone()]);
        assert_eq!(grants.entry_count(ManagedGrantKind::McpTool), 1);

        assert!(delete_managed_grant(&project_dir, ManagedGrantKind::McpTool, &key).unwrap());
        assert!(list_managed_grants(&project_dir).is_empty());
        assert!(
            store
                .mcp_tool_grant_scope("external", "search")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn delete_managed_grant_absent_key_is_noop() {
        let dir = tempfile::tempdir().unwrap();
        // No file at all: deleting an absent key returns false, writes nothing.
        assert!(!delete_managed_grant(dir.path(), ManagedGrantKind::Command, "nope").unwrap());
        assert!(!dir.path().join(APPROVALS_FILE).exists());
    }

    #[tokio::test]
    async fn approvals_store_missing_files_are_healthy_first_run_state() {
        let tmp = tempfile::tempdir().unwrap();
        let global = tempfile::tempdir().unwrap();
        let (store, _) = test_store(tmp.path(), global.path().to_path_buf());
        // No approvals.json anywhere: the normal first-run state, not a
        // refusal.
        store.approvals_store_health().unwrap();
    }

    #[tokio::test]
    async fn corrupt_approvals_store_fails_closed_instead_of_dropping_standing_rejects() {
        let tmp = tempfile::tempdir().unwrap();
        let global = tempfile::tempdir().unwrap();
        let (store, _) = test_store(tmp.path(), global.path().to_path_buf());
        let info = cmd_info("rm", Some("-rf"), false);

        // Seed a standing project-scope reject.
        store
            .record_command_reject(&info, Scope::Project)
            .await
            .unwrap();
        assert_eq!(
            store.command_reject_scope(&info.key).await.unwrap(),
            Some(Scope::Project)
        );

        // Corrupt the persisted store (as a partial write or disk damage
        // would).
        let dir = test_project_dir(&store).to_path_buf();
        let store_path = dir.join(APPROVALS_FILE);
        let valid_bytes = std::fs::read(&store_path).unwrap();
        let corrupt_bytes = b"{\"commands_reject\": ".as_slice();
        std::fs::write(&store_path, corrupt_bytes).unwrap();

        // The health gate fails closed with a visible, repair-oriented
        // error — the standing reject is not silently dropped.
        let err = store.approvals_store_health().unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("corrupt"), "{msg}");
        assert!(msg.contains("approvals.json"), "{msg}");
        assert!(msg.contains("Restore"), "{msg}");

        // The corrupt bytes were preserved for diagnosis — copied aside,
        // never deleted — and the live path is left exactly as found for
        // the owner to repair (never vacated, renamed, or deleted).
        assert_eq!(std::fs::read(&store_path).unwrap(), corrupt_bytes);
        let residue = find_quarantine_residue(&dir)
            .expect("residue enumeration")
            .expect("quarantine copy preserved");
        assert_eq!(std::fs::read(&residue).unwrap(), corrupt_bytes);

        // Still refusing: the store has not been repaired yet.
        assert!(store.approvals_store_health().is_err());

        // Repair: restore the valid store and remove the quarantine copy.
        std::fs::write(&store_path, &valid_bytes).unwrap();
        std::fs::remove_file(&residue).unwrap();
        store.approvals_store_health().unwrap();

        // The standing reject is honored again.
        assert_eq!(
            store.command_reject_scope(&info.key).await.unwrap(),
            Some(Scope::Project)
        );
    }

    #[tokio::test]
    async fn corrupt_approvals_store_fails_the_lookup_itself_closed() {
        // Issue #297: the health check and the authorization lookup are one
        // fail-closed operation. A store that goes corrupt between a
        // decision-boundary health gate and the decision's own lookup must
        // fail that decision at the lookup — never be consumed as empty
        // approval state (which would silently drop the standing reject).
        let tmp = tempfile::tempdir().unwrap();
        let global = tempfile::tempdir().unwrap();
        let (store, _) = test_store(tmp.path(), global.path().to_path_buf());
        let info = cmd_info("rm", Some("-rf"), false);
        store
            .record_command_reject(&info, Scope::Project)
            .await
            .unwrap();

        // Corrupt the persisted store (the TOCTOU window: this lands after
        // any earlier health check passed). Each detection quarantines the
        // corrupt copy aside and the residue keeps later reads failed
        // closed, so both are cleared before re-corrupting for each query
        // surface.
        let dir = test_project_dir(&store).to_path_buf();
        let store_path = dir.join(APPROVALS_FILE);
        let corrupt_bytes = b"{\"commands_reject\": ".as_slice();
        let re_corrupt = || {
            if let Some(residue) = find_quarantine_residue(&dir).expect("residue enumeration") {
                std::fs::remove_file(residue).unwrap();
            }
            std::fs::write(&store_path, corrupt_bytes).unwrap();
        };

        // The lookup itself refuses with the repair-oriented error — no
        // separate health check is required for the decision to see the
        // corruption.
        re_corrupt();
        let err = match store.command_reject_scope(&info.key).await {
            Ok(scope) => panic!("corrupt store must fail the lookup closed, got {scope:?}"),
            Err(error) => format!("{error:#}"),
        };
        assert!(err.contains("corrupt"), "{err}");
        assert!(err.contains("approvals.json"), "{err}");

        // The first detection quarantined the corrupt bytes and the residue
        // keeps every later read failed closed. A consecutive lookup must
        // stay failed closed on its own — the lookup API can never read a
        // post-quarantine store as healthy approval state, which would
        // silently drop the standing reject (issue #297).
        let err = match store.command_reject_scope(&info.key).await {
            Ok(scope) => panic!("post-quarantine lookup must stay failed closed, got {scope:?}"),
            Err(error) => format!("{error:#}"),
        };
        assert!(err.contains("corrupt"), "{err}");
        assert!(err.contains("approvals.json"), "{err}");
        assert!(err.contains("quarantined earlier"), "{err}");

        // The same fail-closed read holds for every other file-backed
        // query surface.
        let loop_sig = GrantStore::loop_signature("bash", &serde_json::json!({"command": "ls"}));
        re_corrupt();
        assert!(store.loop_rule(&loop_sig).await.is_err());
        re_corrupt();
        assert!(
            store
                .is_path_granted_for(&tmp.path().join("x"), SandboxPathAccess::Read)
                .await
                .is_err()
        );
        re_corrupt();
        assert!(
            store
                .mcp_tool_reject_scope("external", "search")
                .await
                .is_err()
        );

        // The corrupt bytes were preserved for diagnosis — copied aside,
        // never deleted — and the live path was left exactly as found.
        assert_eq!(std::fs::read(&store_path).unwrap(), corrupt_bytes);
        let residue = find_quarantine_residue(&dir)
            .expect("residue enumeration")
            .expect("quarantine copy preserved");
        assert_eq!(std::fs::read(&residue).unwrap(), corrupt_bytes);
    }

    #[tokio::test]
    async fn corrupt_global_approvals_store_refuses_the_health_gate() {
        let tmp = tempfile::tempdir().unwrap();
        let global = tempfile::tempdir().unwrap();
        let (store, _) = test_store(tmp.path(), global.path().to_path_buf());
        std::fs::write(global.path().join(APPROVALS_FILE), b"not json at all").unwrap();

        let err = store.approvals_store_health().unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("corrupt"), "{msg}");
        // The corrupt global store was quarantined, not deleted.
        let residue = find_quarantine_residue(global.path())
            .expect("residue enumeration")
            .expect("global quarantine copy preserved");
        assert_eq!(
            std::fs::read(&residue).unwrap(),
            b"not json at all".as_slice()
        );
    }

    #[tokio::test]
    async fn recording_into_corrupt_approvals_store_fails_closed_without_clobbering() {
        let tmp = tempfile::tempdir().unwrap();
        let global = tempfile::tempdir().unwrap();
        let (store, _) = test_store(tmp.path(), global.path().to_path_buf());
        let info = cmd_info("gh", Some("pr"), false);

        // Corrupt the project store before any record.
        let dir = test_project_dir(&store).to_path_buf();
        std::fs::create_dir_all(&dir).unwrap();
        let store_path = dir.join(APPROVALS_FILE);
        let corrupt_bytes = b"{".as_slice();
        std::fs::write(&store_path, corrupt_bytes).unwrap();

        // A record at project scope must fail closed rather than recreate a
        // fresh store that silently drops every standing entry.
        let err = match store
            .record_command(&info, RiskTier::Mutating, Scope::Project)
            .await
        {
            Ok(()) => panic!("recording into a corrupt store must fail closed"),
            Err(StoreError::Io(error)) => format!("{error:#}"),
            Err(other) => panic!("unexpected store error: {other}"),
        };
        assert!(err.contains("corrupt"), "{err}");

        // The corrupt bytes are preserved (copied aside, never deleted) and
        // the active store path was NOT rewritten with a fresh file — it
        // still holds the corrupt bytes, exactly as found.
        assert_eq!(std::fs::read(&store_path).unwrap(), corrupt_bytes);
        let residue = find_quarantine_residue(&dir)
            .expect("residue enumeration")
            .expect("quarantine copy preserved");
        assert_eq!(std::fs::read(&residue).unwrap(), corrupt_bytes);
    }

    /// Child-probe writer id for the cross-process lock test: the parent
    /// re-executes this test binary as a separate child process with this
    /// variable (and the dir variable below) set, and the probe performs
    /// one locked read-modify-write cycle before returning.
    const APPROVALS_LOCK_PROBE_WRITER: &str = "COCKPIT_TEST_APPROVALS_LOCK_WRITER";
    /// Child-probe approvals dir for the cross-process lock test.
    const APPROVALS_LOCK_PROBE_DIR: &str = "COCKPIT_TEST_APPROVALS_LOCK_DIR";

    #[test]
    fn approvals_writes_are_serialized_and_owner_private() {
        // Child-probe mode: run one locked read-modify-write cycle and
        // return. This keeps the serialization test on the real
        // cross-process boundary (issue #297) instead of only the
        // intra-process one: a regression that keeps threads serialized
        // but loses inter-process exclusion fails the parent's assertions.
        if let (Ok(writer), Ok(dir)) = (
            std::env::var(APPROVALS_LOCK_PROBE_WRITER),
            std::env::var(APPROVALS_LOCK_PROBE_DIR),
        ) {
            mutate_approvals(Path::new(&dir), move |file| {
                file.commands_reject.insert(format!("key-{writer}"));
                (true, ())
            })
            .expect("probe approvals write");
            return;
        }

        let dir = tempfile::tempdir().unwrap();
        let store_path = dir.path().join(APPROVALS_FILE);

        // Pre-existing permissive lock file and stale fixed-name temp, as
        // an earlier crash or a bad umask would leave behind (issue #297):
        // acquisition must tighten the lock through its own handle and
        // never truncate it, and a staged publish must never consume the
        // stale temp entry — it stages in a fresh exclusive temp of its
        // own instead.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let tmp = dir.path().join(format!("{APPROVALS_FILE}.tmp"));
            std::fs::write(&tmp, b"stale").unwrap();
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o666)).unwrap();
            let lock = dir.path().join(APPROVALS_LOCK_FILE);
            std::fs::write(&lock, b"lock sentinel").unwrap();
            std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(0o666)).unwrap();
        }

        // Seed one entry.
        mutate_approvals(dir.path(), |file| {
            file.commands_reject.insert("seed".to_string());
            (true, ())
        })
        .unwrap();

        // Concurrent read-modify-write cycles must serialize under the
        // cross-process lock: every writer's entry survives. The writers
        // are real child processes (the probe mode above) spawned
        // together, so the lock is exercised across overlapping
        // processes — a regression that keeps threads serialized but
        // loses inter-process exclusion clobbers entries here.
        const WRITERS: u32 = 8;
        let exe = std::env::current_exe().unwrap();
        // Libtest test names are the module path from the crate root
        // (`approval::store::tests::…`) — they are never crate-qualified,
        // so a `cockpit_core::…` filter matches zero tests and the children
        // exit successfully without ever entering the probe above. The
        // current test thread's name is exactly the full libtest test
        // name, so the child filter self-maintains through renames.
        let test_name = std::thread::current()
            .name()
            .expect("libtest names the test thread")
            .to_string();
        let mut children = Vec::new();
        for writer in 0..WRITERS {
            let child = std::process::Command::new(&exe)
                .arg("--exact")
                .arg(&test_name)
                .env(APPROVALS_LOCK_PROBE_WRITER, writer.to_string())
                .env(APPROVALS_LOCK_PROBE_DIR, dir.path().as_os_str())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .expect("spawning approvals writer probe");
            children.push((writer, child));
        }
        for (writer, child) in children {
            let output = child
                .wait_with_output()
                .expect("waiting for approvals writer probe");
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(
                output.status.success(),
                "writer {writer} failed\nstdout:\n{stdout}\nstderr:\n{stderr}"
            );
            // The probe must actually run in the child: a filter that
            // matched zero tests still exits 0, and the entry assertions
            // below would then prove nothing about the cross-process
            // boundary.
            assert!(
                stdout.contains("1 passed"),
                "writer {writer} ran no matching test — the libtest filter \
                 matched nothing\nstdout:\n{stdout}\nstderr:\n{stderr}"
            );
        }

        let file = load_approvals(dir.path()).unwrap().unwrap();
        for writer in 0..WRITERS {
            assert!(
                file.commands_reject.contains(&format!("key-{writer}")),
                "writer {writer}'s entry was clobbered"
            );
        }
        assert!(file.commands_reject.contains("seed"));
        assert!(store_path.exists());

        // The store file and the lock file are never world-readable —
        // including when they started as pre-existing permissive files —
        // the lock is never truncated by acquisition, and the stale
        // fixed-name temp is never consumed by a publish (issue #297).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&store_path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "approvals.json must be owner-only");
            let lock_path = dir.path().join(APPROVALS_LOCK_FILE);
            let lock_mode = std::fs::metadata(&lock_path).unwrap().permissions().mode() & 0o777;
            assert_eq!(lock_mode, 0o600, "approvals lock must be owner-only");
            assert_eq!(
                std::fs::read(&lock_path).unwrap(),
                b"lock sentinel".as_slice(),
                "lock acquisition must never truncate the lock file"
            );
            let stale_tmp = dir.path().join(format!("{APPROVALS_FILE}.tmp"));
            assert_eq!(
                std::fs::read(&stale_tmp).unwrap(),
                b"stale".as_slice(),
                "a stale fixed-name temp must never be consumed by a publish"
            );
            let stale_mode = std::fs::metadata(&stale_tmp).unwrap().permissions().mode() & 0o777;
            assert_eq!(
                stale_mode, 0o666,
                "an unconsumed stale temp is never touched"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn quarantine_copies_the_diagnosed_bytes_aside_and_tightens_the_original() {
        // Quarantine never mutates the live path: a path-based rename
        // cannot be proven to act on the inspected object at the moment it
        // takes effect, so the diagnosed bytes are copied aside to a
        // fresh owner-only copy, and the world-readable corrupt original
        // is tightened best-effort through the inspected handle
        // (issue #297).
        use std::io::Read as _;
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(APPROVALS_FILE);
        std::fs::write(&path, b"{corrupt").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
        let mut inspected = std::fs::File::open(&path).unwrap();
        let mut bytes = Vec::new();
        inspected.read_to_end(&mut bytes).unwrap();

        let preserved = quarantine_corrupt_approvals(&path, &inspected, &bytes)
            .expect("quarantine preserves the diagnosed bytes");
        // The live path is left exactly as found — never vacated, renamed,
        // or deleted — for the owner to repair in place.
        assert_eq!(std::fs::read(&path).unwrap(), b"{corrupt".as_slice());
        assert_eq!(std::fs::read(&preserved).unwrap(), b"{corrupt".as_slice());
        let mode = std::fs::metadata(&preserved).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "the quarantine copy must be owner-only");
        let live_mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            live_mode, 0o600,
            "the corrupt original is tightened through the inspected handle"
        );
    }

    #[cfg(unix)]
    #[test]
    fn quarantine_preserves_the_inspected_object_not_whatever_occupies_the_live_path() {
        // The bytes are read through an open handle, and by quarantine
        // time an external repair (or any non-cooperating writer) has
        // replaced the live path with a valid store. Quarantine must
        // preserve the object it diagnosed and never touch the
        // replacement at the live path (issue #297).
        use std::io::Read as _;
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(APPROVALS_FILE);
        std::fs::write(&path, b"{corrupt").unwrap();
        let mut inspected = std::fs::File::open(&path).unwrap();
        let mut bytes = Vec::new();
        inspected.read_to_end(&mut bytes).unwrap();
        // Replace the path entry (rename, not truncate — the handle keeps
        // pointing at the corrupt object).
        let replacement = dir.path().join("replacement");
        std::fs::write(&replacement, b"{}").unwrap();
        std::fs::rename(&replacement, &path).unwrap();

        let preserved = quarantine_corrupt_approvals(&path, &inspected, &bytes)
            .expect("quarantine preserves the inspected object");
        // The diagnosed bytes are what got preserved, by copy, while the
        // live path keeps its never-diagnosed replacement.
        assert_eq!(std::fs::read(&preserved).unwrap(), b"{corrupt".as_slice());
        assert_eq!(std::fs::read(&path).unwrap(), b"{}".as_slice());
        let mode = std::fs::metadata(&preserved).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "the quarantine copy must be owner-only");
    }

    #[cfg(unix)]
    #[test]
    fn reading_a_world_readable_approvals_store_repairs_it_to_owner_only() {
        // A live approvals.json created by the previous ambient-umask
        // writer can stay world-readable indefinitely on an installation
        // that only ever reads: the read path itself must tighten it
        // (issue #297), not just a later durable write.
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(APPROVALS_FILE);
        std::fs::write(&path, b"{}").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();

        // A plain read, as every lookup performs — no write involved.
        load_approvals(dir.path()).unwrap().unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "a healthy read must tighten the live store to owner-only"
        );
    }

    #[cfg(unix)]
    #[test]
    fn quarantine_preservation_never_overwrites_an_existing_copy() {
        // The preservation primitive is `create_new`: a colliding
        // quarantine name fails with `AlreadyExists` instead of replacing
        // the existing artifact, so a preserved diagnostic copy can never
        // be destroyed by a later quarantine attempt (issue #297).
        let dir = tempfile::tempdir().unwrap();
        let candidate = dir.path().join("approvals.json.corrupt-1");
        write_private_file(&candidate, b"first").unwrap();
        let err = write_private_file(&candidate, b"second").unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read(&candidate).unwrap(), b"first".as_slice());
    }

    #[cfg(unix)]
    #[test]
    fn discard_partial_private_candidate_never_deletes_a_replacement_at_the_name() {
        // Post-creation identity race (issue #297): between the exclusive
        // create of a private candidate and its failure cleanup, a
        // non-cooperating writer can unlink the candidate and install a
        // different object at the same name. The cleanup must remove only
        // the object this process created — proven through the held
        // handle — and leave the replacement artifact exactly as found.
        let dir = tempfile::tempdir().unwrap();
        let candidate = dir.path().join("approvals.json.corrupt-1");
        let out = open_new_private_file(&candidate).unwrap();
        std::fs::remove_file(&candidate).unwrap();
        std::fs::write(&candidate, b"replacement artifact").unwrap();

        discard_partial_private_candidate(out, &candidate);

        assert_eq!(
            std::fs::read(&candidate).unwrap(),
            b"replacement artifact".as_slice(),
            "cleanup must never destroy an object it did not create"
        );
    }

    #[cfg(unix)]
    #[test]
    fn discard_partial_private_candidate_removes_the_partial_it_created() {
        // The happy failure path (issue #297): a candidate whose entry is
        // still the object this process created is removed, and the
        // removal is proven after the act through the still-held handle
        // (its one link drops to zero at this removal) — leaving no
        // residue from a failed write.
        let dir = tempfile::tempdir().unwrap();
        let candidate = dir.path().join("approvals.json.corrupt-1");
        let out = open_new_private_file(&candidate).unwrap();

        discard_partial_private_candidate(out, &candidate);

        assert!(
            !candidate.exists(),
            "the partial this process created must be removed"
        );
    }

    #[cfg(unix)]
    #[test]
    fn discard_partial_private_candidate_refuses_a_hard_linked_candidate() {
        // Pre-removal link-count guard (issue #297): a hard link to the
        // candidate object means it is linked more than once — its state
        // was tampered with and the entry can no longer be bounded to the
        // one link this process created, so the guarded removal refuses
        // and leaves the name exactly as found.
        let dir = tempfile::tempdir().unwrap();
        let candidate = dir.path().join("approvals.json.corrupt-1");
        let out = open_new_private_file(&candidate).unwrap();
        let alias = dir.path().join("hard-linked-alias");
        std::fs::hard_link(&candidate, &alias).unwrap();

        discard_partial_private_candidate(out, &candidate);

        assert!(
            candidate.exists(),
            "a hard-linked candidate must never be removed by cleanup"
        );
        assert!(alias.exists(), "the alias must be left untouched");
    }

    #[cfg(unix)]
    #[test]
    fn store_publish_aborts_when_the_held_lock_no_longer_occupies_the_lock_path() {
        // The lock must be one stable shared object (issue #297): if the
        // lock pathname is replaced while a cycle holds a lock on the
        // original object, the serialization boundary is gone, so the
        // publish aborts rather than silently racing whatever now
        // serializes on the replacement. A later cycle converges on the
        // current lock object and succeeds.
        let dir = tempfile::tempdir().unwrap();
        let lock = lock_approvals(dir.path()).unwrap();
        std::fs::write(dir.path().join(APPROVALS_FILE), b"{}").unwrap();
        // Replace the lock path entry (unlink + install a different
        // object), as a non-cooperating writer would.
        std::fs::remove_file(dir.path().join(APPROVALS_LOCK_FILE)).unwrap();
        std::fs::write(dir.path().join(APPROVALS_LOCK_FILE), b"").unwrap();

        let error = store_approvals(
            dir.path(),
            &lock,
            &ApprovalsFile {
                commands_reject: BTreeSet::from(["stolen-boundary".to_string()]),
                ..ApprovalsFile::default()
            },
        )
        .unwrap_err();
        let message = format!("{error:#}");
        assert!(
            message.contains("no longer refers to the lock object"),
            "{message}"
        );
        // The store is left untouched.
        assert_eq!(
            std::fs::read(dir.path().join(APPROVALS_FILE)).unwrap(),
            b"{}".as_slice()
        );
        // The next cycle acquires the current lock object and succeeds.
        drop(lock);
        mutate_approvals(dir.path(), |file| {
            file.commands_reject.insert("fresh".to_string());
            (true, ())
        })
        .unwrap();
        let file = load_approvals(dir.path()).unwrap().unwrap();
        assert!(
            file.commands_reject.contains("fresh"),
            "a fresh cycle must serialize on the current lock object"
        );
    }

    #[cfg(unix)]
    #[test]
    fn store_publish_aborts_and_cleans_its_temp_when_the_lock_is_replaced_after_staging() {
        // The serialization fence is proven at the publication boundary,
        // after the staged temp exists (issue #297): a lock pathname
        // replaced between staging and the publish aborts the write with
        // the store untouched — and removes this process's own staged
        // partial, so the abort never leaves temp residue.
        let dir = tempfile::tempdir().unwrap();
        let lock = lock_approvals(dir.path()).unwrap();
        std::fs::write(dir.path().join(APPROVALS_FILE), b"{}").unwrap();
        let dir_path = dir.path().to_path_buf();
        AFTER_STAGING_HOOK.with(|slot| {
            *slot.borrow_mut() = Some(Box::new(move || {
                // Replace the lock path entry (unlink + install a
                // different object), as a non-cooperating writer would.
                std::fs::remove_file(dir_path.join(APPROVALS_LOCK_FILE)).unwrap();
                std::fs::write(dir_path.join(APPROVALS_LOCK_FILE), b"").unwrap();
            }));
        });

        let error = store_approvals(
            dir.path(),
            &lock,
            &ApprovalsFile {
                commands_reject: BTreeSet::from(["stolen-boundary".to_string()]),
                ..ApprovalsFile::default()
            },
        )
        .unwrap_err();
        let message = format!("{error:#}");
        assert!(
            message.contains("no longer refers to the lock object"),
            "{message}"
        );
        // The store is left untouched.
        assert_eq!(
            std::fs::read(dir.path().join(APPROVALS_FILE)).unwrap(),
            b"{}".as_slice()
        );
        // The staged partial this process created is removed by the
        // abort — the boundary fence never leaks temp residue.
        for entry in std::fs::read_dir(dir.path()).unwrap() {
            let name = entry.unwrap().file_name();
            let name = name.to_string_lossy();
            assert!(
                !name.starts_with(&format!("{APPROVALS_FILE}.tmp-")),
                "a fence abort must clean its own staged temp (found {name})"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn store_publish_aborts_when_the_staged_temp_is_substituted_before_the_boundary_proofs() {
        // The staged entry is discoverable by enumeration after its
        // creation (issue #297): a non-cooperating writer can unlink it and
        // install a replacement before the publish. The pre-act staged
        // identity proof catches it, the publish aborts with the store
        // untouched, and the replacement is left exactly as found — never
        // removed, never installed.
        let dir = tempfile::tempdir().unwrap();
        let lock = lock_approvals(dir.path()).unwrap();
        std::fs::write(dir.path().join(APPROVALS_FILE), b"{}").unwrap();
        let dir_path = dir.path().to_path_buf();
        AFTER_STAGING_HOOK.with(|slot| {
            *slot.borrow_mut() = Some(Box::new(move || {
                let staged = find_staged_store_temp(&dir_path);
                std::fs::remove_file(&staged).unwrap();
                std::fs::write(&staged, b"attacker staged bytes").unwrap();
            }));
        });

        let error = store_approvals(
            dir.path(),
            &lock,
            &ApprovalsFile {
                commands_reject: BTreeSet::from(["never-landed".to_string()]),
                ..ApprovalsFile::default()
            },
        )
        .unwrap_err();
        let message = format!("{error:#}");
        assert!(
            message.contains("substituted before the rename"),
            "{message}"
        );
        // The store is left untouched.
        assert_eq!(
            std::fs::read(dir.path().join(APPROVALS_FILE)).unwrap(),
            b"{}".as_slice()
        );
        // The replacement at the staged name is left exactly as found —
        // it is not this process's object to remove or install.
        let staged = find_staged_store_temp(dir.path());
        assert_eq!(
            std::fs::read(&staged).unwrap(),
            b"attacker staged bytes".as_slice()
        );
    }

    #[cfg(unix)]
    #[test]
    fn store_publish_fails_closed_when_the_staged_temp_is_substituted_in_the_rename_window() {
        // The irreducible name-based instant between the pre-act proofs
        // and the rename (issue #297): a substitution landing exactly
        // there makes the rename install the replacement's entry. The
        // post-act published-entry proof detects it through the held
        // staged handle and the write reports failure — a substituted
        // publish never reports success.
        let dir = tempfile::tempdir().unwrap();
        let lock = lock_approvals(dir.path()).unwrap();
        std::fs::write(dir.path().join(APPROVALS_FILE), b"{}").unwrap();
        let dir_path = dir.path().to_path_buf();
        BEFORE_PUBLISH_RENAME_HOOK.with(|slot| {
            *slot.borrow_mut() = Some(Box::new(move || {
                let staged = find_staged_store_temp(&dir_path);
                std::fs::remove_file(&staged).unwrap();
                std::fs::write(&staged, b"attacker installed bytes").unwrap();
            }));
        });

        let error = store_approvals(
            dir.path(),
            &lock,
            &ApprovalsFile {
                commands_reject: BTreeSet::from(["never-reported-success".to_string()]),
                ..ApprovalsFile::default()
            },
        )
        .unwrap_err();
        let message = format!("{error:#}");
        assert!(
            message.contains("substituted during the rename"),
            "{message}"
        );
        // The transient installed bytes are the attacker's, not this
        // write's — the failure is reported, never a false success. (The
        // live path now holds invalid JSON; every later read fails closed
        // through the corrupt-store path, preserving the standing
        // rejects rather than silently dropping them.)
        assert_eq!(
            std::fs::read(dir.path().join(APPROVALS_FILE)).unwrap(),
            b"attacker installed bytes".as_slice()
        );
    }

    #[cfg(unix)]
    #[test]
    fn store_publish_fails_closed_when_the_lock_is_replaced_in_the_rename_window() {
        // The serialization boundary is proven on both sides of the
        // rename (issue #297): a lock pathname replaced in the pre-act
        // proof→rename window is caught by the post-act fence, and the
        // write reports failure — a publish is never claimed successful
        // while the exclusion it relied on was replaced mid-act.
        let dir = tempfile::tempdir().unwrap();
        let lock = lock_approvals(dir.path()).unwrap();
        std::fs::write(dir.path().join(APPROVALS_FILE), b"{}").unwrap();
        let dir_path = dir.path().to_path_buf();
        BEFORE_PUBLISH_RENAME_HOOK.with(|slot| {
            *slot.borrow_mut() = Some(Box::new(move || {
                std::fs::remove_file(dir_path.join(APPROVALS_LOCK_FILE)).unwrap();
                std::fs::write(dir_path.join(APPROVALS_LOCK_FILE), b"").unwrap();
            }));
        });

        let error = store_approvals(
            dir.path(),
            &lock,
            &ApprovalsFile {
                commands_reject: BTreeSet::from(["boundary-replaced-midact".to_string()]),
                ..ApprovalsFile::default()
            },
        )
        .unwrap_err();
        let message = format!("{error:#}");
        assert!(
            message.contains("was replaced while the store was being published"),
            "{message}"
        );
        // The rename itself completed with this process's proven-staged
        // object (the post-act published-entry proof passed), but the
        // serialization boundary was gone mid-act, so the write is
        // reported as failed — the honest outcome, never a claimed
        // serialized success.
        let file = load_approvals(dir.path()).unwrap().unwrap();
        assert!(
            file.commands_reject.contains("boundary-replaced-midact"),
            "the completed rename's data is on disk; only the claim of a \
             serialized success is refused"
        );
    }

    /// The staged store temp's path, found by enumeration: the staging
    /// name is random but its prefix is fixed, exactly how a
    /// non-cooperating writer discovers it (issue #297). Test-only.
    #[cfg(unix)]
    fn find_staged_store_temp(dir: &Path) -> PathBuf {
        std::fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with(&format!("{APPROVALS_FILE}.tmp-")))
            })
            .expect("the staged store temp exists while the publish is in flight")
    }

    #[cfg(unix)]
    #[test]
    fn lock_acquisition_fails_closed_on_a_symlinked_lock_path() {
        // A planted symlink at the lock path must never be followed
        // (issue #297): acquisition refuses (fail closed) instead of
        // locking — and truncating, and tightening the mode of — the
        // symlink's target through a followed handle.
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        std::fs::write(&target, b"must not be truncated").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o666)).unwrap();
        std::os::unix::fs::symlink(&target, dir.path().join(APPROVALS_LOCK_FILE)).unwrap();

        let error = lock_approvals(dir.path()).unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains(APPROVALS_LOCK_FILE), "{message}");
        // The symlink's target is untouched — never truncated, never
        // tightened through a followed handle.
        assert_eq!(
            std::fs::read(&target).unwrap(),
            b"must not be truncated".as_slice()
        );
        let mode = std::fs::metadata(&target).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o666);
    }

    #[cfg(unix)]
    #[test]
    fn unenumerable_approvals_dir_fails_the_read_closed_not_open() {
        // When the approvals directory cannot be inspected, absence of a
        // preserved quarantine copy has NOT been established: the read
        // fails closed instead of proceeding as though the fence were
        // clear (issue #297).
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(APPROVALS_FILE), b"{}").unwrap();
        // Traversable but not enumerable (no read bit): the live file can
        // still be opened, but the residue scan cannot run.
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o111)).unwrap();

        let err = load_approvals(dir.path()).unwrap_err();
        let msg = err.refusal_message();
        assert!(msg.contains("could not be searched"), "{msg}");
        let dir_display = dir.path().display().to_string();
        assert!(msg.contains(&dir_display), "{msg}");

        // Restore enumerability and the same store reads healthy again.
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        load_approvals(dir.path()).unwrap().unwrap();
    }

    #[tokio::test]
    async fn loop_rule_keys_on_exact_signature_not_tool_name() {
        // A rule for one call must NOT cover a different call of the same
        // tool with different args.
        let tmp = tempfile::tempdir().unwrap();
        let global = tempfile::tempdir().unwrap();
        let (store, _) = test_store(tmp.path(), global.path().to_path_buf());
        let sig_a = GrantStore::loop_signature("read", &serde_json::json!({"path": "a"}));
        let sig_b = GrantStore::loop_signature("read", &serde_json::json!({"path": "b"}));
        store
            .record_loop_rule(&sig_a, LoopVerdict::Accept, Scope::Session)
            .await
            .unwrap();
        assert_eq!(
            store.loop_rule(&sig_a).await.unwrap(),
            Some(LoopVerdict::Accept)
        );
        assert!(store.loop_rule(&sig_b).await.unwrap().is_none());
    }

    // ---- live approval-policy reload (approval-policy-live-reload) --------

    use crate::daemon::session_worker::SessionConfigSnapshot;
    use std::sync::{Arc, RwLock};

    /// A config snapshot carrying `policy` as the effective approval policy;
    /// everything else is default. Used to feed a specific policy through a
    /// live [`SessionConfigHandle`] cell.
    fn snapshot_with_policy(
        generation: u64,
        policy: ApprovalPolicyConfig,
    ) -> SessionConfigSnapshot {
        let extended = crate::config::extended::ExtendedConfig {
            approval_policy: policy,
            ..Default::default()
        };
        SessionConfigSnapshot::new(
            generation,
            crate::config::providers::ProvidersConfig::default(),
            extended,
        )
    }

    /// Replace the live policy in a shared snapshot cell, as a daemon
    /// re-resolution (`ReplaceConfigSnapshot`) would for a running session.
    fn set_cell_policy(
        cell: &Arc<RwLock<SessionConfigSnapshot>>,
        generation: u64,
        policy: ApprovalPolicyConfig,
    ) {
        *cell.write().unwrap() = snapshot_with_policy(generation, policy);
    }

    /// Build an in-memory-backed store whose approval policy is read live from
    /// the returned shared cell. Mutating the cell simulates a policy change on
    /// a running session. The `tmp` dir must outlive the store.
    fn live_policy_store(
        tmp: &Path,
        initial: ApprovalPolicyConfig,
    ) -> (GrantStore, Arc<RwLock<SessionConfigSnapshot>>) {
        let db = Db::open_in_memory().unwrap();
        let session = crate::session::Session::create_for_test(
            db.clone(),
            tmp.to_path_buf(),
            "builder",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap();
        let cell = Arc::new(RwLock::new(snapshot_with_policy(1, initial)));
        let store = GrantStore::new(
            db,
            session.id,
            tmp.to_path_buf(),
            SessionConfigHandle::new(cell.clone()),
        );
        (store, cell)
    }

    fn risk_policy(tier_key: &str, scope: ApprovalPolicyScope) -> ApprovalPolicyConfig {
        let mut policy = ApprovalPolicyConfig::default();
        policy.risk_max_scope.insert(tier_key.to_string(), scope);
        policy
    }

    fn dangerous_flag_policy(tier: &str, flags: Vec<&str>) -> ApprovalPolicyConfig {
        let mut policy = ApprovalPolicyConfig::default();
        policy.dangerous_flags.insert(
            "git push".to_string(),
            DangerousFlagRule {
                flags: flags.into_iter().map(str::to_string).collect(),
                tier: tier.to_string(),
            },
        );
        policy
    }

    /// A1: a policy change during a live session is observed by the store
    /// without rebuilding it.
    #[tokio::test]
    async fn grant_store_observes_policy_change_without_rebuild() {
        let tmp = tempfile::tempdir().unwrap();
        let (store, cell) = live_policy_store(
            tmp.path(),
            risk_policy("ordinary", ApprovalPolicyScope::Session),
        );
        assert_eq!(
            store.approval_policy().risk_max_scope.get("ordinary"),
            Some(&ApprovalPolicyScope::Session),
        );

        // Change the policy live — no new store is constructed.
        set_cell_policy(
            &cell,
            2,
            risk_policy("ordinary", ApprovalPolicyScope::Project),
        );
        assert_eq!(
            store.approval_policy().risk_max_scope.get("ordinary"),
            Some(&ApprovalPolicyScope::Project),
            "the same store observed the live policy change",
        );
    }

    /// A2: the accessor performs no disk read per call (asserted with the
    /// existing `load_for_cwd` counter).
    #[tokio::test]
    async fn approval_policy_accessor_does_no_disk_read() {
        let tmp = tempfile::tempdir().unwrap();
        let (store, _cell) = live_policy_store(tmp.path(), ApprovalPolicyConfig::default());
        crate::config::extended::reset_load_for_cwd_call_count();
        for _ in 0..5 {
            let _ = store.approval_policy();
        }
        assert_eq!(
            crate::config::extended::load_for_cwd_call_count(),
            0,
            "approval_policy() must not read config from disk",
        );
    }

    /// A3: resolution is trust-aware — it flows through the in-memory
    /// `SessionConfigHandle` (fed by the daemon's trust-aware `ConfigSource`
    /// in production), never a bare `load_for_cwd`. Construction and reads
    /// perform no bare disk load.
    #[tokio::test]
    async fn grant_store_policy_resolution_is_trust_aware() {
        let tmp = tempfile::tempdir().unwrap();
        let mut policy = ApprovalPolicyConfig::default();
        policy
            .program_max_scope
            .insert("gh".to_string(), ApprovalPolicyScope::Project);
        let (store, _cell) = live_policy_store(tmp.path(), policy);
        // The resolution path reads through the handle (fed by the trust-aware
        // ConfigSource in production), never a bare `load_for_cwd`.
        crate::config::extended::reset_load_for_cwd_call_count();
        let resolved = store.approval_policy();
        assert_eq!(
            crate::config::extended::load_for_cwd_call_count(),
            0,
            "no bare load_for_cwd on the resolution path",
        );
        assert_eq!(
            resolved.program_max_scope.get("gh"),
            Some(&ApprovalPolicyScope::Project),
            "the store resolves exactly the policy carried by the handle",
        );
    }

    /// A4: an in-flight decision captures the policy once at its start and is
    /// not re-evaluated when the policy changes mid-decision; the next
    /// decision observes the new policy.
    #[tokio::test]
    async fn policy_change_does_not_affect_inflight_decision() {
        let tmp = tempfile::tempdir().unwrap();
        let (store, cell) = live_policy_store(
            tmp.path(),
            risk_policy("ordinary", ApprovalPolicyScope::Session),
        );

        // The decision reads the policy once at its start.
        let captured = store.approval_policy();

        // The policy changes live, mid-decision.
        set_cell_policy(
            &cell,
            2,
            risk_policy("ordinary", ApprovalPolicyScope::Global),
        );

        // The in-flight decision's captured policy is unaffected...
        assert_eq!(
            captured.risk_max_scope.get("ordinary"),
            Some(&ApprovalPolicyScope::Session),
        );
        // ...while the next decision observes the new policy.
        assert_eq!(
            store.approval_policy().risk_max_scope.get("ordinary"),
            Some(&ApprovalPolicyScope::Global),
        );
    }

    /// A5: a malformed policy keeps the last good value and never falls open
    /// to a more permissive outcome. An unrecognized risk-tier key would
    /// silently drop the intended cap (a fall-open) and is therefore rejected.
    #[tokio::test]
    async fn invalid_policy_keeps_last_good_and_does_not_fall_open() {
        let tmp = tempfile::tempdir().unwrap();
        // Last good policy tightens ordinary commands to Session (narrower
        // than the built-in default of Global).
        let (store, cell) = live_policy_store(
            tmp.path(),
            risk_policy("ordinary", ApprovalPolicyScope::Session),
        );
        assert_eq!(
            store.approval_policy().risk_max_scope.get("ordinary"),
            Some(&ApprovalPolicyScope::Session),
        );

        // A malformed policy lands live: an unknown risk-tier key.
        set_cell_policy(
            &cell,
            2,
            risk_policy("not-a-tier", ApprovalPolicyScope::Global),
        );

        let resolved = store.approval_policy();
        assert_eq!(
            resolved.risk_max_scope.get("ordinary"),
            Some(&ApprovalPolicyScope::Session),
            "malformed policy must keep the last good cap, not fall open",
        );
        assert!(
            !resolved.risk_max_scope.contains_key("not-a-tier"),
            "the malformed policy must not be adopted",
        );
    }

    #[tokio::test]
    async fn dangerous_flags_rule_with_bad_tier_keeps_last_good_policy() {
        let tmp = tempfile::tempdir().unwrap();
        let (store, cell) = live_policy_store(
            tmp.path(),
            risk_policy("ordinary", ApprovalPolicyScope::Session),
        );

        set_cell_policy(
            &cell,
            2,
            dangerous_flag_policy("not-a-tier", vec!["--force"]),
        );

        let resolved = store.approval_policy();
        assert_eq!(
            resolved.risk_max_scope.get("ordinary"),
            Some(&ApprovalPolicyScope::Session),
            "bad dangerousFlags tier must keep the last good policy",
        );
        assert!(
            resolved.dangerous_flags.is_empty(),
            "the malformed dangerousFlags policy must not be adopted",
        );
    }

    #[tokio::test]
    async fn dangerous_flags_rule_with_empty_flag_list_keeps_last_good_policy() {
        let tmp = tempfile::tempdir().unwrap();
        let (store, cell) = live_policy_store(
            tmp.path(),
            risk_policy("ordinary", ApprovalPolicyScope::Session),
        );

        set_cell_policy(&cell, 2, dangerous_flag_policy("destructive", Vec::new()));

        let resolved = store.approval_policy();
        assert_eq!(
            resolved.risk_max_scope.get("ordinary"),
            Some(&ApprovalPolicyScope::Session),
            "empty dangerousFlags flag list must keep the last good policy",
        );
        assert!(
            resolved.dangerous_flags.is_empty(),
            "the malformed dangerousFlags policy must not be adopted",
        );
    }

    /// A6: grant-file behavior is unchanged — a direct file deletion (as the
    /// permissions pane performs) still propagates to the same live store on
    /// its next check, because grant files are re-read per check.
    #[tokio::test]
    async fn grant_file_changes_still_propagate() {
        let tmp = tempfile::tempdir().unwrap();
        let global = tempfile::tempdir().unwrap();
        let (store, _) = test_store(tmp.path(), global.path().to_path_buf());
        let info = cmd_info("gh", Some("pr"), false);
        store
            .record_command(&info, info.risk.tier, Scope::Project)
            .await
            .unwrap();
        assert!(store.is_command_granted(&info.key).await);

        // Delete the grant straight from the file, as the permissions pane does.
        let dir = test_project_dir(&store).to_path_buf();
        assert!(
            delete_managed_grant(&dir, ManagedGrantKind::Command, &info.key.as_display_str())
                .unwrap()
        );

        // The same store sees the deletion on its next check (no rebuild).
        assert!(!store.is_command_granted(&info.key).await);
    }

    /// A7: approval outcomes are unchanged for a static policy. A Session-scope
    /// grant of an ordinary command is within the default cap (Global) and is
    /// allowed without a prompt; repeated policy reads are stable.
    #[tokio::test]
    async fn approval_outcomes_unchanged_for_static_policy() {
        let tmp = tempfile::tempdir().unwrap();
        let global = tempfile::tempdir().unwrap();
        let (store, _) = test_store(tmp.path(), global.path().to_path_buf());
        let info = cmd_info("gh", Some("pr"), false);

        assert!(!crate::approval::command_grant_allowed_by_policy(&store, &info).await);
        store
            .record_command(&info, info.risk.tier, Scope::Session)
            .await
            .unwrap();
        assert!(crate::approval::command_grant_allowed_by_policy(&store, &info).await);

        // The static policy resolves to the same value on every read.
        assert_eq!(store.approval_policy(), store.approval_policy());
    }
}

#[cfg(test)]
mod mcp_server_connect_grant_tests {
    use super::*;

    #[tokio::test]
    async fn server_grant_does_not_survive_command_change() {
        let root = tempfile::tempdir().unwrap();
        let global = tempfile::tempdir().unwrap();
        let (store, _) = super::tests::test_store(root.path(), global.path().to_path_buf());
        let original = "stdio command=first args=[\"--safe\"]";
        let changed = "stdio command=second args=[\"--safe\"]";
        store
            .record_mcp_server_connect("server", original, Scope::Project)
            .await
            .unwrap();
        assert_eq!(
            store
                .mcp_server_connect_grant_scope("server", original)
                .await
                .unwrap(),
            Some(Scope::Project)
        );
        assert_eq!(
            store
                .mcp_server_connect_grant_scope("server", changed)
                .await
                .unwrap(),
            None
        );
        // A server-connect grant cannot become an external tool grant.
        assert_eq!(
            store
                .mcp_tool_grant_scope("server", original)
                .await
                .unwrap(),
            None
        );
    }
}

#[cfg(test)]
mod image_generation_grant_tests {
    use super::*;

    #[tokio::test]
    async fn image_generation_grant_once_and_global_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let global = tempfile::tempdir().unwrap();
        let (store, _sid, project_id) =
            super::tests::test_store_with_project_id(tmp.path(), global.path().to_path_buf());
        let binding = "c".repeat(64);
        let authority = "out-authority-digest";
        let bounds = ImageGenerationGrantBounds {
            destination_binding_digest: &binding,
            output_path_authority: authority,
            reference_egress: false,
            fanout: 1,
            total_outputs: 1,
            cost_maximum: Some(1),
        };
        assert!(
            matches!(
                store
                    .record_image_generation_grant_bounded(Scope::Once, &project_id, bounds)
                    .await,
                Err(StoreError::OnceNotPersistable)
            ),
            "once grants are never persisted"
        );
        assert!(
            matches!(
                store
                    .record_image_generation_grant_bounded(Scope::Global, &project_id, bounds)
                    .await,
                Err(StoreError::ImageGenerationNoGlobalScope)
            ),
            "global image-generation grants are unrepresentable"
        );
    }

    #[tokio::test]
    async fn image_generation_grant_session_project_round_trip_and_revoke() {
        let tmp = tempfile::tempdir().unwrap();
        let global = tempfile::tempdir().unwrap();
        let (store, _sid, project_id) =
            super::tests::test_store_with_project_id(tmp.path(), global.path().to_path_buf());
        let binding = "d".repeat(64);
        let authority = "out-authority-digest";
        let bounds = ImageGenerationGrantBounds {
            destination_binding_digest: &binding,
            output_path_authority: authority,
            reference_egress: false,
            fanout: 2,
            total_outputs: 3,
            cost_maximum: Some(20),
        };

        // No grant initially.
        assert_eq!(
            store
                .image_generation_grant_scope_bounded(&project_id, bounds)
                .await,
            None
        );

        // Session-scope grant round-trips and matches the current session.
        store
            .record_image_generation_grant_bounded(Scope::Session, &project_id, bounds)
            .await
            .unwrap();
        assert_eq!(
            store
                .image_generation_grant_scope_bounded(&project_id, bounds)
                .await,
            Some(Scope::Session)
        );
        assert_eq!(
            store
                .image_generation_grant_scope_bounded(
                    &project_id,
                    ImageGenerationGrantBounds {
                        destination_binding_digest: &"e".repeat(64),
                        ..bounds
                    }
                )
                .await,
            None
        );
        // Revoking the session grant prevents reuse.
        assert_eq!(
            store
                .revoke_image_generation_grants_bounded(Scope::Session, &project_id, bounds)
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            store
                .image_generation_grant_scope_bounded(&project_id, bounds)
                .await,
            None
        );

        // Project-scope grant round-trips and matches via project_id.
        store
            .record_image_generation_grant_bounded(Scope::Project, &project_id, bounds)
            .await
            .unwrap();
        assert_eq!(
            store
                .image_generation_grant_scope_bounded(&project_id, bounds)
                .await,
            Some(Scope::Project)
        );
        // Membership audit: a foreign project_id never matches a project grant.
        assert_eq!(
            store
                .image_generation_grant_scope_bounded("other-project", bounds)
                .await,
            None
        );
        // Revoking the project grant prevents reuse.
        assert_eq!(
            store
                .revoke_image_generation_grants_bounded(Scope::Project, &project_id, bounds)
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            store
                .image_generation_grant_scope_bounded(&project_id, bounds)
                .await,
            None
        );
    }
}
