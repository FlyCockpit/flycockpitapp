//! Approval-decision store (sandboxing part 1, §2).
//!
//! Records grants so a future access skips the prompt. Two grant kinds —
//! command-key (the §1 `argv[0]`+subcommand key) and path (an absolute
//! path or prefix, for part 2's native confinement) — across four
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
//! location scheme. Project/Global are plain JSON files written
//! atomically (temp + rename); Session lives in SQLite.
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
use serde::{Deserialize, Serialize};

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
    /// No project root could be resolved for a `Project`-scope grant
    /// (the cwd isn't inside a git worktree).
    #[error("no project root for the current directory; cannot store a project grant")]
    NoProjectRoot,
    /// An I/O / serialization failure while reading or writing a grant.
    #[error(transparent)]
    Io(#[from] anyhow::Error),
}

/// On-disk shape of a project/global `approvals.json`. Sorted sets keep
/// the file stable (no spurious diffs) and dedup automatically.
#[derive(Debug, Default, Serialize, Deserialize)]
struct ApprovalsFile {
    /// Command-key allow grants, as storage strings (`"gh pr"`, `"ls"`).
    #[serde(default)]
    commands: BTreeSet<String>,
    /// Path allow grants, as absolute path / prefix strings mapped to access mode.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    paths: BTreeMap<String, SandboxPathAccess>,
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
/// last good policy is kept instead. Program/command keys are an open domain
/// (any command name) and are not validated.
fn approval_policy_is_valid(policy: &ApprovalPolicyConfig) -> bool {
    policy
        .risk_max_scope
        .keys()
        .all(|key| RiskTier::from_policy_key(key).is_some())
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

    /// Whether a command key is already **allowed** at *any* scope that
    /// applies to this session (Session, Project, or Global). `Once`
    /// grants are never stored, so they never show up here.
    #[cfg(test)]
    pub fn is_command_granted(&self, key: &ApprovalKey) -> bool {
        self.command_grant_scope(key).is_some()
    }

    pub fn command_grant_scope(&self, key: &ApprovalKey) -> Option<Scope> {
        let s = key.as_storage_str();
        if self.session_has(GrantKind::Command, &s, Verdict::Allow) {
            return Some(Scope::Session);
        }
        if self.project_file().is_some_and(|f| f.commands.contains(&s)) {
            return Some(Scope::Project);
        }
        if self.global_file().is_some_and(|f| f.commands.contains(&s)) {
            return Some(Scope::Global);
        }
        None
    }

    /// Whether a command key is **rejected** at any applicable scope — the
    /// allow query's mirror. A standing reject auto-denies the command
    /// without prompting (`DecisionSource::StandingReject`).
    #[cfg(test)]
    pub fn is_command_rejected(&self, key: &ApprovalKey) -> bool {
        self.command_reject_scope(key).is_some()
    }

    pub fn command_reject_scope(&self, key: &ApprovalKey) -> Option<Scope> {
        let s = key.as_storage_str();
        if self.session_has(GrantKind::Command, &s, Verdict::Reject) {
            return Some(Scope::Session);
        }
        if self
            .project_file()
            .is_some_and(|f| f.commands_reject.contains(&s))
        {
            return Some(Scope::Project);
        }
        if self
            .global_file()
            .is_some_and(|f| f.commands_reject.contains(&s))
        {
            return Some(Scope::Global);
        }
        None
    }

    #[cfg(test)]
    fn is_path_granted(&self, path: &Path) -> bool {
        self.is_path_granted_for(path, SandboxPathAccess::Read)
    }

    pub fn is_path_granted_for(&self, path: &Path, required: SandboxPathAccess) -> bool {
        self.effective_path_grant_access(path)
            .is_some_and(|access| access >= required)
    }

    pub fn effective_path_grant_access(&self, path: &Path) -> Option<SandboxPathAccess> {
        let candidate = normalize_path(path, &self.cwd);
        let matches = |stored: &str| path_covers(stored, &candidate);
        if self.path_reject_matches(matches) {
            return None;
        }
        let mut access: Option<SandboxPathAccess> = None;
        for (key, grant_access) in self.path_allow_entries() {
            if path_covers(&key, &candidate) {
                access = Some(access.map_or(grant_access, |current| current.max(grant_access)));
            }
        }
        access
    }

    pub fn effective_path_grants(&self) -> Vec<EffectivePathGrant> {
        let rejects = self.path_reject_entries();
        let mut by_path: BTreeMap<String, SandboxPathAccess> = BTreeMap::new();
        for (key, access) in self.path_allow_entries() {
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
        grants
    }

    /// Whether a path is **rejected** at any applicable scope — the allow
    /// path query's mirror (same prefix-match semantics). A standing path
    /// reject auto-denies the out-of-cwd access without prompting.
    pub fn is_path_rejected(&self, path: &Path) -> bool {
        let candidate = normalize_path(path, &self.cwd);
        let matches = |stored: &str| path_covers(stored, &candidate);
        self.path_reject_matches(matches)
    }

    /// Record a command-key **allow** grant at `scope`. Rejects wrappers at
    /// any non-`Once` scope (priority #1). `Once` is a no-op error — the
    /// caller shouldn't record it, but rejecting loudly catches misuse.
    /// Clears any standing **reject** for this key across every reachable
    /// scope first (mutual exclusivity), then writes the allow.
    pub fn record_command(
        &self,
        info: &crate::approval::classify::SimpleCommandInfo,
        scope: Scope,
    ) -> Result<(), StoreError> {
        if scope == Scope::Once {
            return Err(StoreError::OnceNotPersistable);
        }
        if info.wrapper {
            return Err(StoreError::WrapperNotPersistable(info.key.as_storage_str()));
        }
        self.record(
            GrantKind::Command,
            &info.key.as_storage_str(),
            scope,
            Verdict::Allow,
            None,
        )
    }

    /// Record a command-key **reject** grant at `scope` — the allow
    /// recorder's mirror. Same `Once`/wrapper rules (a wrapper is never
    /// persistable in either polarity). Clears any standing **allow** for
    /// this key across every reachable scope first, then writes the reject.
    pub fn record_command_reject(
        &self,
        info: &crate::approval::classify::SimpleCommandInfo,
        scope: Scope,
    ) -> Result<(), StoreError> {
        if scope == Scope::Once {
            return Err(StoreError::OnceNotPersistable);
        }
        if info.wrapper {
            return Err(StoreError::WrapperNotPersistable(info.key.as_storage_str()));
        }
        self.record(
            GrantKind::Command,
            &info.key.as_storage_str(),
            scope,
            Verdict::Reject,
            None,
        )
    }

    /// Record a path **allow** grant at `scope`. Paths are never wrappers,
    /// so the only rejection is `Once`. The path is normalized (absolutized
    /// against this store's session cwd) before storage so later prefix
    /// checks are stable.
    /// Clears any standing **reject** for this key across reachable scopes
    /// first.
    pub fn record_path(
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
        )
    }

    /// Record a path **reject** grant at `scope` — the allow recorder's
    /// mirror. Clears any standing **allow** for this key across reachable
    /// scopes first, then writes the reject.
    pub fn record_path_reject(&self, path: &Path, scope: Scope) -> Result<(), StoreError> {
        if scope == Scope::Once {
            return Err(StoreError::OnceNotPersistable);
        }
        self.record(
            GrantKind::Path,
            &normalize_path(path, &self.cwd),
            scope,
            Verdict::Reject,
            Some(SandboxPathAccess::ReadWrite),
        )
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
    /// other), so the first scope with *any* rule decides.
    pub fn loop_rule(&self, signature: &str) -> Option<LoopVerdict> {
        if let Some(v) = self.session_loop_rule(signature) {
            return Some(v);
        }
        if let Some(v) = self
            .project_file()
            .and_then(|f| file_loop_rule(&f, signature))
        {
            return Some(v);
        }
        self.global_file()
            .and_then(|f| file_loop_rule(&f, signature))
    }

    /// Record a loop-guard rule for `signature` at `scope`. Recording one
    /// verdict at a scope clears the opposite verdict at the same scope so
    /// a signature never carries contradictory rules within one scope.
    /// `Once` is rejected (it is never persisted — the caller acts on a
    /// one-off decision directly).
    pub fn record_loop_rule(
        &self,
        signature: &str,
        verdict: LoopVerdict,
        scope: Scope,
    ) -> Result<(), StoreError> {
        match scope {
            Scope::Once => Err(StoreError::OnceNotPersistable),
            Scope::Session => self
                .session_record_loop_rule(signature, verdict)
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

    fn session_loop_rule(&self, signature: &str) -> Option<LoopVerdict> {
        self.db
            .read_blocking(|conn| {
                let verdict: Option<String> = conn
                    .query_row(
                        "SELECT rule_verdict FROM loop_guard_rules \
                         WHERE session_id = ?1 AND signature = ?2",
                        rusqlite::params![self.session_id.to_string(), signature],
                        |row| row.get(0),
                    )
                    .optional()?;
                Ok(verdict)
            })
            .ok()
            .flatten()
            .and_then(|s| parse_verdict(&s))
    }

    fn session_record_loop_rule(&self, signature: &str, verdict: LoopVerdict) -> Result<()> {
        let session_id = self.session_id;
        let signature = signature.to_owned();
        self.db.write_blocking(move |conn| {
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
    }

    fn file_record_loop_rule(
        &self,
        dir: &Path,
        signature: &str,
        verdict: LoopVerdict,
    ) -> Result<()> {
        let mut file = load_approvals(dir).unwrap_or_default();
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
        store_approvals(dir, &file)
    }

    // ---- internals --------------------------------------------------------

    fn record(
        &self,
        kind: GrantKind,
        key: &str,
        scope: Scope,
        verdict: Verdict,
        access: Option<SandboxPathAccess>,
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
            .map_err(StoreError::Io)?;
        match scope {
            Scope::Once => Err(StoreError::OnceNotPersistable),
            Scope::Session => self
                .session_insert(kind, key, verdict, access)
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
                self.file_insert(dir, kind, key, verdict, access)
                    .map_err(StoreError::Io)
            }
            Scope::Global => {
                let dir = self
                    .global_dir
                    .clone()
                    .context("no global config dir available")
                    .map_err(StoreError::Io)?;
                self.file_insert(&dir, kind, key, verdict, access)
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
    fn clear_key_everywhere(&self, kind: GrantKind, key: &str, verdict: Verdict) -> Result<()> {
        // Session (always reachable).
        self.session_remove(kind, key, verdict)?;
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

    fn session_has(&self, kind: GrantKind, key: &str, verdict: Verdict) -> bool {
        self.db
            .read_blocking(|conn| {
                let n: i64 = conn.query_row(
                    "SELECT COUNT(*) FROM approval_grants \
                     WHERE session_id = ?1 AND grant_kind = ?2 AND grant_key = ?3 \
                       AND verdict = ?4",
                    rusqlite::params![
                        self.session_id.to_string(),
                        kind.as_str(),
                        key,
                        verdict.as_str()
                    ],
                    |row| row.get(0),
                )?;
                Ok(n > 0)
            })
            .unwrap_or(false)
    }

    fn session_path_entries(&self, verdict: Verdict) -> Vec<(String, SandboxPathAccess)> {
        self.db
            .read_blocking(|conn| {
                let mut stmt = conn.prepare(
                    "SELECT grant_key, access FROM approval_grants \
                     WHERE session_id = ?1 AND grant_kind = 'path' AND verdict = ?2 \
                     ORDER BY grant_key",
                )?;
                let rows = stmt.query_map(
                    rusqlite::params![self.session_id.to_string(), verdict.as_str()],
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
            .unwrap_or_default()
    }

    fn path_allow_entries(&self) -> Vec<(String, SandboxPathAccess)> {
        let mut entries = self.session_path_entries(Verdict::Allow);
        if let Some(file) = self.project_file() {
            entries.extend(file.paths);
        }
        if let Some(file) = self.global_file() {
            entries.extend(file.paths);
        }
        entries
    }

    fn path_reject_entries(&self) -> Vec<(String, SandboxPathAccess)> {
        let mut entries = self.session_path_entries(Verdict::Reject);
        if let Some(file) = self.project_file() {
            entries.extend(file.paths_reject);
        }
        if let Some(file) = self.global_file() {
            entries.extend(file.paths_reject);
        }
        entries
    }

    fn path_reject_matches<F>(&self, matches: F) -> bool
    where
        F: Fn(&str) -> bool,
    {
        self.path_reject_entries()
            .iter()
            .any(|(key, _)| matches(key))
    }

    fn session_insert(
        &self,
        kind: GrantKind,
        key: &str,
        verdict: Verdict,
        access: Option<SandboxPathAccess>,
    ) -> Result<()> {
        let session_id = self.session_id;
        let key = key.to_owned();
        let access = access.map(SandboxPathAccess::storage_str);
        self.db.write_blocking(move |conn| {
            // `INSERT OR REPLACE` on the (session_id, grant_kind, grant_key)
            // primary key flips an existing opposite verdict in place — a key
            // can never carry both polarities at session scope.
            conn.execute(
                "INSERT OR REPLACE INTO approval_grants \
                 (session_id, grant_kind, grant_key, granted_at, verdict, access) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![
                    session_id.to_string(),
                    kind.as_str(),
                    key,
                    now_epoch_seconds(),
                    verdict.as_str(),
                    access
                ],
            )
            .context("inserting session approval grant")?;
            Ok(())
        })
    }

    /// Remove a session-scope grant of `verdict` polarity for an exact
    /// `(kind, key)`. Used to clear the opposite polarity before writing.
    fn session_remove(&self, kind: GrantKind, key: &str, verdict: Verdict) -> Result<()> {
        let session_id = self.session_id;
        let key = key.to_owned();
        self.db.write_blocking(move |conn| {
            conn.execute(
                "DELETE FROM approval_grants \
                 WHERE session_id = ?1 AND grant_kind = ?2 AND grant_key = ?3 \
                   AND verdict = ?4",
                rusqlite::params![session_id.to_string(), kind.as_str(), key, verdict.as_str()],
            )
            .context("removing session approval grant")?;
            Ok(())
        })
    }

    // ---- project / global scope (JSON files) ------------------------------

    fn project_file(&self) -> Option<ApprovalsFile> {
        let dir = self.project_approvals_dir.as_ref()?;
        load_approvals(dir)
    }

    fn global_file(&self) -> Option<ApprovalsFile> {
        let dir = self.global_dir.as_ref()?;
        load_approvals(dir)
    }

    fn file_insert(
        &self,
        dir: &Path,
        kind: GrantKind,
        key: &str,
        verdict: Verdict,
        access: Option<SandboxPathAccess>,
    ) -> Result<()> {
        let mut file = load_approvals(dir).unwrap_or_default();
        // Clear the opposite polarity within this same file too, so one
        // `approvals.json` never lists a key in both an allow and a reject
        // set (belt-and-braces with `clear_key_everywhere`, which already
        // visited this scope — but this keeps `file_insert` self-consistent).
        verdict_remove(&mut file, kind, verdict.opposite(), key);
        verdict_insert(&mut file, kind, verdict, key, access);
        store_approvals(dir, &file)
    }

    /// Remove a grant of `verdict` polarity for an exact `key` from the
    /// `approvals.json` in `dir`. A missing file / missing key is a no-op
    /// (no write). Used to clear the opposite polarity before writing.
    fn file_remove(&self, dir: &Path, kind: GrantKind, key: &str, verdict: Verdict) -> Result<()> {
        let Some(mut file) = load_approvals(dir) else {
            return Ok(());
        };
        if verdict_remove(&mut file, kind, verdict, key) {
            store_approvals(dir, &file)?;
        }
        Ok(())
    }
}

fn verdict_insert(
    file: &mut ApprovalsFile,
    kind: GrantKind,
    verdict: Verdict,
    key: &str,
    access: Option<SandboxPathAccess>,
) {
    match (kind, verdict) {
        (GrantKind::Command, Verdict::Allow) => {
            file.commands.insert(key.to_string());
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
    }
}

fn verdict_remove(file: &mut ApprovalsFile, kind: GrantKind, verdict: Verdict, key: &str) -> bool {
    match (kind, verdict) {
        (GrantKind::Command, Verdict::Allow) => file.commands.remove(key),
        (GrantKind::Command, Verdict::Reject) => file.commands_reject.remove(key),
        (GrantKind::Path, Verdict::Allow) => file.paths.remove(key).is_some(),
        (GrantKind::Path, Verdict::Reject) => file.paths_reject.remove(key).is_some(),
    }
}

fn path_access_from_storage(value: Option<&str>) -> SandboxPathAccess {
    match value {
        Some("read") => SandboxPathAccess::Read,
        Some("read-write") => SandboxPathAccess::ReadWrite,
        _ => SandboxPathAccess::ReadWrite,
    }
}

fn paths_overlap(a: &str, b: &str) -> bool {
    path_covers(a, b) || path_covers(b, a)
}

/// `<global config dir>` for approvals. We prefer `~/.config/cockpit`
/// (XDG-canonical), the same home-scoped layer config discovery treats
/// as the user-level config root.
pub fn global_approvals_dir() -> Option<PathBuf> {
    dirs::home_dir().map(|home| home.join(".config/cockpit"))
}

/// Machine-local approvals dir for a project root. This is keyed through
/// the same hashed-cwd config directory used by the config layer, so the
/// persisted user decision never lives inside the repository.
pub fn project_approvals_dir(root: &Path) -> Option<PathBuf> {
    crate::config::dirs::local_config_dir_for(root).ok()
}

/// A management-UI grant kind: the four entry buckets a project/global
/// `approvals.json` carries. Unlike [`GrantKind`] (which only spans the
/// command/path grants the approval flow records), this also names the
/// two loop-guard buckets so the `/permissions` UI can list and delete
/// every persisted entry — not just commands and paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagedGrantKind {
    /// A command-key grant (`commands` set).
    Command,
    /// A path grant (`paths` set).
    Path,
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
            ManagedGrantKind::LoopAccept => "Loop always-accept",
            ManagedGrantKind::LoopReject => "Loop always-reject",
        }
    }
}

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

/// The four ordered grant buckets of one scope's `approvals.json`, each a
/// sorted list of entries. Produced by [`list_managed_grants`] for the
/// `/permissions` management UI; the order (commands, paths, accept,
/// reject) is the order the UI renders sections in.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ManagedGrants {
    pub commands: Vec<String>,
    pub paths: Vec<ManagedPathGrant>,
    pub loop_accept: Vec<String>,
    pub loop_reject: Vec<String>,
}

impl ManagedGrants {
    /// Whether the scope has no persisted grants of any kind — drives the
    /// pane's explicit empty-state per scope.
    pub fn is_empty(&self) -> bool {
        self.commands.is_empty()
            && self.paths.is_empty()
            && self.loop_accept.is_empty()
            && self.loop_reject.is_empty()
    }

    pub fn entry_count(&self, kind: ManagedGrantKind) -> usize {
        match kind {
            ManagedGrantKind::Command => self.commands.len(),
            ManagedGrantKind::Path => self.paths.len(),
            ManagedGrantKind::LoopAccept => self.loop_accept.len(),
            ManagedGrantKind::LoopReject => self.loop_reject.len(),
        }
    }
}

/// Read every persisted grant from the `approvals.json` in `dir` (the
/// machine-local project approvals dir or the global config dir). A missing or
/// unparseable file reads as no grants — the management UI shows an empty
/// scope, never an error. Entries come out sorted (the on-disk `BTreeSet`
/// ordering) so the listing is stable.
pub fn list_managed_grants(dir: &Path) -> ManagedGrants {
    let file = load_approvals(dir).unwrap_or_default();
    ManagedGrants {
        commands: file.commands.into_iter().collect(),
        paths: file
            .paths
            .into_iter()
            .map(|(key, access)| ManagedPathGrant { key, access })
            .collect(),
        loop_accept: file.loop_accept.into_iter().collect(),
        loop_reject: file.loop_reject.into_iter().collect(),
    }
}

/// Remove a single grant `key` of `kind` from the `approvals.json` in
/// `dir`, rewriting the file via the same load→mutate→atomic-store path
/// the approval store uses to *record* grants. Reloading first means a
/// concurrent edit to a different entry is preserved (we only drop the one
/// key, never clobber the whole file from a stale snapshot). Returns `true`
/// if the key was present and removed; `false` (no write) if it wasn't —
/// so a double-delete or a vanished entry is a harmless no-op. The change
/// takes effect on the next approval check, which re-reads the file.
pub fn delete_managed_grant(dir: &Path, kind: ManagedGrantKind, key: &str) -> Result<bool> {
    let mut file = load_approvals(dir).unwrap_or_default();
    let removed = match kind {
        ManagedGrantKind::Command => file.commands.remove(key),
        ManagedGrantKind::Path => file.paths.remove(key).is_some(),
        ManagedGrantKind::LoopAccept => file.loop_accept.remove(key),
        ManagedGrantKind::LoopReject => file.loop_reject.remove(key),
    };
    if !removed {
        return Ok(false);
    }
    store_approvals(dir, &file)?;
    Ok(true)
}

/// File name for the per-scope approvals store inside an approvals dir.
const APPROVALS_FILE: &str = "approvals.json";

fn load_approvals(dir: &Path) -> Option<ApprovalsFile> {
    let path = dir.join(APPROVALS_FILE);
    let bytes = std::fs::read(&path).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Write `file` to `<dir>/approvals.json` atomically (temp + rename) so a
/// crash mid-write can't corrupt the store. Creates `dir` if needed.
fn store_approvals(dir: &Path, file: &ApprovalsFile) -> Result<()> {
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let path = dir.join(APPROVALS_FILE);
    let tmp = dir.join(format!("{APPROVALS_FILE}.tmp"));
    let json = serde_json::to_vec_pretty(file).context("serializing approvals")?;
    std::fs::write(&tmp, &json).with_context(|| format!("writing {}", tmp.display()))?;
    std::fs::rename(&tmp, &path).with_context(|| format!("renaming into {}", path.display()))?;
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
    use crate::approval::classify::SimpleCommandInfo;

    fn cmd_info(program: &str, sub: Option<&str>, wrapper: bool) -> SimpleCommandInfo {
        let key = ApprovalKey {
            program: program.to_string(),
            subcommand: sub.map(str::to_string),
        };
        SimpleCommandInfo {
            program: program.to_string(),
            normalized_program: program.to_string(),
            subcommand: sub.map(str::to_string),
            key,
            wrapper,
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
    fn test_store(project: &Path, global: PathBuf) -> (GrantStore, uuid::Uuid) {
        let db = Db::open_in_memory().unwrap();
        let session =
            crate::session::Session::create(db.clone(), project.to_path_buf(), "builder").unwrap();
        let sid = session.id;
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
        (store, sid)
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

    #[test]
    fn session_grant_then_granted() {
        let tmp = tempfile::tempdir().unwrap();
        let global = tempfile::tempdir().unwrap();
        let (store, _) = test_store(tmp.path(), global.path().to_path_buf());
        let info = cmd_info("gh", Some("pr"), false);
        assert!(!store.is_command_granted(&info.key));
        store.record_command(&info, Scope::Session).unwrap();
        assert!(store.is_command_granted(&info.key));
        // A different subcommand still prompts.
        let other = cmd_info("gh", Some("repo"), false);
        assert!(!store.is_command_granted(&other.key));
    }

    #[test]
    fn project_grant_covers_subcommand_args_and_persists() {
        let tmp = tempfile::tempdir().unwrap();
        let global = tempfile::tempdir().unwrap();
        let (store, sid) = test_store(tmp.path(), global.path().to_path_buf());
        let info = cmd_info("gh", Some("pr"), false);
        store.record_command(&info, Scope::Project).unwrap();

        // `gh pr create ...` derives the same key → granted, no prompt.
        let create = cmd_info("gh", Some("pr"), false);
        assert!(store.is_command_granted(&create.key));
        // `gh repo ...` is a different key → still prompts.
        let repo = cmd_info("gh", Some("repo"), false);
        assert!(!store.is_command_granted(&repo.key));

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
        assert!(reloaded.is_command_granted(&info.key));
    }

    #[test]
    fn project_grant_writes_machine_local_not_repo() {
        let env = tempfile::tempdir().unwrap();
        let _home = crate::config::dirs::test_support::IsolatedCockpitHome::new(env.path());
        let project = tempfile::tempdir_in(env.path()).unwrap();
        let status = std::process::Command::new("git")
            .args(["init", "-q"])
            .current_dir(project.path())
            .status()
            .unwrap();
        assert!(status.success());
        crate::config::trust::clear_runtime_policy_for_tests();

        let db = Db::open_in_memory().unwrap();
        let session =
            crate::session::Session::create(db.clone(), project.path().to_path_buf(), "builder")
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
        store.record_command(&info, Scope::Project).unwrap();

        assert!(project_dir.join(APPROVALS_FILE).exists());
        assert!(!project.path().join(".cockpit/approvals.json").exists());
        assert!(!project_dir.starts_with(project.path()));
        crate::config::trust::clear_runtime_policy_for_tests();
    }

    #[test]
    fn repo_side_project_approvals_file_is_ignored_even_when_trusted() {
        let tmp = tempfile::tempdir().unwrap();
        let global = tempfile::tempdir().unwrap();
        let (store, _) = test_store(tmp.path(), global.path().to_path_buf());
        let repo_dir = tmp.path().join(".cockpit");
        let command = cmd_info("cargo", Some("test"), false);
        let granted_dir = tmp.path().join("secrets");
        store_approvals(
            &repo_dir,
            &ApprovalsFile {
                commands: BTreeSet::from([command.key.as_storage_str()]),
                paths: BTreeMap::from([(
                    normalize_path(&granted_dir, store.cwd()),
                    SandboxPathAccess::ReadWrite,
                )]),
                ..ApprovalsFile::default()
            },
        )
        .unwrap();

        assert!(!crate::approval::command_grant_allowed_by_policy(
            &store, &command
        ));
        assert!(!store.is_path_granted(&granted_dir.join("token.txt")));
        assert!(!test_project_dir(&store).join(APPROVALS_FILE).exists());
    }

    #[test]
    fn global_grant_persists_and_applies() {
        let tmp = tempfile::tempdir().unwrap();
        let global = tempfile::tempdir().unwrap();
        let (store, _) = test_store(tmp.path(), global.path().to_path_buf());
        let info = cmd_info("cargo", Some("build"), false);
        store.record_command(&info, Scope::Global).unwrap();

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
        assert!(elsewhere.is_command_granted(&info.key));
    }

    #[test]
    fn ignore_cfg_blocks_project_approval_file_reads_and_writes() {
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
        store_approvals(
            &project_dir,
            &ApprovalsFile {
                commands: BTreeSet::from(["cargo test".to_string()]),
                ..ApprovalsFile::default()
            },
        )
        .unwrap();

        let db = Db::open_in_memory().unwrap();
        let session =
            crate::session::Session::create(db.clone(), tmp.path().to_path_buf(), "builder")
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

        assert!(!store.is_command_granted(&info.key));
        assert!(matches!(
            store.record_command(&info, Scope::Project),
            Err(StoreError::NoProjectRoot)
        ));
        store.record_command(&info, Scope::Session).unwrap();
        assert!(store.is_command_granted(&info.key));
        crate::config::trust::clear_runtime_policy_for_tests();
    }

    #[test]
    fn wrapper_rejected_at_every_non_once_scope() {
        let tmp = tempfile::tempdir().unwrap();
        let global = tempfile::tempdir().unwrap();
        let (store, _) = test_store(tmp.path(), global.path().to_path_buf());
        let wrapper = cmd_info("bash", None, true);
        for scope in [Scope::Session, Scope::Project, Scope::Global] {
            let err = store.record_command(&wrapper, scope).unwrap_err();
            assert!(
                matches!(err, StoreError::WrapperNotPersistable(_)),
                "scope {scope:?} should reject wrapper, got {err:?}"
            );
        }
        // And nothing was written.
        assert!(!store.is_command_granted(&wrapper.key));
    }

    #[test]
    fn once_scope_is_never_recorded() {
        let tmp = tempfile::tempdir().unwrap();
        let global = tempfile::tempdir().unwrap();
        let (store, _) = test_store(tmp.path(), global.path().to_path_buf());
        let info = cmd_info("ls", None, false);
        assert!(matches!(
            store.record_command(&info, Scope::Once),
            Err(StoreError::OnceNotPersistable)
        ));
        assert!(!store.is_command_granted(&info.key));
    }

    #[test]
    fn path_grant_prefix_match() {
        let tmp = tempfile::tempdir().unwrap();
        let global = tempfile::tempdir().unwrap();
        let (store, _) = test_store(tmp.path(), global.path().to_path_buf());
        let dir = tmp.path().join("src");
        store
            .record_path(&dir, Scope::Project, SandboxPathAccess::ReadWrite)
            .unwrap();
        // A file under the granted dir is covered.
        assert!(store.is_path_granted(&dir.join("main.rs")));
        // A sibling that shares a string prefix but not a path prefix is
        // NOT covered.
        let sibling = tmp.path().join("src-gen").join("x.rs");
        assert!(!store.is_path_granted(&sibling));
    }

    #[test]
    fn path_grant_session_scope() {
        let tmp = tempfile::tempdir().unwrap();
        let global = tempfile::tempdir().unwrap();
        let (store, _) = test_store(tmp.path(), global.path().to_path_buf());
        let file = tmp.path().join("a/b/c.txt");
        assert!(!store.is_path_granted(&file));
        store
            .record_path(&file, Scope::Session, SandboxPathAccess::ReadWrite)
            .unwrap();
        assert!(store.is_path_granted(&file));
    }

    #[test]
    fn path_grant_modes_round_trip_at_each_scope() {
        for scope in [Scope::Session, Scope::Project, Scope::Global] {
            let tmp = tempfile::tempdir().unwrap();
            let global = tempfile::tempdir().unwrap();
            let (store, _) = test_store(tmp.path(), global.path().to_path_buf());
            let dir = tmp.path().join(format!("mode-{scope:?}"));
            store
                .record_path(&dir, scope, SandboxPathAccess::Read)
                .unwrap();
            assert!(store.is_path_granted_for(&dir.join("file.txt"), SandboxPathAccess::Read));
            assert!(
                !store.is_path_granted_for(&dir.join("file.txt"), SandboxPathAccess::ReadWrite),
                "read grant must not satisfy read-write at {scope:?}"
            );

            match scope {
                Scope::Session => {
                    let access: String = store
                        .db
                        .read_blocking(|conn| {
                            Ok(conn.query_row(
                                "SELECT access FROM approval_grants \
                                 WHERE session_id = ?1 AND grant_kind = 'path' AND grant_key = ?2",
                                rusqlite::params![
                                    store.session_id.to_string(),
                                    normalize_path(&dir, store.cwd())
                                ],
                                |row| row.get(0),
                            )?)
                        })
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

    #[test]
    fn effective_path_grants_use_strongest_access_and_filter_rejects() {
        let tmp = tempfile::tempdir().unwrap();
        let global = tempfile::tempdir().unwrap();
        let (store, _) = test_store(tmp.path(), global.path().to_path_buf());
        let read_dir = tmp.path().join("read-only");
        let rw_dir = tmp.path().join("read-write");
        let rejected_dir = tmp.path().join("rejected");

        store
            .record_path(&read_dir, Scope::Session, SandboxPathAccess::Read)
            .unwrap();
        store
            .record_path(&read_dir, Scope::Project, SandboxPathAccess::ReadWrite)
            .unwrap();
        store
            .record_path(&rw_dir, Scope::Global, SandboxPathAccess::ReadWrite)
            .unwrap();
        store
            .record_path(&rejected_dir, Scope::Project, SandboxPathAccess::ReadWrite)
            .unwrap();
        store
            .record_path_reject(&rejected_dir, Scope::Session)
            .unwrap();

        let grants = store.effective_path_grants();
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

    #[test]
    fn approval_timestamp_columns_are_integer() {
        let db = Db::open_in_memory().unwrap();
        db.read_blocking(|conn| {
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
        .unwrap();
    }

    #[test]
    fn session_approval_records_epoch_integer_timestamp() {
        let tmp = tempfile::tempdir().unwrap();
        let global = tempfile::tempdir().unwrap();
        let (store, _) = test_store(tmp.path(), global.path().to_path_buf());
        let before = now_epoch_seconds();

        store
            .record_command(&cmd_info("grep", None, false), Scope::Session)
            .unwrap();

        let (value, sqlite_type): (i64, String) = store
            .db
            .read_blocking(|conn| {
                conn.query_row(
                    "SELECT granted_at, typeof(granted_at) FROM approval_grants \
                     WHERE session_id = ?1 AND grant_kind = 'command' AND grant_key = 'grep'",
                    [store.session_id.to_string()],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .map_err(Into::into)
            })
            .unwrap();
        let after = now_epoch_seconds();

        assert_eq!(sqlite_type, "integer");
        assert!((before..=after).contains(&value));
    }

    #[test]
    fn loop_rule_records_epoch_integer_timestamp() {
        let tmp = tempfile::tempdir().unwrap();
        let global = tempfile::tempdir().unwrap();
        let (store, _) = test_store(tmp.path(), global.path().to_path_buf());
        let signature = GrantStore::loop_signature("read", &serde_json::json!({"path": "x"}));
        let before = now_epoch_seconds();

        store
            .record_loop_rule(&signature, LoopVerdict::Accept, Scope::Session)
            .unwrap();

        let (value, sqlite_type): (i64, String) = store
            .db
            .read_blocking(|conn| {
                conn.query_row(
                    "SELECT recorded_at, typeof(recorded_at) FROM loop_guard_rules \
                     WHERE session_id = ?1 AND signature = ?2",
                    rusqlite::params![store.session_id.to_string(), signature],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .map_err(Into::into)
            })
            .unwrap();
        let after = now_epoch_seconds();

        assert_eq!(sqlite_type, "integer");
        assert!((before..=after).contains(&value));
    }

    #[test]
    fn relative_path_grants_use_store_cwd_not_process_cwd() {
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
            .unwrap();

        assert!(store.is_path_granted(Path::new("src/main.rs")));
        assert!(!store.is_path_granted(&unrelated_daemon_cwd.path().join("src/main.rs")));
    }

    #[test]
    fn normalize_path_uses_explicit_base_for_relative_paths() {
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

    #[test]
    fn normalize_path_keeps_absolute_paths_and_lexical_parent_resolution() {
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
    #[test]
    fn command_reject_at_each_scope() {
        for scope in [Scope::Session, Scope::Project, Scope::Global] {
            let tmp = tempfile::tempdir().unwrap();
            let global = tempfile::tempdir().unwrap();
            let (store, sid) = test_store(tmp.path(), global.path().to_path_buf());
            let info = cmd_info("gh", Some("pr"), false);
            assert!(!store.is_command_rejected(&info.key));
            store.record_command_reject(&info, scope).unwrap();
            assert!(store.is_command_rejected(&info.key), "scope {scope:?}");
            // A reject is not an allow.
            assert!(!store.is_command_granted(&info.key), "scope {scope:?}");

            // Reload (fresh store over the same DB + dirs) still sees it.
            let mut reloaded = GrantStore::new(
                store.db.clone(),
                sid,
                tmp.path().to_path_buf(),
                SessionConfigHandle::from_disk_for_tests(tmp.path()),
            );
            point_project_scope(&mut reloaded, tmp.path(), global.path());
            reloaded.global_dir = Some(global.path().to_path_buf());
            assert!(reloaded.is_command_rejected(&info.key), "reload {scope:?}");
        }
    }

    /// A path reject persists and is seen by `is_path_rejected` (prefix
    /// semantics, same as allow) at each non-`Once` scope.
    #[test]
    fn path_reject_at_each_scope() {
        for scope in [Scope::Session, Scope::Project, Scope::Global] {
            let tmp = tempfile::tempdir().unwrap();
            let global = tempfile::tempdir().unwrap();
            let (store, _) = test_store(tmp.path(), global.path().to_path_buf());
            let dir = tmp.path().join("secret");
            assert!(!store.is_path_rejected(&dir.join("k.txt")));
            store.record_path_reject(&dir, scope).unwrap();
            // A file under the rejected dir is covered (prefix match).
            assert!(
                store.is_path_rejected(&dir.join("k.txt")),
                "scope {scope:?}"
            );
            assert!(
                !store.is_path_granted(&dir.join("k.txt")),
                "scope {scope:?}"
            );
        }
    }

    /// Recording a reject for a key first removes any allow grant for that key
    /// at every reachable scope, and vice-versa — a key is never simultaneously
    /// allowed and rejected after any record call (no-coexistence invariant).
    #[test]
    fn reject_and_allow_never_coexist_both_directions() {
        let tmp = tempfile::tempdir().unwrap();
        let global = tempfile::tempdir().unwrap();
        let (store, _) = test_store(tmp.path(), global.path().to_path_buf());
        let info = cmd_info("gh", Some("pr"), false);

        // Allow at project + global, then reject at session: the session
        // reject must clear BOTH the project and the global allow.
        store.record_command(&info, Scope::Project).unwrap();
        store.record_command(&info, Scope::Global).unwrap();
        assert!(store.is_command_granted(&info.key));
        store.record_command_reject(&info, Scope::Session).unwrap();
        assert!(store.is_command_rejected(&info.key));
        assert!(
            !store.is_command_granted(&info.key),
            "reject cleared every reachable allow"
        );

        // Now allow again at project: the allow must clear the session reject.
        store.record_command(&info, Scope::Project).unwrap();
        assert!(store.is_command_granted(&info.key));
        assert!(
            !store.is_command_rejected(&info.key),
            "allow cleared the standing reject"
        );
    }

    /// The same no-coexistence invariant for path grants.
    #[test]
    fn path_reject_and_allow_never_coexist() {
        let tmp = tempfile::tempdir().unwrap();
        let global = tempfile::tempdir().unwrap();
        let (store, _) = test_store(tmp.path(), global.path().to_path_buf());
        let dir = tmp.path().join("data");

        store
            .record_path(&dir, Scope::Project, SandboxPathAccess::ReadWrite)
            .unwrap();
        assert!(store.is_path_granted(&dir.join("x")));
        store.record_path_reject(&dir, Scope::Session).unwrap();
        assert!(store.is_path_rejected(&dir.join("x")));
        assert!(
            !store.is_path_granted(&dir.join("x")),
            "reject cleared allow"
        );

        store
            .record_path(&dir, Scope::Global, SandboxPathAccess::ReadWrite)
            .unwrap();
        assert!(store.is_path_granted(&dir.join("x")));
        assert!(
            !store.is_path_rejected(&dir.join("x")),
            "allow cleared reject"
        );
    }

    /// `Once` is never persisted in either polarity, and a wrapper command can
    /// never be rejected at a persistent scope — identical to the allow rules.
    #[test]
    fn reject_once_and_wrapper_rules() {
        let tmp = tempfile::tempdir().unwrap();
        let global = tempfile::tempdir().unwrap();
        let (store, _) = test_store(tmp.path(), global.path().to_path_buf());

        // Once → OnceNotPersistable; nothing recorded.
        let info = cmd_info("ls", None, false);
        assert!(matches!(
            store.record_command_reject(&info, Scope::Once),
            Err(StoreError::OnceNotPersistable)
        ));
        assert!(!store.is_command_rejected(&info.key));

        // Wrapper → WrapperNotPersistable at every non-Once scope.
        let wrapper = cmd_info("bash", None, true);
        for scope in [Scope::Session, Scope::Project, Scope::Global] {
            assert!(matches!(
                store.record_command_reject(&wrapper, scope),
                Err(StoreError::WrapperNotPersistable(_))
            ));
        }
        assert!(!store.is_command_rejected(&wrapper.key));

        // Path reject Once is also never persisted.
        let p = tmp.path().join("p");
        assert!(matches!(
            store.record_path_reject(&p, Scope::Once),
            Err(StoreError::OnceNotPersistable)
        ));
        assert!(!store.is_path_rejected(&p));
    }

    /// Pre-existing `approval_grants` rows (written before the `verdict`
    /// column) read as allows after the migration backfills `verdict='allow'`.
    #[test]
    fn pre_migration_rows_read_as_allows() {
        let tmp = tempfile::tempdir().unwrap();
        let global = tempfile::tempdir().unwrap();
        let (store, _) = test_store(tmp.path(), global.path().to_path_buf());
        let info = cmd_info("cargo", Some("test"), false);
        let key = info.key.as_storage_str();
        // Simulate a legacy row for the verdict column: insert WITHOUT
        // `verdict` so the migration's column default (`'allow'`) supplies it.
        store
            .db
            .write_blocking(move |conn| {
                conn.execute(
                    "INSERT INTO approval_grants \
                     (session_id, grant_kind, grant_key, granted_at) \
                     VALUES (?1, 'command', ?2, ?3)",
                    rusqlite::params![store.session_id.to_string(), key, 1_700_000_000_i64],
                )?;
                Ok(())
            })
            .unwrap();
        assert!(
            store.is_command_granted(&info.key),
            "legacy row reads as allow"
        );
        assert!(!store.is_command_rejected(&info.key));
    }

    #[test]
    fn unparseable_or_empty_keys_are_just_not_granted() {
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
        };
        assert!(!store.is_command_granted(&unknown));
    }

    // ---- loop-guard rules ------------------------------------------------

    #[test]
    fn loop_signature_keys_on_tool_and_wire_input() {
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

    #[test]
    fn loop_signature_is_object_key_order_independent() {
        use serde_json::json;
        // The model may emit object keys in any order; semantically
        // identical inputs must share a signature.
        let a = GrantStore::loop_signature("edit", &json!({"path": "a", "old": "x", "new": "y"}));
        let b = GrantStore::loop_signature("edit", &json!({"new": "y", "path": "a", "old": "x"}));
        assert_eq!(a, b);
    }

    #[test]
    fn loop_rule_session_record_and_read_round_trip() {
        let tmp = tempfile::tempdir().unwrap();
        let global = tempfile::tempdir().unwrap();
        let (store, _) = test_store(tmp.path(), global.path().to_path_buf());
        let sig = GrantStore::loop_signature("read", &serde_json::json!({"path": "x"}));
        assert!(store.loop_rule(&sig).is_none());
        store
            .record_loop_rule(&sig, LoopVerdict::Reject, Scope::Session)
            .unwrap();
        assert_eq!(store.loop_rule(&sig), Some(LoopVerdict::Reject));
        // Recording the opposite verdict at the same scope flips it (no
        // contradictory pair persists).
        store
            .record_loop_rule(&sig, LoopVerdict::Accept, Scope::Session)
            .unwrap();
        assert_eq!(store.loop_rule(&sig), Some(LoopVerdict::Accept));
    }

    #[test]
    fn loop_rule_project_persists_across_sessions() {
        let tmp = tempfile::tempdir().unwrap();
        let global = tempfile::tempdir().unwrap();
        let (store, sid) = test_store(tmp.path(), global.path().to_path_buf());
        let sig = GrantStore::loop_signature("bash", &serde_json::json!({"command": "ls"}));
        store
            .record_loop_rule(&sig, LoopVerdict::Accept, Scope::Project)
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
        assert_eq!(reloaded.loop_rule(&sig), Some(LoopVerdict::Accept));
    }

    #[test]
    fn loop_rule_session_takes_precedence_over_project() {
        // A session rule and a project rule for the SAME signature resolve
        // to the session verdict (documented precedence: session > project
        // > global).
        let tmp = tempfile::tempdir().unwrap();
        let global = tempfile::tempdir().unwrap();
        let (store, _) = test_store(tmp.path(), global.path().to_path_buf());
        let sig = GrantStore::loop_signature("read", &serde_json::json!({"path": "z"}));
        store
            .record_loop_rule(&sig, LoopVerdict::Accept, Scope::Project)
            .unwrap();
        store
            .record_loop_rule(&sig, LoopVerdict::Reject, Scope::Session)
            .unwrap();
        // Session (reject) wins over project (accept).
        assert_eq!(store.loop_rule(&sig), Some(LoopVerdict::Reject));
    }

    #[test]
    fn loop_rule_project_takes_precedence_over_global() {
        let tmp = tempfile::tempdir().unwrap();
        let global = tempfile::tempdir().unwrap();
        let (store, _) = test_store(tmp.path(), global.path().to_path_buf());
        let sig = GrantStore::loop_signature("read", &serde_json::json!({"path": "q"}));
        store
            .record_loop_rule(&sig, LoopVerdict::Reject, Scope::Global)
            .unwrap();
        store
            .record_loop_rule(&sig, LoopVerdict::Accept, Scope::Project)
            .unwrap();
        // Project (accept) wins over global (reject).
        assert_eq!(store.loop_rule(&sig), Some(LoopVerdict::Accept));
    }

    #[test]
    fn loop_rule_once_scope_is_never_persisted() {
        let tmp = tempfile::tempdir().unwrap();
        let global = tempfile::tempdir().unwrap();
        let (store, _) = test_store(tmp.path(), global.path().to_path_buf());
        let sig = GrantStore::loop_signature("read", &serde_json::json!({"path": "x"}));
        assert!(matches!(
            store.record_loop_rule(&sig, LoopVerdict::Accept, Scope::Once),
            Err(StoreError::OnceNotPersistable)
        ));
        assert!(store.loop_rule(&sig).is_none());
    }

    // ---- management API (`/permissions`) ---------------------------------

    #[test]
    fn list_managed_grants_groups_by_kind_and_sorts() {
        let dir = tempfile::tempdir().unwrap();
        // Seed one of each bucket through the normal store write paths so
        // the file shape is exactly what production records.
        let db = Db::open_in_memory().unwrap();
        let session =
            crate::session::Session::create(db.clone(), dir.path().to_path_buf(), "builder")
                .unwrap();
        let mut store = GrantStore::new(
            db,
            session.id,
            dir.path().to_path_buf(),
            SessionConfigHandle::from_disk_for_tests(dir.path()),
        );
        point_project_scope(&mut store, dir.path(), dir.path());
        store
            .record_command(&cmd_info("gh", Some("pr"), false), Scope::Project)
            .unwrap();
        store
            .record_command(&cmd_info("cargo", Some("build"), false), Scope::Project)
            .unwrap();
        store
            .record_path(
                &dir.path().join("src"),
                Scope::Project,
                SandboxPathAccess::ReadWrite,
            )
            .unwrap();
        let sig = GrantStore::loop_signature("read", &serde_json::json!({"path": "x"}));
        store
            .record_loop_rule(&sig, LoopVerdict::Accept, Scope::Project)
            .unwrap();

        let grants = list_managed_grants(test_project_dir(&store));
        // Commands are sorted; both present.
        assert_eq!(
            grants.commands,
            vec!["cargo build".to_string(), "gh pr".to_string()]
        );
        assert_eq!(grants.paths.len(), 1);
        assert_eq!(grants.loop_accept, vec![sig]);
        assert!(grants.loop_reject.is_empty());
        assert!(!grants.is_empty());
    }

    #[test]
    fn list_managed_grants_missing_file_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let grants = list_managed_grants(dir.path());
        assert!(grants.is_empty(), "no approvals.json → empty, not an error");
    }

    #[test]
    fn delete_managed_grant_removes_one_leaves_others() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open_in_memory().unwrap();
        let session =
            crate::session::Session::create(db.clone(), dir.path().to_path_buf(), "builder")
                .unwrap();
        let mut store = GrantStore::new(
            db,
            session.id,
            dir.path().to_path_buf(),
            SessionConfigHandle::from_disk_for_tests(dir.path()),
        );
        point_project_scope(&mut store, dir.path(), dir.path());
        store
            .record_command(&cmd_info("gh", Some("pr"), false), Scope::Project)
            .unwrap();
        store
            .record_command(&cmd_info("cargo", Some("build"), false), Scope::Project)
            .unwrap();
        let project_dir = test_project_dir(&store).to_path_buf();

        // Deleting one command leaves the other intact.
        assert!(delete_managed_grant(&project_dir, ManagedGrantKind::Command, "gh pr").unwrap());
        let grants = list_managed_grants(&project_dir);
        assert_eq!(grants.commands, vec!["cargo build".to_string()]);

        // The removal is durable: a fresh store no longer treats it as granted.
        assert!(!store.is_command_granted(&ApprovalKey {
            program: "gh".into(),
            subcommand: Some("pr".into()),
        }));
        assert!(store.is_command_granted(&ApprovalKey {
            program: "cargo".into(),
            subcommand: Some("build".into()),
        }));
    }

    #[test]
    fn delete_managed_grant_handles_each_kind() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open_in_memory().unwrap();
        let session =
            crate::session::Session::create(db.clone(), dir.path().to_path_buf(), "builder")
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
            .unwrap();
        let acc = GrantStore::loop_signature("read", &serde_json::json!({"p": 1}));
        let rej = GrantStore::loop_signature("bash", &serde_json::json!({"c": "x"}));
        store
            .record_loop_rule(&acc, LoopVerdict::Accept, Scope::Project)
            .unwrap();
        store
            .record_loop_rule(&rej, LoopVerdict::Reject, Scope::Project)
            .unwrap();

        let project_dir = test_project_dir(&store).to_path_buf();
        let path_key = list_managed_grants(&project_dir).paths[0].key.clone();
        assert!(delete_managed_grant(&project_dir, ManagedGrantKind::Path, &path_key).unwrap());
        assert!(delete_managed_grant(&project_dir, ManagedGrantKind::LoopAccept, &acc).unwrap());
        assert!(delete_managed_grant(&project_dir, ManagedGrantKind::LoopReject, &rej).unwrap());
        assert!(list_managed_grants(&project_dir).is_empty());
    }

    #[test]
    fn delete_managed_grant_absent_key_is_noop() {
        let dir = tempfile::tempdir().unwrap();
        // No file at all: deleting an absent key returns false, writes nothing.
        assert!(!delete_managed_grant(dir.path(), ManagedGrantKind::Command, "nope").unwrap());
        assert!(!dir.path().join(APPROVALS_FILE).exists());
    }

    #[test]
    fn loop_rule_keys_on_exact_signature_not_tool_name() {
        // A rule for one call must NOT cover a different call of the same
        // tool with different args.
        let tmp = tempfile::tempdir().unwrap();
        let global = tempfile::tempdir().unwrap();
        let (store, _) = test_store(tmp.path(), global.path().to_path_buf());
        let sig_a = GrantStore::loop_signature("read", &serde_json::json!({"path": "a"}));
        let sig_b = GrantStore::loop_signature("read", &serde_json::json!({"path": "b"}));
        store
            .record_loop_rule(&sig_a, LoopVerdict::Accept, Scope::Session)
            .unwrap();
        assert_eq!(store.loop_rule(&sig_a), Some(LoopVerdict::Accept));
        assert!(store.loop_rule(&sig_b).is_none());
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
        let mut extended = crate::config::extended::ExtendedConfig::default();
        extended.approval_policy = policy;
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
        let session =
            crate::session::Session::create(db.clone(), tmp.to_path_buf(), "builder").unwrap();
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

    /// A1: a policy change during a live session is observed by the store
    /// without rebuilding it.
    #[test]
    fn grant_store_observes_policy_change_without_rebuild() {
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
    #[test]
    fn approval_policy_accessor_does_no_disk_read() {
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
    #[test]
    fn grant_store_policy_resolution_is_trust_aware() {
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
    #[test]
    fn policy_change_does_not_affect_inflight_decision() {
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
    #[test]
    fn invalid_policy_keeps_last_good_and_does_not_fall_open() {
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

    /// A6: grant-file behavior is unchanged — a direct file deletion (as the
    /// permissions pane performs) still propagates to the same live store on
    /// its next check, because grant files are re-read per check.
    #[test]
    fn grant_file_changes_still_propagate() {
        let tmp = tempfile::tempdir().unwrap();
        let global = tempfile::tempdir().unwrap();
        let (store, _) = test_store(tmp.path(), global.path().to_path_buf());
        let info = cmd_info("gh", Some("pr"), false);
        store.record_command(&info, Scope::Project).unwrap();
        assert!(store.is_command_granted(&info.key));

        // Delete the grant straight from the file, as the permissions pane does.
        let dir = test_project_dir(&store).to_path_buf();
        assert!(delete_managed_grant(&dir, ManagedGrantKind::Command, "gh pr").unwrap());

        // The same store sees the deletion on its next check (no rebuild).
        assert!(!store.is_command_granted(&info.key));
    }

    /// A7: approval outcomes are unchanged for a static policy. A Session-scope
    /// grant of an ordinary command is within the default cap (Global) and is
    /// allowed without a prompt; repeated policy reads are stable.
    #[test]
    fn approval_outcomes_unchanged_for_static_policy() {
        let tmp = tempfile::tempdir().unwrap();
        let global = tempfile::tempdir().unwrap();
        let (store, _) = test_store(tmp.path(), global.path().to_path_buf());
        let info = cmd_info("gh", Some("pr"), false);

        assert!(!crate::approval::command_grant_allowed_by_policy(
            &store, &info
        ));
        store.record_command(&info, Scope::Session).unwrap();
        assert!(crate::approval::command_grant_allowed_by_policy(
            &store, &info
        ));

        // The static policy resolves to the same value on every read.
        assert_eq!(store.approval_policy(), store.approval_policy());
    }
}
