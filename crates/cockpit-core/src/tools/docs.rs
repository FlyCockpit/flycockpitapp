//! Docs-pipeline-only tools: `list-packages` and `add-package`
//! (prompt `docs-agent.md` component C, Docs.1 resolver surface).
//!
//! These are assigned exclusively to the Docs.1 *resolver* stage. Their
//! job is to get a dependency's source into cockpit's package registry
//! (cloning it shallowly from registry-declared metadata if absent —
//! decision 4) so the pipeline can launch Docs.2 in the resolved package
//! directory.
//!
//! Resolution side-channel: both tools record the resolved on-disk path
//! into a shared [`DocsResolution`] the pipeline owns. The pipeline reads
//! it after Docs.1 finishes to decide whether to launch Docs.2 — this is
//! deterministic, not a parse of the model's free text (priority #1:
//! defensive against weak models).

use std::sync::{Arc, Mutex};

use anyhow::Result;
use async_trait::async_trait;
use serde_json::Value;

use crate::db::packages::SourceType;
use crate::engine::tool::{Tool, ToolCtx, ToolOutput, invalid_input};
use crate::packages::resolve::{RepoResolution, resolve_repo_url};
use crate::packages::{self, Ecosystem};

/// Shared resolution slot threaded into the Docs.1 tools and read back by
/// the pipeline. Records the on-disk path of the package the resolver
/// confirmed/cloned, plus its identifier for the citation header.
#[derive(Default)]
pub struct DocsResolution {
    inner: Mutex<Option<Resolved>>,
}

#[derive(Clone)]
pub struct Resolved {
    pub identifier: String,
    pub path: std::path::PathBuf,
}

impl DocsResolution {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    fn record(&self, identifier: &str, path: &std::path::Path) {
        *self.inner.lock().expect("docs resolution mutex") = Some(Resolved {
            identifier: identifier.to_string(),
            path: path.to_path_buf(),
        });
    }

    /// The resolved package, if Docs.1 located one with a path that
    /// still exists on disk (an imported kcl clone may have been
    /// removed — tolerate that cleanly per the edge-case spec).
    pub fn take(&self) -> Option<Resolved> {
        let resolved = self.inner.lock().expect("docs resolution mutex").clone();
        resolved.filter(|r| r.path.is_dir())
    }
}

/// `list-packages` — list every registered package so the resolver can
/// see whether the dependency it needs is already present.
pub struct ListPackagesTool {
    resolution: Arc<DocsResolution>,
    /// The package the pipeline asked Docs.1 to resolve. Listing a match
    /// for it records the resolution side-channel.
    target: String,
}

impl ListPackagesTool {
    pub fn new(resolution: Arc<DocsResolution>, target: String) -> Self {
        Self { resolution, target }
    }
}

#[async_trait]
impl Tool for ListPackagesTool {
    fn name(&self) -> &str {
        "list-packages"
    }

    fn description(&self) -> &str {
        "List registered dependency packages available to the docs answerer"
    }

    fn defensive_description(&self) -> Option<String> {
        Some(
            "List the dependency packages already registered (source cloned locally) and \
             available to answer questions about. Call this FIRST: if the package you need is \
             already listed, it's ready to use and you don't need to clone it again. Only when \
             the package is missing from this list should you register it with `add-package`. \
             Takes no arguments."
                .to_string(),
        )
    }

    fn parameters(&self) -> Value {
        serde_json::json!({ "type": "object", "properties": {} })
    }

    fn defensive_parameters(&self) -> Option<Value> {
        Some(serde_json::json!({ "type": "object", "properties": {} }))
    }

    async fn call(&self, _args: Value, ctx: &ToolCtx) -> Result<ToolOutput> {
        let packages = ctx.session.db.list_packages()?;
        if packages.is_empty() {
            return Ok(ToolOutput::text(
                "No packages registered. Use add-package to clone the dependency's source."
                    .to_string(),
            ));
        }
        let mut out = String::new();
        for p in &packages {
            // If a registered package matches the requested target,
            // record it as resolved so the pipeline can proceed without
            // a clone.
            if identifier_matches(&p.identifier, &self.target) {
                self.resolution
                    .record(&p.identifier, std::path::Path::new(&p.path));
            }
            out.push_str(&format!("{}  [{}]\n", p.identifier, p.source_type.as_str()));
        }
        Ok(ToolOutput::text(out))
    }
}

/// `add-package` — register a dependency by cloning its source from a
/// registry-declared repo (decision 4: never a guessed URL). Resolves
/// the repo from crates.io / npm / PyPI metadata for the named
/// ecosystem; refuses to clone when no source repo is declared.
///
/// Cloning a NEW package is gated behind explicit user approval
/// (implementation note): the gate fires only when a
/// clone would actually happen — after the repo URL is resolved from
/// official registry metadata (so the URL + rationale shown are grounded,
/// never fabricated) and before the clone — and never for a package that's
/// already registered. The `approver` + `interrupts` are threaded straight
/// into the tool (independent of the noninteractive `ToolCtx::approver`,
/// which the docs pipeline leaves `None` so the filesystem-confine path
/// raises no escalation). Both `None` (a context with no interactive
/// client) → no clone, with a clear refusal rather than a silent failure.
pub struct AddPackageTool {
    resolution: Arc<DocsResolution>,
    approver: Option<Arc<crate::approval::Approver>>,
    interrupts: Option<Arc<crate::engine::interrupt::InterruptHub>>,
}

impl AddPackageTool {
    pub fn new(
        resolution: Arc<DocsResolution>,
        approver: Option<Arc<crate::approval::Approver>>,
        interrupts: Option<Arc<crate::engine::interrupt::InterruptHub>>,
    ) -> Self {
        Self {
            resolution,
            approver,
            interrupts,
        }
    }

    /// Raise the package-add approval for a clone that is about to happen.
    /// Returns [`CloneApproval::NoApprover`] when there is no approver wired
    /// or no interactive client to answer (headless / background) — deny
    /// without blocking, mirroring the gitignore-read gate. Otherwise it
    /// prompts and maps the user's answer to approve/deny.
    async fn approve_clone(
        &self,
        identifier: &str,
        clone_url: &str,
        rationale: &str,
    ) -> Result<CloneApproval> {
        let (Some(approver), Some(interrupts)) = (&self.approver, &self.interrupts) else {
            return Ok(CloneApproval::NoApprover);
        };
        // No human on the other end → cannot approve a clone; refuse cleanly
        // rather than block forever on a prompt nobody will answer.
        if !interrupts.is_interactive_attached() {
            return Ok(CloneApproval::NoApprover);
        }
        let decision = approver
            .approve_package_add(identifier, clone_url, rationale)
            .await?;
        Ok(if decision.is_allowed() {
            CloneApproval::Approved
        } else {
            CloneApproval::Denied
        })
    }
}

/// Outcome of the package-add approval gate.
enum CloneApproval {
    /// The user approved this clone.
    Approved,
    /// The user dismissed/denied the prompt.
    Denied,
    /// No approver / no interactive client to answer — cannot clone.
    NoApprover,
}

#[async_trait]
impl Tool for AddPackageTool {
    fn name(&self) -> &str {
        "add-package"
    }

    fn description(&self) -> &str {
        "Clone a dependency's source from its official registry-declared repo and register it"
    }

    fn defensive_description(&self) -> Option<String> {
        Some(
            "Register a dependency by cloning its source code from the repository its official \
             package registry declares — crates.io for `cargo`, npm for `npm`, PyPI for `pip`. \
             Use this when the package you need is NOT already in `list-packages`. Give the \
             package's published name and its ecosystem; the source repo is resolved from \
             registry metadata only (never a guessed URL), so a package whose registry declares \
             no source repo cannot be cloned. After this succeeds the package is available to \
             answer questions about."
                .to_string(),
        )
    }

    fn parameters(&self) -> Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "name":      { "type": "string", "description": "Package name as published (e.g. `tokio`, `requests`)" },
                "ecosystem": { "type": "string", "description": "Registry to resolve the source repo from", "enum": ["cargo", "npm", "pip"] }
            },
            "required": ["name", "ecosystem"]
        })
    }

    fn defensive_parameters(&self) -> Option<Value> {
        Some(serde_json::json!({
            "type": "object",
            "properties": {
                "name":      { "type": "string", "description": "The package's name exactly as published to its registry, e.g. `tokio` (cargo), `requests` (pip)" },
                "ecosystem": { "type": "string", "description": "Which registry to resolve the source repository from: `cargo` (crates.io), `npm`, or `pip` (PyPI)", "enum": ["cargo", "npm", "pip"] }
            },
            "required": ["name", "ecosystem"]
        }))
    }

    async fn call(&self, args: Value, ctx: &ToolCtx) -> Result<ToolOutput> {
        let name = args
            .get("name")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| invalid_input("`name` is required"))?;
        let eco_str = args
            .get("ecosystem")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid_input("`ecosystem` is required (cargo|npm|pip)"))?;
        let eco = Ecosystem::parse(eco_str)
            .ok_or_else(|| invalid_input(format!("unknown ecosystem `{eco_str}`")))?;

        let identifier = packages::ecosystem_slug(eco, name);

        // Already registered under the ecosystem-prefixed identifier?
        if let Some(existing) = ctx.session.db.package_by_identifier(&identifier)? {
            self.resolution
                .record(&existing.identifier, std::path::Path::new(&existing.path));
            return Ok(ToolOutput::text(format!(
                "`{identifier}` is already registered at {}.",
                existing.path
            )));
        }

        // Resolve the source repo from official registry metadata only.
        let repo = match resolve_repo_url(eco, name).await {
            Ok(RepoResolution::Resolved(url)) => url,
            Ok(RepoResolution::NotDeclared) => {
                return Ok(ToolOutput::text(format!(
                    "Could not resolve a source repo for `{name}`: the {eco_str} registry declares no repository. Refusing to clone a guessed URL."
                )));
            }
            Err(e) => {
                return Ok(ToolOutput::text(format!(
                    "Could not look up `{name}` on the {eco_str} registry: {e}"
                )));
            }
        };

        // Cloning a NEW package requires explicit user approval. The gate
        // fires here — after the URL is resolved from official registry
        // metadata (so the URL + rationale are grounded, never a guess) and
        // before any clone. The rationale names the exact registry the repo
        // was declared by; it is not free-form model text.
        let rationale = format!(
            "`{name}`'s official {} registry declares this repository.",
            eco.registry_label()
        );
        match self.approve_clone(&identifier, &repo, &rationale).await? {
            CloneApproval::Approved => {}
            CloneApproval::Denied => {
                // Surface the denial cleanly so Docs.1 stops — it cannot
                // answer without the package, and must not loop or guess an
                // alternate URL.
                return Ok(ToolOutput::text(format!(
                    "Cloning `{identifier}` from {repo} was not approved, so it could not be \
                     registered. Without its source the docs question cannot be answered; do not \
                     guess an alternate URL or retry."
                )));
            }
            CloneApproval::NoApprover => {
                return Ok(ToolOutput::text(format!(
                    "Cloning `{identifier}` from {repo} requires user approval, but no interactive \
                     client is attached to approve it, so it could not be registered. Without its \
                     source the docs question cannot be answered."
                )));
            }
        }

        let row = match packages::add_git(&ctx.session.db, &ctx.cwd, &identifier, &repo, None, true)
        {
            Ok(row) => row,
            Err(e) => {
                return Ok(ToolOutput::text(format!(
                    "Could not clone `{name}` from {repo}: {e}"
                )));
            }
        };
        debug_assert_eq!(row.source_type, SourceType::Git);
        self.resolution
            .record(&row.identifier, std::path::Path::new(&row.path));
        Ok(ToolOutput::text(format!(
            "Registered `{identifier}` from {repo} at {}.",
            row.path
        )))
    }
}

/// Whether a registered `identifier` satisfies a requested `target`. The
/// caller's `package` is a bare name (`tokio`) or scoped name
/// (`@tanstack/query`); registered identifiers may be bare (kcl imports)
/// or ecosystem-prefixed (`cargo:tokio`). Match either form.
fn identifier_matches(identifier: &str, target: &str) -> bool {
    if identifier == target {
        return true;
    }
    // Strip an ecosystem prefix (`cargo:`, `npm:`, `pip:`) and compare.
    identifier
        .split_once(':')
        .is_some_and(|(_, rest)| rest == target)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::common::test_ctx;

    #[test]
    fn identifier_matching() {
        assert!(identifier_matches("tokio", "tokio"));
        assert!(identifier_matches("cargo:tokio", "tokio"));
        assert!(identifier_matches("npm:@tanstack/query", "@tanstack/query"));
        assert!(!identifier_matches("cargo:tokio", "serde"));
    }

    #[tokio::test]
    async fn list_packages_records_matching_target() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = test_ctx(tmp.path());
        // Register a package whose on-disk path exists.
        let pkg_dir = tmp.path().join("clone");
        std::fs::create_dir_all(&pkg_dir).unwrap();
        ctx.session
            .db
            .upsert_package(&crate::db::packages::NewPackage {
                identifier: "cargo:tokio".into(),
                display_name: "tokio".into(),
                source_type: SourceType::Git,
                source_url: Some("u".into()),
                source_branch: Some("main".into()),
                path: pkg_dir.to_string_lossy().into(),
                shallow: true,
                prepare_scope: "global".into(),
            })
            .unwrap();
        let resolution = DocsResolution::new();
        let tool = ListPackagesTool::new(resolution.clone(), "tokio".into());
        let _ = tool.call(serde_json::json!({}), &ctx).await.unwrap();
        let resolved = resolution.take().expect("expected a resolution");
        assert_eq!(resolved.identifier, "cargo:tokio");
        assert_eq!(resolved.path, pkg_dir);
    }

    #[tokio::test]
    async fn list_packages_empty_message() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = test_ctx(tmp.path());
        let resolution = DocsResolution::new();
        let tool = ListPackagesTool::new(resolution.clone(), "tokio".into());
        let out = tool.call(serde_json::json!({}), &ctx).await.unwrap();
        assert!(out.content.contains("No packages registered"));
        assert!(resolution.take().is_none());
    }

    /// Build an [`Approver`] backed by the ctx's session DB, wired to a
    /// fresh detached hub — enough to prove the package-add gate is (or
    /// isn't) reached without any network or interactive client.
    fn approver_for(ctx: &ToolCtx) -> Arc<crate::approval::Approver> {
        let db = ctx.session.db.clone();
        let sid = ctx.session.id;
        let store = crate::approval::store::GrantStore::new(db.clone(), sid, ctx.cwd.clone());
        let hub = Arc::new(crate::engine::interrupt::InterruptHub::detached());
        Arc::new(crate::approval::Approver::new(
            store,
            db,
            sid,
            "docs-resolver",
            hub,
        ))
    }

    /// An already-registered package short-circuits BEFORE the package-add
    /// gate: it records the resolution and returns the "already registered"
    /// message without raising any approval (the gate would otherwise block
    /// on a detached hub forever). This is the no-re-prompt edge case.
    #[tokio::test]
    async fn add_package_already_registered_skips_gate() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = test_ctx(tmp.path());
        let pkg_dir = tmp.path().join("clone");
        std::fs::create_dir_all(&pkg_dir).unwrap();
        ctx.session
            .db
            .upsert_package(&crate::db::packages::NewPackage {
                identifier: "cargo:tokio".into(),
                display_name: "tokio".into(),
                source_type: SourceType::Git,
                source_url: Some("u".into()),
                source_branch: Some("main".into()),
                path: pkg_dir.to_string_lossy().into(),
                shallow: true,
                prepare_scope: "global".into(),
            })
            .unwrap();

        let resolution = DocsResolution::new();
        // A real approver + interactive-less hub is wired: if the gate were
        // reached it would either block forever or refuse — proving the
        // already-registered short-circuit fires first.
        let approver = approver_for(&ctx);
        let interrupts = Arc::new(crate::engine::interrupt::InterruptHub::detached());
        let tool = AddPackageTool::new(resolution.clone(), Some(approver), Some(interrupts));
        let out = tool
            .call(
                serde_json::json!({"name": "tokio", "ecosystem": "cargo"}),
                &ctx,
            )
            .await
            .unwrap();
        assert!(out.content.contains("already registered"));
        // The resolution was recorded from the existing row (no clone).
        let resolved = resolution.take().expect("existing package recorded");
        assert_eq!(resolved.identifier, "cargo:tokio");
        assert_eq!(resolved.path, pkg_dir);
    }

    /// With no approver wired, the gate refuses the clone cleanly (cannot
    /// approve without an approver) rather than silently proceeding —
    /// `approve_clone` returns `NoApprover`.
    #[tokio::test]
    async fn approve_clone_without_approver_refuses() {
        let resolution = DocsResolution::new();
        let tool = AddPackageTool::new(resolution, None, None);
        let outcome = tool
            .approve_clone("cargo:tokio", "https://example.invalid/x", "grounded")
            .await
            .unwrap();
        assert!(matches!(outcome, CloneApproval::NoApprover));
    }

    /// With an approver wired but no interactive client attached (detached
    /// hub), the gate refuses rather than blocking forever on a prompt
    /// nobody can answer.
    #[tokio::test]
    async fn approve_clone_headless_refuses() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = test_ctx(tmp.path());
        let approver = approver_for(&ctx);
        let interrupts = Arc::new(crate::engine::interrupt::InterruptHub::detached());
        let resolution = DocsResolution::new();
        let tool = AddPackageTool::new(resolution, Some(approver), Some(interrupts));
        let outcome = tool
            .approve_clone("cargo:tokio", "https://example.invalid/x", "grounded")
            .await
            .unwrap();
        assert!(matches!(outcome, CloneApproval::NoApprover));
    }
}
