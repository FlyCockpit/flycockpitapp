//! `use_sealed_value` — the sole model-facing sealed-value use mechanism.
//!
//! This tool accepts exactly `{sealed_value_id, action_id, parameters}` and
//! returns exactly the granted action's declared safe projection. There is no
//! sibling tool that returns a literal, for any caller: a trusted model's raw
//! custody is an *inference egress* contract governed by `ModelTrust`, not a
//! tool API. Untrusted callers reach only this surface regardless of steering.
//!
//! Every failure renders the single content-free denial, so the tool is not an
//! oracle over the sealed inventory.

use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use serde_json::Value;

use crate::engine::tool::{Tool, ToolCtx, ToolEffect, ToolOutput, invalid_input};
use crate::sealed::runtime::SealedProjectTrustSource;
use crate::sealed::{
    SealedCompartment, SealedProjectKey, SealedProjectTrust, SealedRuntime, SealedUseContext,
    SealedUseDenied, SessionRedactionSink, parse_use_sealed_value_args, use_sealed_value_schema,
};

/// Reads the workspace-trust decision live from the database.
pub(crate) struct LiveWorkspaceTrust {
    pub(crate) session: std::sync::Arc<crate::session::Session>,
}

#[async_trait]
impl SealedProjectTrustSource for LiveWorkspaceTrust {
    async fn current_trust(&self) -> anyhow::Result<SealedProjectTrust> {
        let decision = self
            .session
            .db
            .workspace_trust_by_root(&self.session.project_root)
            .await?;
        Ok(match decision.map(|decision| decision.mode) {
            Some(cockpit_db::db::workspace_trust::WorkspaceTrustMode::Trust) => {
                SealedProjectTrust::Trusted
            }
            // Fail closed: unknown, ignore-config, and explicitly untrusted
            // all deny.
            _ => SealedProjectTrust::Untrusted,
        })
    }
}

pub struct UseSealedValueTool {
    /// Pre-built runtime, for tests and for hosts that compile their own
    /// registry. `None` builds from the session's database, the default
    /// compartment, and the daemon's installed closed registry.
    runtime: Option<Arc<SealedRuntime>>,
}

impl UseSealedValueTool {
    pub fn new() -> Self {
        Self { runtime: None }
    }

    pub fn with_runtime(runtime: Arc<SealedRuntime>) -> Self {
        Self {
            runtime: Some(runtime),
        }
    }

    pub(crate) async fn runtime_for(&self, ctx: &ToolCtx) -> Result<Arc<SealedRuntime>> {
        if let Some(runtime) = &self.runtime {
            return Ok(Arc::clone(runtime));
        }
        // The live registry is rebuilt from THIS session's database, scoped to
        // THIS session's project: it reflects every currently-persisted action
        // for the project, with no install-once OnceLock and no shared mutable
        // state (`sealed-owner-persistence-and-executor` inc3b). Cross-project
        // actions are absent, so they can never resolve here.
        let project_key = SealedProjectKey::from_canonical(ctx.session.project_id.clone());
        let registry =
            crate::sealed::action_admin::build_live_registry(&ctx.session.db, project_key.as_str())
                .await?;
        Ok(Arc::new(SealedRuntime::new(
            ctx.session.db.clone(),
            SealedCompartment::from_vault(ctx.session.secret_vault().clone()),
            registry,
        )))
    }
}

impl Default for UseSealedValueTool {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Tool for UseSealedValueTool {
    fn name(&self) -> &str {
        crate::sealed::USE_SEALED_VALUE_TOOL
    }

    fn description(&self) -> &str {
        "Use a sealed value you were granted, by reference, through a granted action; the value's content is never returned"
    }

    fn verbose_description(&self) -> Option<String> {
        Some(
            "Use a sealed value without ever seeing it. Name the sealed value id and the action id you were granted, plus that action's declared bounded parameters. Use list_sealed_value_descriptions to identify values referenceable in this session; it returns safe metadata only. You cannot supply an endpoint, command, environment key, header, request template, or output projection. The result is only the action's declared safe fields. If anything about the grant is wrong, missing, stale, or revoked you get one identical unavailable answer."
                .to_string(),
        )
    }

    /// Dynamic: an action instance performs an owner-defined effect.
    fn effect(&self) -> ToolEffect {
        ToolEffect::Dynamic
    }

    fn parameters(&self) -> Value {
        use_sealed_value_schema()
    }

    async fn call(&self, args: Value, ctx: &ToolCtx) -> Result<ToolOutput> {
        // Argument shape is validated before anything else, so a malformed
        // call never reaches the grant table let alone a literal.
        let request =
            parse_use_sealed_value_args(&args).map_err(|error| invalid_input(error.to_string()))?;

        let trust = LiveWorkspaceTrust {
            session: ctx.session.clone(),
        };
        // Authorization runs against this reading; the runtime re-reads through
        // the same source before releasing a literal and denies on any change.
        let project_trust = trust
            .current_trust()
            .await
            .unwrap_or(SealedProjectTrust::Untrusted);

        let use_ctx = SealedUseContext {
            // Fail closed. This tool returns reference-only projections for
            // every caller, so trust never widens what it yields; recording
            // the default keeps the custody predicate honest rather than
            // inventing a trusted claim the tool cannot verify.
            caller_trust: crate::config::providers::ModelTrust::default(),
            project_key: SealedProjectKey::from_canonical(ctx.session.project_id.clone()),
            project_trust,
            session_id: ctx.session.id,
            // The session's config generation. A config change — including any
            // provider, model, or trust change — bumps it and thereby retires
            // every outstanding grant.
            session_generation: ctx.config.generation(),
            now_ms: chrono::Utc::now().timestamp_millis(),
        };

        // A registry-build / DB failure must be INDISTINGUISHABLE from any other
        // denial: return the same standard sealed-unavailable text, never a
        // detailed error (which would leak internal failure detail and be a
        // distinguishable response the caller could probe).
        let runtime = match self.runtime_for(ctx).await {
            Ok(runtime) => runtime,
            Err(_) => return Ok(ToolOutput::text(SealedUseDenied.to_string())),
        };
        let sink = SessionRedactionSink::new(ctx.interrupts.clone(), ctx.session.clone());
        match runtime
            .use_sealed_value(&request, &use_ctx, &sink, &trust)
            .await
        {
            Ok(projection) => Ok(ToolOutput::text(render_projection(&projection))),
            Err(denied) => Ok(ToolOutput::text(denied.to_string())),
        }
    }
}

/// Render only the declared safe projection, as stable `key: value` lines.
///
/// No status line, no timing, no byte count: the rendering adds nothing the
/// action did not declare.
fn render_projection(projection: &crate::sealed::SealedActionResult) -> String {
    if projection.is_empty() {
        return "ok".to_string();
    }
    projection
        .entries()
        .map(|(name, value)| format!("{name}: {value}"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// The denial string this tool renders, exposed for the reference matrix test.
pub fn denial_text() -> String {
    SealedUseDenied.to_string()
}
