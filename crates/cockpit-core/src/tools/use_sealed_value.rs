//! `use_sealed_value` — the sole model-facing sealed-value use mechanism.
//!
//! This tool accepts exactly `{sealed_value_id, action_id, parameters}` and
//! returns exactly the granted action's declared safe projection. There is no
//! sibling tool that returns a literal, for any caller: a trusted model's raw
//! custody is an *inference egress* contract governed by `ModelTrust`, not a
//! tool API. Untrusted callers in every `LlmMode` reach only this surface.
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
struct LiveWorkspaceTrust {
    session: std::sync::Arc<crate::session::Session>,
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

    fn runtime_for(&self, ctx: &ToolCtx) -> Result<Arc<SealedRuntime>> {
        if let Some(runtime) = &self.runtime {
            return Ok(Arc::clone(runtime));
        }
        Ok(Arc::new(SealedRuntime::new(
            ctx.session.db.clone(),
            SealedCompartment::from_vault(ctx.session.secret_vault().clone()),
            crate::sealed::action::installed_sealed_action_registry(),
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

    fn defensive_description(&self) -> Option<String> {
        Some(
            "Use a sealed value without ever seeing it. Name the sealed value id and the action id you were granted, plus that action's declared bounded parameters. You cannot supply an endpoint, command, environment key, header, request template, or output projection, and you cannot list which sealed values exist. The result is only the action's declared safe fields. If anything about the grant is wrong, missing, stale, or revoked you get one identical unavailable answer."
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
            caller_mode: ctx.llm_mode,
            project_key: SealedProjectKey::from_canonical(ctx.session.project_id.clone()),
            project_trust,
            session_id: ctx.session.id,
            // The session's config generation. A config change — including any
            // provider, model, or trust change — bumps it and thereby retires
            // every outstanding grant.
            session_generation: ctx.config.generation(),
            now_ms: chrono::Utc::now().timestamp_millis(),
        };

        let runtime = self.runtime_for(ctx)?;
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
