//! Model-facing KB sealed-value authoring. Both paths return only a symbolic
//! token suitable for markdown; literals stay in the daemon vault.

use anyhow::Result;
use async_trait::async_trait;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::engine::tool::{Tool, ToolCtx, ToolEffect, ToolOutput, invalid_input, typed_args};
use crate::sealed::runtime::SealedProjectTrustSource;
use crate::sealed::{
    KnowledgeBaseSealedStore, SealedCompartment, SealedLiteral, SealedProjectKey,
    SealedProjectTrust, SealedUseContext, SealedUseDenied, parse_use_sealed_value_args,
};

const CREATE_KB_SEALED_VALUE_TOOL: &str = "knowledge_sealed_create";
const COPY_KB_SEALED_VALUE_TOOL: &str = "knowledge_sealed_copy";

#[derive(Deserialize)]
struct CreateArgs {
    knowledge_base_id: String,
    literal: String,
}

#[derive(Debug, Deserialize)]
struct CopyArgs {
    knowledge_base_id: String,
    source: Value,
}

fn scope(ctx: &ToolCtx, trust: SealedProjectTrust) -> SealedUseContext {
    SealedUseContext {
        caller_trust: crate::config::providers::ModelTrust::default(),
        project_key: SealedProjectKey::from_canonical(ctx.session.project_id.clone()),
        project_trust: trust,
        session_id: ctx.session.id,
        session_generation: ctx.config.generation(),
        now_ms: chrono::Utc::now().timestamp_millis(),
    }
}

pub struct CreateKnowledgeBaseSealedValueTool;

#[async_trait]
impl Tool for CreateKnowledgeBaseSealedValueTool {
    fn name(&self) -> &str {
        CREATE_KB_SEALED_VALUE_TOOL
    }

    fn description(&self) -> &str {
        "Store a value in the daemon vault for one attached knowledge base and return its symbolic markdown reference"
    }

    fn effect(&self) -> ToolEffect {
        ToolEffect::Mutating
    }

    fn parameters(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "knowledge_base_id": { "type": "string" },
                "literal": { "type": "string", "maxLength": 16384 }
            },
            "required": ["knowledge_base_id", "literal"],
            "additionalProperties": false
        })
    }

    async fn call(&self, args: Value, ctx: &ToolCtx) -> Result<ToolOutput> {
        let args: CreateArgs = typed_args(args)?;
        if args.literal.len() > cockpit_proto::MAX_SENSITIVE_FRAME_BYTES {
            return Err(invalid_input(
                "knowledge sealed literal exceeds the sensitive-frame limit",
            ));
        }
        let kb_id =
            crate::knowledge::sealed_knowledge_base_id_for_tool(ctx, &args.knowledge_base_id)
                .await?;
        let reference = KnowledgeBaseSealedStore::new(ctx.session.secret_vault().clone())
            .create(kb_id, SealedLiteral::new(args.literal))?;
        Ok(ToolOutput::text(reference.token()?))
    }
}

pub struct CopyKnowledgeBaseSealedValueTool;

#[async_trait]
impl Tool for CopyKnowledgeBaseSealedValueTool {
    fn name(&self) -> &str {
        COPY_KB_SEALED_VALUE_TOOL
    }

    fn description(&self) -> &str {
        "Copy one Owner-granted sealed value into an attached knowledge base and return its symbolic markdown reference"
    }

    fn effect(&self) -> ToolEffect {
        ToolEffect::Dynamic
    }

    fn parameters(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "knowledge_base_id": { "type": "string" },
                "source": crate::sealed::use_sealed_value_schema()
            },
            "required": ["knowledge_base_id", "source"],
            "additionalProperties": false
        })
    }

    async fn call(&self, args: Value, ctx: &ToolCtx) -> Result<ToolOutput> {
        let args: CopyArgs = typed_args(args)?;
        let request = parse_use_sealed_value_args(&args.source)
            .map_err(|error| invalid_input(error.to_string()))?;
        let kb_id =
            crate::knowledge::sealed_knowledge_base_id_for_tool(ctx, &args.knowledge_base_id)
                .await?;
        let trust = crate::tools::use_sealed_value::LiveWorkspaceTrust {
            session: ctx.session.clone(),
        };
        let project_trust = trust
            .current_trust()
            .await
            .unwrap_or(SealedProjectTrust::Untrusted);
        let registry = crate::sealed::action_admin::build_live_registry(
            &ctx.session.db,
            &ctx.session.project_id,
        )
        .await;
        let Ok(registry) = registry else {
            return Ok(ToolOutput::text(SealedUseDenied.to_string()));
        };
        let runtime = crate::sealed::SealedRuntime::new(
            ctx.session.db.clone(),
            SealedCompartment::from_vault(ctx.session.secret_vault().clone()),
            registry,
        );
        let sink =
            crate::sealed::SessionRedactionSink::new(ctx.interrupts.clone(), ctx.session.clone());
        let store = KnowledgeBaseSealedStore::new(ctx.session.secret_vault().clone());
        match runtime
            .copy_to_knowledge_base(
                &request,
                &scope(ctx, project_trust),
                &sink,
                &trust,
                kb_id,
                &store,
            )
            .await
        {
            Ok(reference) => Ok(ToolOutput::text(reference.token()?)),
            Err(denied) => Ok(ToolOutput::text(denied.to_string())),
        }
    }
}
