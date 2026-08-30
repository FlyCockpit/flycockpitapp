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
const SEALED_LITERAL_LEDGER_PLACEHOLDER: &str = "[sealed literal omitted]";

/// Project arguments for tool identities whose inputs are sensitive even when
/// the concrete tool is not present in the current toolbox. Ledger safety is a
/// property of the resolved identity, not of transient tool availability.
pub(crate) fn ledger_args_for_sensitive_tool(tool: &str, args: &Value) -> Option<Value> {
    if tool != CREATE_KB_SEALED_VALUE_TOOL {
        return None;
    }

    let mut projected = serde_json::Map::new();
    if let Some(knowledge_base_id) = args.get("knowledge_base_id") {
        projected.insert("knowledge_base_id".to_string(), knowledge_base_id.clone());
    }
    projected.insert(
        "literal".to_string(),
        Value::String(SEALED_LITERAL_LEDGER_PLACEHOLDER.to_string()),
    );
    Some(Value::Object(projected))
}

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

    fn ledger_args(&self, args: &Value) -> Value {
        ledger_args_for_sensitive_tool(self.name(), args)
            .expect("knowledge_sealed_create has an identity-based ledger projection")
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sensitive_tool_identity_projection_omits_literal_and_unknown_fields() {
        const SECRET: &str = "kb-sealed-ledger-secret";
        let projected = ledger_args_for_sensitive_tool(
            CREATE_KB_SEALED_VALUE_TOOL,
            &serde_json::json!({
                "knowledge_base_id": "kb-1",
                "literal": SECRET,
                "unexpected": SECRET,
            }),
        )
        .expect("create tool has an identity projection");

        assert_eq!(
            projected,
            serde_json::json!({
                "knowledge_base_id": "kb-1",
                "literal": SEALED_LITERAL_LEDGER_PLACEHOLDER,
            })
        );
        assert!(!projected.to_string().contains(SECRET));
        assert!(ledger_args_for_sensitive_tool("other", &serde_json::json!({})).is_none());
    }
}
