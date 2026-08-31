//! Read-only LSP navigation tool for semantic lookups.

use anyhow::Result;
use async_trait::async_trait;
use serde_json::Value;

use crate::daemon::lsp::{LspNavigationRequest, LspOperation};
use crate::engine::tool::{Tool, ToolCtx, ToolEffect, ToolOutput, invalid_input};
use crate::tools::common::resolve;

pub struct LspTool;

#[async_trait]
impl Tool for LspTool {
    fn name(&self) -> &str {
        "lsp"
    }

    fn description(&self) -> &str {
        "Semantic hover, definition, or references when intel tools need type precision"
    }

    fn verbose_description(&self) -> Option<String> {
        Some(
            "Use LSP only for type-aware hover, definition, or references after cheaper intel/search tools are insufficient; it is read-only and may be unavailable."
                .to_string(),
        )
    }

    fn effect(&self) -> ToolEffect {
        ToolEffect::ReadOnly
    }

    fn parameters(&self) -> Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "operation": { "type": "string", "enum": ["hover", "definition", "references"], "description": "Semantic lookup operation" },
                "file": { "type": "string", "x-cockpit-kind": "path", "description": "Source file path" },
                "line": { "type": "integer", "minimum": 1, "description": "1-based line" },
                "character": { "type": "integer", "minimum": 1, "description": "1-based character" }
            },
            "required": ["operation", "file"]
        })
    }

    async fn call(&self, args: Value, ctx: &ToolCtx) -> Result<ToolOutput> {
        let operation = args
            .get("operation")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid_input("`operation` is required"))?;
        let operation = match operation {
            "hover" => LspOperation::Hover,
            "definition" => LspOperation::Definition,
            "references" => LspOperation::References,
            other => {
                return Err(invalid_input(format!(
                    "unsupported LSP operation `{other}`; expected hover, definition, or references"
                )));
            }
        };
        let file = args
            .get("file")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid_input("`file` is required"))?;
        let line = optional_u32(&args, "line")?;
        let character = optional_u32(&args, "character")?;
        let file = resolve(file, &ctx.cwd);
        let file = crate::tools::sandbox::check_native_access(
            ctx,
            &file,
            crate::tools::shell_sandbox::SandboxPathAccess::Read,
        )
        .await?;
        let Some(lsp) = &ctx.lsp else {
            return Ok(ToolOutput::text("LSP is unavailable in this context."));
        };
        let config = ctx.config.extended();
        // LSP servers may read the supplied file while serving navigation.
        // Reclaim the exact path after the availability/config gates and
        // directly before handing it to that host-facing subsystem.
        crate::tools::sandbox::recheck_native_access_effect_boundary(
            &file,
            crate::tools::shell_sandbox::SandboxPathAccess::Read,
        )
        .await?;
        // `Tool::call` is also used by private verification investigation,
        // which deliberately bypasses the normal tool dispatcher.  Keep the
        // opaque LSP host boundary fenced here as well: an LSP server rooted
        // in the workspace can write outside this read-only navigation API.
        crate::knowledge::ensure_workspace_tool_access(ctx, self.name()).await?;
        let out = lsp
            .navigate(
                &ctx.cwd,
                LspNavigationRequest {
                    operation,
                    file,
                    line,
                    character,
                },
                &config,
            )
            .await;
        Ok(ToolOutput::text(out))
    }
}

fn optional_u32(args: &Value, key: &str) -> Result<Option<u32>> {
    let Some(value) = args.get(key) else {
        return Ok(None);
    };
    let Some(n) = value.as_u64() else {
        return Err(invalid_input(format!("`{key}` must be an integer")));
    };
    if n == 0 || n > u32::MAX as u64 {
        return Err(invalid_input(format!(
            "`{key}` must be between 1 and {}",
            u32::MAX
        )));
    }
    Ok(Some(n as u32))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::extended::{
        ExtendedConfig, KnowledgeBaseEmbeddingOwnership, KnowledgeBaseMergePolicy,
        KnowledgeBaseRegistryEntry, KnowledgeBaseSource,
    };

    #[tokio::test]
    async fn direct_lsp_call_keeps_local_knowledge_host_fence() {
        let workspace = tempfile::tempdir().unwrap();
        let source = workspace.path().join("src.rs");
        std::fs::write(&source, "fn main() {}\n").unwrap();
        let mut ctx = crate::tools::common::test_ctx(workspace.path());
        ctx.lsp = Some(std::sync::Arc::new(crate::daemon::lsp::LspManager::new()));
        ctx.config = crate::daemon::session_worker::SessionConfigHandle::detached(
            crate::daemon::session_worker::SessionConfigSnapshot::new(
                0,
                crate::config::providers::ProvidersConfig::default(),
                ExtendedConfig {
                    knowledge_bases: vec![KnowledgeBaseRegistryEntry::new(
                        "private".to_string(),
                        "Private".to_string(),
                        "Private local knowledge".to_string(),
                        KnowledgeBaseSource::Local {
                            path: workspace.path().join("knowledge"),
                        },
                        KnowledgeBaseEmbeddingOwnership::Local,
                        None,
                        None,
                        false,
                        KnowledgeBaseMergePolicy::Auto,
                    )],
                    ..Default::default()
                },
            ),
        );

        let error = LspTool
            .call(
                serde_json::json!({"operation": "hover", "file": "src.rs"}),
                &ctx,
            )
            .await
            .expect_err("direct LSP calls must not reach the host with a local KB");
        assert!(error.to_string().contains("knowledge bases are read-only"));
    }
}
