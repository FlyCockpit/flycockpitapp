//! `seed` — a re-queryable read-only subagent hands a small, directly-relevant
//! read-only result up to its caller (GOALS §3c).
//!
//! The subagent calls `seed({tool, args})` to mark a read-only result
//! (`read` / `grep` / `glob` / intel `search` / other read-only intel tools)
//! that the caller should receive directly. The entry is appended to the
//! frame's [`crate::engine::seed_collector::SeedCollector`]; on the
//! subagent's return the driver re-executes it in the caller's cwd and
//! injects it into the caller's transcript as a native tool-call/result pair,
//! capped under the subagent-report budget (GOALS §10).
//!
//! Read-only only: write/lock/`bash` are rejected at validation. This tool
//! is registered **only** on read-only noninteractive subagents in `normal`
//! mode (the capability is gated, not the description text — see
//! [`crate::engine::tool::Capability`]); the driver re-exec is the hard gate.

use anyhow::Result;
use async_trait::async_trait;
use serde_json::{Value, json};

use crate::db::seed_tools::SeedTool;
use crate::engine::compact::{is_read_only_seed_tool, read_only_seed_tool_names};
use crate::engine::tool::{Tool, ToolCtx, ToolOutput, invalid_input};

pub struct SeedEmitTool;

#[async_trait]
impl Tool for SeedEmitTool {
    fn name(&self) -> &str {
        "seed"
    }

    fn description(&self) -> &str {
        "Hand one directly-relevant read-only result up to your caller; seed nothing that isn't."
    }

    fn parameters(&self) -> Value {
        seed_item_schema()
    }

    async fn call(&self, args: Value, ctx: &ToolCtx) -> Result<ToolOutput> {
        let tool = args
            .get("tool")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| invalid_input("`tool` is required and non-empty"))?;
        // Read-only only — never seed a write/lock/bash path into the caller.
        if !is_read_only_seed_tool(tool) {
            return Err(invalid_input(format!(
                "`{tool}` is not a read-only tool; only read-only results may be seeded"
            )));
        }
        let seed_args = args
            .get("args")
            .cloned()
            .filter(Value::is_object)
            .ok_or_else(|| invalid_input("`args` is required and must be an object"))?;

        ctx.seeds.push(SeedTool {
            tool: tool.to_string(),
            args: seed_args,
        });
        let n = ctx.seeds.len();
        Ok(ToolOutput::text(format!(
            "seeded `{tool}` for the caller ({n} queued); continue, and seed only what is directly relevant"
        )))
    }
}

pub(crate) fn seed_item_schema() -> Value {
    let arms: Vec<Value> = read_only_seed_tool_schemas()
        .into_iter()
        .map(|(tool, args)| {
            json!({
                "type": "object",
                "properties": {
                    "tool": {
                        "type": "string",
                        "const": tool
                    },
                    "args": args
                },
                "required": ["tool", "args"],
                "additionalProperties": false
            })
        })
        .collect();

    json!({
        "type": "object",
        "properties": {
            "tool": {
                "type": "string",
                "enum": read_only_seed_tool_names(),
                "description": "Read-only tool name (read/grep/glob/intel search)"
            },
            "args": seed_args_schema()
        },
        "required": ["tool", "args"],
        "additionalProperties": false,
        "anyOf": arms
    })
}

pub(crate) fn seed_args_schema() -> Value {
    let arms: Vec<Value> = read_only_seed_tool_schemas()
        .into_iter()
        .map(|(_, args)| args)
        .collect();
    json!({
        "anyOf": arms,
        "description": "Args for that read-only tool (file path, line range, query)"
    })
}

fn read_only_seed_tool_schemas() -> Vec<(&'static str, Value)> {
    let mut schemas = vec![
        crate::tools::read::ReadTool.parameters(),
        crate::tools::intel::OutlineTool.parameters(),
        crate::tools::intel::SymbolFindTool.parameters(),
        crate::tools::intel::WordTool.parameters(),
        crate::tools::intel::DepsTool.parameters(),
        crate::tools::intel::CircularTool.parameters(),
        crate::tools::intel::TreeTool.parameters(),
        crate::tools::intel::SearchTool.parameters(),
        crate::tools::intel::ImpactTool.parameters(),
        crate::tools::grep::GrepTool.parameters(),
        crate::tools::glob::GlobTool.parameters(),
    ];
    let names = read_only_seed_tool_names();
    assert_eq!(
        schemas.len(),
        names.len(),
        "seed schema tool list must match read_only_seed_tool_names"
    );
    for schema in &mut schemas {
        close_schema_object(schema);
    }
    names.into_iter().zip(schemas).collect()
}

fn close_schema_object(schema: &mut Value) {
    let Some(object) = schema.as_object_mut() else {
        return;
    };
    if object.contains_key("properties")
        || object.get("type") == Some(&json!("object"))
        || object
            .get("type")
            .and_then(Value::as_array)
            .is_some_and(|kinds| kinds.iter().any(|kind| kind.as_str() == Some("object")))
    {
        object.insert("additionalProperties".to_string(), Value::Bool(false));
    }
    if let Some(properties) = object.get_mut("properties").and_then(Value::as_object_mut) {
        for property in properties.values_mut() {
            close_schema_object(property);
        }
    }
    if let Some(items) = object.get_mut("items") {
        close_schema_object(items);
    }
    if let Some(definitions) = object.get_mut("$defs").and_then(Value::as_object_mut) {
        for definition in definitions.values_mut() {
            close_schema_object(definition);
        }
    }
    for key in ["anyOf", "oneOf", "allOf"] {
        if let Some(variants) = object.get_mut(key).and_then(Value::as_array_mut) {
            for variant in variants {
                close_schema_object(variant);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn queues_a_read_only_seed() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = crate::tools::common::test_ctx(dir.path());
        SeedEmitTool
            .call(
                serde_json::json!({ "tool": "read", "args": { "path": "/a.rs" } }),
                &ctx,
            )
            .await
            .unwrap();
        let drained = ctx.seeds.drain();
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].tool, "read");
    }

    #[tokio::test]
    async fn rejects_a_write_tool() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = crate::tools::common::test_ctx(dir.path());
        let err = SeedEmitTool
            .call(
                serde_json::json!({ "tool": "bash", "args": { "command": "rm -rf /" } }),
                &ctx,
            )
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("read-only"), "{err}");
        assert_eq!(ctx.seeds.len(), 0);
    }

    #[tokio::test]
    async fn requires_object_args() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = crate::tools::common::test_ctx(dir.path());
        let err = SeedEmitTool
            .call(serde_json::json!({ "tool": "read", "args": "/a.rs" }), &ctx)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("args"), "{err}");
    }

    #[test]
    fn seed_item_schema_is_closed_and_discriminated_by_tool() {
        let schema = seed_item_schema();
        assert_eq!(schema["type"], "object");
        assert_eq!(schema["additionalProperties"], false);
        assert_eq!(schema["required"], json!(["tool", "args"]));
        assert_eq!(schema["properties"]["args"], seed_args_schema());

        let arms = schema["anyOf"].as_array().unwrap();
        assert_eq!(arms.len(), read_only_seed_tool_names().len());
        for (tool, arm) in read_only_seed_tool_names().into_iter().zip(arms) {
            assert_eq!(arm["type"], "object");
            assert_eq!(arm["additionalProperties"], false);
            assert_eq!(arm["required"], json!(["tool", "args"]));
            assert_eq!(arm["properties"]["tool"]["const"], tool);
            assert_eq!(
                arm["properties"]["args"]["additionalProperties"], false,
                "{tool} args schema is closed"
            );
        }

        let validator = jsonschema::validator_for(&schema).unwrap();
        assert!(validator.is_valid(&json!({
            "tool": "read",
            "args": { "path": "src/lib.rs" }
        })));
        assert!(!validator.is_valid(&json!({
            "tool": "read",
            "args": { "pattern": "needle" }
        })));
    }
}
