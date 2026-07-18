use crate::db::tool_calls::Recovery;
use crate::mcp::config::ServerConfig;
use crate::mcp::protocol::ToolDescriptor;
use serde_json::Value;

#[derive(Debug, Clone)]
pub enum NestedRepair {
    Dispatch {
        args: Value,
        #[allow(dead_code)]
        recovery: Option<(Recovery, Value)>,
    },
    Reject(String),
}

pub fn repair_nested_args(
    outer: Option<&Value>,
    server: &str,
    tool: &str,
    mut nested: Value,
    schema: &Value,
    call_name: &str,
) -> NestedRepair {
    let outcome = crate::engine::repair::repair(&mut nested, schema, call_name);
    if !outcome.valid {
        return NestedRepair::Reject(outcome.error.unwrap_or_else(|| {
            format!(
                "`{server}.{tool}` arguments failed schema validation; re-emit `{call_name}` with `args` matching the tool's input schema."
            )
        }));
    }

    let recovery = if outcome.recovery == Recovery::Clean {
        None
    } else {
        outer.cloned().map(|mut canonical_outer| {
            match &mut canonical_outer {
                Value::Object(map) => {
                    map.insert("args".to_string(), nested.clone());
                }
                other => {
                    *other = serde_json::json!({
                        "server": server,
                        "tool": tool,
                        "args": nested.clone(),
                    });
                }
            }
            (outcome.recovery, canonical_outer)
        })
    };

    NestedRepair::Dispatch {
        args: nested,
        recovery,
    }
}

pub fn repair_invoke_args_from_tools(
    tools: &[ToolDescriptor],
    outer: Option<&Value>,
    server: &str,
    tool: &str,
    nested: Value,
    call_name: &str,
) -> NestedRepair {
    let Some(desc) = tools.iter().find(|desc| desc.name == tool) else {
        return NestedRepair::Dispatch {
            args: nested,
            recovery: None,
        };
    };
    if !desc.input_schema.is_object() {
        return NestedRepair::Dispatch {
            args: nested,
            recovery: None,
        };
    }
    repair_nested_args(outer, server, tool, nested, &desc.input_schema, call_name)
}

pub async fn prepare_invoke_args(
    server: &str,
    server_cfg: &ServerConfig,
    tool: &str,
    nested: Value,
    outer: Option<&Value>,
    call_name: &str,
) -> NestedRepair {
    let Ok(tools) = crate::mcp::catalog::list_tools_cached(server, server_cfg).await else {
        return NestedRepair::Dispatch {
            args: nested,
            recovery: None,
        };
    };
    repair_invoke_args_from_tools(&tools, outer, server, tool, nested, call_name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn count_schema() -> Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "count": { "type": "integer" }
            },
            "required": ["count"]
        })
    }

    fn count_tool() -> ToolDescriptor {
        ToolDescriptor {
            name: "count".into(),
            description: "Count things".into(),
            input_schema: count_schema(),
        }
    }

    #[test]
    fn nested_repair_rejects_unrepairable_args_before_dispatch() {
        let outer = serde_json::json!({
            "server": "srv",
            "tool": "count",
            "args": {}
        });

        match repair_nested_args(
            Some(&outer),
            "srv",
            "count",
            serde_json::json!({}),
            &count_schema(),
            "mcp.invoke",
        ) {
            NestedRepair::Reject(message) => {
                assert!(message.contains("requires a `count` string"), "{message}");
                assert!(message.contains("Re-emit the call"), "{message}");
            }
            other => panic!("expected reject, got {other:?}"),
        }
    }

    #[test]
    fn nested_repair_dispatches_repaired_args_with_canonical_outer_call() {
        let outer = serde_json::json!({
            "server": "srv",
            "tool": "count",
            "args": { "count": "3" },
            "extra": true
        });

        match repair_nested_args(
            Some(&outer),
            "srv",
            "count",
            serde_json::json!({ "count": "3" }),
            &count_schema(),
            "mcp.invoke",
        ) {
            NestedRepair::Dispatch {
                args,
                recovery: Some((recovery, canonical)),
            } => {
                assert_eq!(args, serde_json::json!({ "count": 3 }));
                assert!(
                    matches!(
                        recovery,
                        Recovery::ShapeRepair {
                            stage: "parse_stringified_number",
                            ref path,
                            ..
                        } if path == "count"
                    ),
                    "unexpected recovery: {recovery:?}"
                );
                assert_eq!(
                    canonical,
                    serde_json::json!({
                        "server": "srv",
                        "tool": "count",
                        "args": { "count": 3 },
                        "extra": true
                    })
                );
            }
            other => panic!("expected repaired dispatch, got {other:?}"),
        }
    }

    #[test]
    fn nested_repair_clean_args_dispatch_unchanged_without_recovery() {
        let outer = serde_json::json!({
            "server": "srv",
            "tool": "count",
            "args": { "count": 3 }
        });
        let nested = serde_json::json!({ "count": 3 });

        match repair_nested_args(
            Some(&outer),
            "srv",
            "count",
            nested.clone(),
            &count_schema(),
            "mcp.invoke",
        ) {
            NestedRepair::Dispatch { args, recovery } => {
                assert_eq!(args, nested);
                assert!(recovery.is_none());
            }
            other => panic!("expected clean dispatch, got {other:?}"),
        }
    }

    #[test]
    fn nested_repair_non_object_schema_dispatches_unchanged_without_recovery() {
        let outer = serde_json::json!({
            "server": "srv",
            "tool": "loose",
            "args": { "anything": "goes" }
        });
        let nested = serde_json::json!({ "anything": "goes" });

        match repair_nested_args(
            Some(&outer),
            "srv",
            "loose",
            nested.clone(),
            &Value::Null,
            "mcp.invoke",
        ) {
            NestedRepair::Dispatch { args, recovery } => {
                assert_eq!(args, nested);
                assert!(recovery.is_none());
            }
            other => panic!("expected clean dispatch, got {other:?}"),
        }
    }

    #[test]
    fn nested_repair_is_idempotent_after_canonical_rewrite() {
        let outer = serde_json::json!({
            "server": "srv",
            "tool": "count",
            "args": { "count": 3 }
        });

        match repair_nested_args(
            Some(&outer),
            "srv",
            "count",
            serde_json::json!({ "count": 3 }),
            &count_schema(),
            "mcp.invoke",
        ) {
            NestedRepair::Dispatch { args, recovery } => {
                assert_eq!(args, serde_json::json!({ "count": 3 }));
                assert!(recovery.is_none());
            }
            other => panic!("expected clean dispatch, got {other:?}"),
        }
    }

    #[test]
    fn monty_repair_from_tools_repairs_args_without_outer_recovery() {
        match repair_invoke_args_from_tools(
            &[count_tool()],
            None,
            "srv",
            "count",
            serde_json::json!({ "count": "3" }),
            "mcp.invoke",
        ) {
            NestedRepair::Dispatch { args, recovery } => {
                assert_eq!(args, serde_json::json!({ "count": 3 }));
                assert!(recovery.is_none());
            }
            other => panic!("expected repaired dispatch, got {other:?}"),
        }
    }
}
