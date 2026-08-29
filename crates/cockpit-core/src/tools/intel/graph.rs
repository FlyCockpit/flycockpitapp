use super::common::*;

const GRAPH_KIND_VALUES: &[&str] = &["deps", "importers", "cycles", "callers", "calls", "recent"];

fn graph_kind_error() -> anyhow::Error {
    invalid_input(
        "`kind` must be one of `deps`, `importers`, `cycles`, `callers`, `calls`, `recent`",
    )
}

fn required_for_kind(field: &str, kind: &str) -> anyhow::Error {
    invalid_input(format!("`{field}` is required for graph kind `{kind}`"))
}

fn non_empty_str<'a>(args: &'a Value, field: &str) -> Option<&'a str> {
    args.get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
}

fn graph_schema(defensive: bool) -> Value {
    let (kind_desc, path_desc, name_desc, hops_desc, symbol_kind_desc, limit_desc) = if defensive {
        (
            "Relationship query to run: `deps` for imports from one file, `importers` for files that import it, `cycles` for import cycles, `callers`/`calls` for one symbol's call graph, or `recent` for most-recently-modified files",
            "Required for `deps` and `importers`: the file path to analyze, relative to the project root or absolute",
            "Required for `callers` and `calls`: the exact symbol name to analyze",
            "For `deps` and `importers`, how many dependency levels to follow, 1-10; defaults to 1",
            "For `callers` and `calls`, optional symbol-kind filter such as `function`, `struct`, or `method`; omit to match any kind",
            "For `recent`, maximum number of recently-modified files to return; defaults to 20",
        )
    } else {
        (
            "Relationship query to run: `deps`, `importers`, `cycles`, `callers`, `calls`, or `recent`",
            "File path for `deps` or `importers`",
            "Symbol name for `callers` or `calls`",
            "Max dependency hops, 1-10",
            "Symbol-kind filter for `callers` or `calls`",
            "Max recently modified files",
        )
    };
    serde_json::json!({
        "type": "object",
        "properties": {
            "kind": {
                "type": "string",
                "enum": GRAPH_KIND_VALUES,
                "description": kind_desc
            },
            "path": { "type": "string", "x-cockpit-kind": "path", "description": path_desc },
            "name": { "type": "string", "description": name_desc },
            "hops": { "type": "integer", "description": hops_desc },
            "symbol_kind": { "type": "string", "description": symbol_kind_desc },
            "limit": { "type": "integer", "description": limit_desc }
        },
        "required": ["kind"]
    })
}

pub struct GraphTool;

#[async_trait]
impl Tool for GraphTool {
    fn name(&self) -> &str {
        "graph"
    }

    fn description(&self) -> &str {
        "Inspect imports, importers, cycles, callers, calls, or recent files; use `change_impact` diffs, `search` text, `code` structure, `context_pack` bundles"
    }

    fn verbose_description(&self) -> Option<String> {
        Some(
            "Inspect code relationships through one closed `kind`: `deps` lists files a path \
             imports, `importers` lists files that import it, `cycles` finds import cycles, \
             `callers` and `calls` answer one symbol's call graph, and `recent` lists files by \
             modification time. Use this instead of grepping imports or symbol names through \
             `bash` when the indexed graph can answer directly; use `change_impact` for current \
             diff blast-radius hints."
                .to_string(),
        )
    }

    fn effect(&self) -> ToolEffect {
        ToolEffect::ReadOnly
    }

    fn parameters(&self) -> Value {
        graph_schema(false)
    }

    fn verbose_parameters(&self) -> Option<Value> {
        Some(graph_schema(true))
    }

    fn honors_dispatch_cancel(&self) -> bool {
        true
    }

    async fn call(&self, args: Value, ctx: &ToolCtx) -> Result<ToolOutput> {
        let Some(kind) = non_empty_str(&args, "kind") else {
            return Err(graph_kind_error());
        };
        match kind {
            "deps" => {
                let path =
                    non_empty_str(&args, "path").ok_or_else(|| required_for_kind("path", kind))?;
                let mut delegated = serde_json::Map::new();
                delegated.insert("path".to_string(), Value::String(path.to_string()));
                delegated.insert(
                    "direction".to_string(),
                    Value::String("forward".to_string()),
                );
                if let Some(hops) = args.get("hops").and_then(Value::as_u64) {
                    delegated.insert(
                        "hops".to_string(),
                        Value::Number(serde_json::Number::from(hops)),
                    );
                }
                super::deps::DepsTool
                    .call(Value::Object(delegated), ctx)
                    .await
            }
            "importers" => {
                let path =
                    non_empty_str(&args, "path").ok_or_else(|| required_for_kind("path", kind))?;
                let mut delegated = serde_json::Map::new();
                delegated.insert("path".to_string(), Value::String(path.to_string()));
                delegated.insert(
                    "direction".to_string(),
                    Value::String("reverse".to_string()),
                );
                if let Some(hops) = args.get("hops").and_then(Value::as_u64) {
                    delegated.insert(
                        "hops".to_string(),
                        Value::Number(serde_json::Number::from(hops)),
                    );
                }
                super::deps::DepsTool
                    .call(Value::Object(delegated), ctx)
                    .await
            }
            "cycles" => {
                super::circular::CircularTool
                    .call(serde_json::json!({}), ctx)
                    .await
            }
            "callers" => {
                let name =
                    non_empty_str(&args, "name").ok_or_else(|| required_for_kind("name", kind))?;
                super::impact::call_impact_section(
                    name,
                    non_empty_str(&args, "path"),
                    non_empty_str(&args, "symbol_kind"),
                    super::impact::ImpactSection::Callers,
                    ctx,
                )
                .await
            }
            "calls" => {
                let name =
                    non_empty_str(&args, "name").ok_or_else(|| required_for_kind("name", kind))?;
                super::impact::call_impact_section(
                    name,
                    non_empty_str(&args, "path"),
                    non_empty_str(&args, "symbol_kind"),
                    super::impact::ImpactSection::Calls,
                    ctx,
                )
                .await
            }
            "recent" => {
                let mut delegated = serde_json::Map::new();
                if let Some(limit) = args.get("limit").and_then(Value::as_u64) {
                    delegated.insert(
                        "limit".to_string(),
                        Value::Number(serde_json::Number::from(limit)),
                    );
                }
                super::hot::HotTool
                    .call(Value::Object(delegated), ctx)
                    .await
            }
            _ => Err(graph_kind_error()),
        }
    }
}
