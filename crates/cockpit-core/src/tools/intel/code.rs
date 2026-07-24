use super::common::*;

const CODE_KIND_VALUES: &[&str] = &["tree", "outline", "symbol_find", "word"];

fn code_kind_error() -> anyhow::Error {
    invalid_input("`kind` must be one of `tree`, `outline`, `symbol_find`, `word`")
}

fn required_for_kind(field: &str, kind: &str) -> anyhow::Error {
    invalid_input(format!("`{field}` is required for code kind `{kind}`"))
}

fn non_empty_str<'a>(args: &'a Value, field: &str) -> Option<&'a str> {
    args.get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
}

fn code_schema(defensive: bool) -> Value {
    let (path_desc, name_desc, token_desc, exact_desc, symbol_kind_desc, ci_desc) = if defensive {
        (
            "For `tree`, optional subtree to list; for `outline`, required path to the single source file to outline",
            "Required when `kind` is `symbol_find`: the symbol name or prefix whose definition you need",
            "Required when `kind` is `word`: the exact identifier token to find uses of, matched as a whole word",
            "For `symbol_find`, match `name` exactly instead of as a prefix",
            "For `symbol_find`, optional symbol-kind filter such as `function`, `struct`, `class`, or `method`",
            "For `word`, match the token regardless of letter case",
        )
    } else {
        (
            "Subtree path for `tree`, or file path for `outline`",
            "Symbol name or prefix for `symbol_find`",
            "Identifier token for `word`",
            "Exact-match toggle for `symbol_find`",
            "Symbol-kind filter for `symbol_find`",
            "Case-insensitive match toggle for `word`",
        )
    };
    serde_json::json!({
        "type": "object",
        "properties": {
            "kind": {
                "type": "string",
                "enum": CODE_KIND_VALUES,
                "description": "Structure lookup to run: `tree`, `outline`, `symbol_find`, or `word`"
            },
            "path": { "type": "string", "x-cockpit-kind": "path", "description": path_desc },
            "name": { "type": "string", "description": name_desc },
            "token": { "type": "string", "description": token_desc },
            "exact": { "type": "boolean", "description": exact_desc },
            "symbol_kind": { "type": "string", "description": symbol_kind_desc },
            "case_insensitive": { "type": "boolean", "description": ci_desc }
        },
        "required": ["kind"]
    })
}

pub struct CodeTool;

#[async_trait]
impl Tool for CodeTool {
    fn name(&self) -> &str {
        "code"
    }

    fn description(&self) -> &str {
        "Inspect code structure: tree, outline, definitions, or token uses; use `search`/`grep` for text, `context_pack` for bundles, `read` for contents"
    }

    fn defensive_description(&self) -> Option<String> {
        Some(
            "Inspect code structure through one closed `kind`: `tree` maps files, `outline` shows \
             one file's symbols/imports, `symbol_find` finds definitions, and `word` finds whole-token \
             uses. Use these instead of `ls`/`find`, `cat | head`, or `bash`/`grep` when you need \
             indexed structure; use `search` for general text or regex and `context_pack` for a \
             broader task-shaped bundle."
                .to_string(),
        )
    }

    fn parameters(&self) -> Value {
        code_schema(false)
    }

    fn defensive_parameters(&self) -> Option<Value> {
        Some(code_schema(true))
    }

    async fn call(&self, args: Value, ctx: &ToolCtx) -> Result<ToolOutput> {
        let Some(kind) = non_empty_str(&args, "kind") else {
            return Err(code_kind_error());
        };
        match kind {
            "tree" => {
                let mut delegated = serde_json::Map::new();
                if let Some(path) = args.get("path") {
                    delegated.insert("path".to_string(), path.clone());
                }
                let mut out = super::tree::TreeTool
                    .call(Value::Object(delegated), ctx)
                    .await?;
                if let Some(Value::Object(mut canonical)) = out.canonical_args.take() {
                    canonical.insert("kind".to_string(), Value::String("tree".to_string()));
                    out.canonical_args = Some(Value::Object(canonical));
                }
                Ok(out)
            }
            "outline" => {
                let path =
                    non_empty_str(&args, "path").ok_or_else(|| required_for_kind("path", kind))?;
                super::outline::OutlineTool
                    .call(serde_json::json!({ "path": path }), ctx)
                    .await
            }
            "symbol_find" => {
                let name =
                    non_empty_str(&args, "name").ok_or_else(|| required_for_kind("name", kind))?;
                let mut delegated = serde_json::Map::new();
                delegated.insert("name".to_string(), Value::String(name.to_string()));
                if let Some(exact) = args.get("exact").and_then(Value::as_bool) {
                    delegated.insert("exact".to_string(), Value::Bool(exact));
                }
                if let Some(symbol_kind) = non_empty_str(&args, "symbol_kind") {
                    delegated.insert("kind".to_string(), Value::String(symbol_kind.to_string()));
                }
                super::symbol_find::SymbolFindTool
                    .call(Value::Object(delegated), ctx)
                    .await
            }
            "word" => {
                let token = non_empty_str(&args, "token")
                    .ok_or_else(|| required_for_kind("token", kind))?;
                let mut delegated = serde_json::Map::new();
                delegated.insert("token".to_string(), Value::String(token.to_string()));
                if let Some(case_insensitive) =
                    args.get("case_insensitive").and_then(Value::as_bool)
                {
                    delegated.insert(
                        "case_insensitive".to_string(),
                        Value::Bool(case_insensitive),
                    );
                }
                super::word::WordTool
                    .call(Value::Object(delegated), ctx)
                    .await
            }
            _ => Err(code_kind_error()),
        }
    }
}
