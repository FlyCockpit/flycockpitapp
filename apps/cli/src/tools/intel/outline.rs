use super::common::*;

// ---- outline ---------------------------------------------------------------

pub struct OutlineTool;

#[async_trait]
impl Tool for OutlineTool {
    fn name(&self) -> &str {
        "outline"
    }
    fn description(&self) -> &str {
        "Show a file's symbols and imports in line order; regex fallback for unknown languages"
    }
    fn defensive_description(&self) -> Option<String> {
        Some(
            "Get a structural outline of one file — its functions, types, methods, and imports \
             in source order with line numbers — without reading the whole file. Use this to see \
             a file's shape and jump straight to the right line with a ranged `read`, instead of \
             `cat | head` in `bash` or paging the whole file. Falls back to a regex scan for \
             languages cockpit can't fully parse."
                .to_string(),
        )
    }
    fn parameters(&self) -> Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "path": { "type": "string", "x-cockpit-kind": "path", "description": "File `path` to outline" }
            },
            "required": ["path"]
        })
    }
    fn defensive_parameters(&self) -> Option<Value> {
        Some(serde_json::json!({
            "type": "object",
            "properties": {
                "path": { "type": "string", "x-cockpit-kind": "path", "description": "Path to the single source file to outline, relative to the project root or absolute" }
            },
            "required": ["path"]
        }))
    }

    async fn call(&self, args: Value, ctx: &ToolCtx) -> Result<ToolOutput> {
        let path_arg = args
            .get("path")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid_input("`path` is required"))?;
        // Native-tool boundary check (sandboxing part 2): the regex
        // fallback below reads the file off disk, so an out-of-cwd path
        // must escalate first.
        crate::tools::sandbox::check_native_access(
            ctx,
            &crate::tools::common::resolve(path_arg, &ctx.cwd),
        )
        .await?;
        let rel = rel_path(path_arg, ctx);
        let index = index_of(ctx);
        index.ensure_fresh().await?;

        let (symbols, imports, language) = index.outline_rows(&rel)?;
        let mut writer = BudgetedWriter::new(STRUCT_TOKEN_CAP);

        // Unknown / not-indexed language → regex fallback (never errors).
        if language.is_empty() || language == "unknown" {
            let abs = crate::tools::common::resolve(path_arg, &ctx.cwd);
            let body = match std::fs::read_to_string(&abs) {
                Ok(b) => b,
                Err(e) => {
                    return Err(invalid_input(format!("read `{rel}`: {e}")));
                }
            };
            writer.writeln(&format!(
                "{rel} (unknown language — regex outline, may be incomplete)"
            ));
            let hits = regex_outline(&body);
            if hits.is_empty() {
                writer.writeln("  (no definitions matched)");
            }
            for (name, line) in hits {
                if !writer.writeln(&format!("  {line}: {name}")) {
                    break;
                }
            }
            return Ok(finish(writer, "\n... [truncated]\n"));
        }

        writer.writeln(&format!("{rel} ({language})"));
        if !imports.is_empty() {
            writer.writeln("imports:");
            for (target, line) in &imports {
                if !writer.writeln(&format!("  {line}: {target}")) {
                    return Ok(finish(writer, "\n... [truncated]\n"));
                }
            }
        }
        if !symbols.is_empty() {
            writer.writeln("symbols:");
            for s in &symbols {
                let vis = s
                    .visibility
                    .as_deref()
                    .map(|v| format!("{v} "))
                    .unwrap_or_default();
                let parent = s
                    .parent
                    .as_deref()
                    .map(|p| format!("{p}."))
                    .unwrap_or_default();
                let span = if s.end_line > s.line {
                    format!("{}-{}", s.line, s.end_line)
                } else {
                    s.line.to_string()
                };
                // Prefer the captured signature (first source line) for
                // callables; fall back to the synthesized form otherwise.
                let sig = match (s.kind.as_str(), &s.signature) {
                    ("function" | "method", Some(sig)) if !sig.is_empty() => {
                        format!("{vis}{}", sig.trim())
                    }
                    _ => format!("{vis}{} {parent}{}", s.kind, s.name),
                };
                if !writer.writeln(&format!("  {span}: {sig}")) {
                    break;
                }
            }
        }
        if symbols.is_empty() && imports.is_empty() {
            writer.writeln("  (no symbols or imports)");
        }
        Ok(finish(writer, "\n... [truncated]\n"))
    }
}
