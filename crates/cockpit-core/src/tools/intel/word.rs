use super::common::*;

// ---- word ------------------------------------------------------------------

pub struct WordTool;

#[async_trait]
impl Tool for WordTool {
    fn name(&self) -> &str {
        "word"
    }
    fn description(&self) -> &str {
        "List whole-token identifier uses from the index; use `symbol_find` for definitions and `search`/`grep` for regex text"
    }
    fn defensive_description(&self) -> Option<String> {
        Some(
            "Find every place an identifier TOKEN appears across the codebase — all uses, not \
             just the definition — returning the file + line of each. Use this to trace where a \
             function/variable/type is referenced before you change it, instead of `bash`/`grep`. \
             Whole-token matches from the index, not substrings or regex; for general-text/regex \
             use `search`, for the definition only use `symbol_find`. Set `case_insensitive` to \
             ignore case."
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
                "token":            { "type": "string", "description": "Identifier token to look up" },
                "case_insensitive": { "type": "boolean", "description": "Case-insensitive match toggle" }
            },
            "required": ["token"]
        })
    }
    fn defensive_parameters(&self) -> Option<Value> {
        Some(serde_json::json!({
            "type": "object",
            "properties": {
                "token":            { "type": "string", "description": "The exact identifier token to find uses of; matched as a whole word, not a substring" },
                "case_insensitive": { "type": "boolean", "description": "When true, match the token regardless of letter case; defaults to case-sensitive" }
            },
            "required": ["token"]
        }))
    }

    async fn call(&self, args: Value, ctx: &ToolCtx) -> Result<ToolOutput> {
        let token = args
            .get("token")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid_input("`token` is required"))?;
        let ci = args
            .get("case_insensitive")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let index = index_of(ctx);
        index.ensure_fresh().await?;

        let grouped = index.word_hits(token, ci)?;
        if grouped.is_empty() {
            return Ok(ToolOutput::text(format!(
                "`{token}` not found in the index."
            )));
        }
        let mut writer = BudgetedWriter::new(STRUCT_TOKEN_CAP);
        for (path, lines) in &grouped {
            let joined = lines
                .iter()
                .map(|l| l.to_string())
                .collect::<Vec<_>>()
                .join(",");
            if !write_retained_line(&mut writer, &format!("{path}: {joined}")) {
                break;
            }
        }
        Ok(finish(writer, "\n... [truncated]\n"))
    }
}
